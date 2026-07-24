# PRD — Bounded Administrative Data Paths

**Source**: IDEATION_PERFORMANCE.md
**Generated**: 2026-07-24

## Implementation Order
1. PERF-004 — Replace webhook configuration N+1 reads with bounded set queries.
2. PERF-006 — Generate audit CSV through cursor iteration and a spooled file.

---

## PERF-004: Consolidate Webhook Configuration Queries

### Scope
**In scope**:
- Fetch non-deleted webhook configurations with three bounded set queries.
- Preserve configuration, subscription, and recent-delivery ordering.
- Preserve empty child collections and delivery error sanitization.
- Derive the page capacity flag from the returned configuration collection.
- Add focused query-count and output-contract tests.

**Out of scope**:
- Add or change database indexes.
- Change webhook delivery retention, retry, worker, or creation behavior.
- Change the `_MAX_CONFIGS` create-time enforcement.
- Replace the three-query implementation with a child-multiplying join.

### Technical Approach
- Keep `list_webhook_configs(conn)` as the public listing function.
- Execute the configuration query first, ordered by `id`.
- Return immediately for an empty configuration list.
- Build a bounded `IN (...)` list from configuration IDs.
- Fetch subscriptions ordered by `config_id, event_type`; group into `dict[int, list[str]]`.
- Fetch the latest ten deliveries per configuration with `ROW_NUMBER() OVER (PARTITION BY config_id ORDER BY id DESC)`.
- Order ranked delivery results by `config_id, id DESC`; group after passing every row through `_public_delivery()`.
- Assemble the existing list-of-dictionaries shape with empty lists for configurations without children.
- In the security-integrations route, set `at_capacity = len(configs) >= 20`; remove the redundant display-only `count_active_configs()` call. Keep `count_active_configs()` for create-time enforcement.
- Assert the runtime SQLite version supports window functions in the focused test environment; do not add a schema migration.

### Touchpoints
- `service_manager/webhooks.py` — replace the per-configuration subscription and delivery reads.
- `service_manager/routes.py` — derive `at_capacity` from the listing result.
- `templates/security_integrations.html` — retain the existing input contract; no markup change required unless the route variable changes.
- `tests/test_webhooks_routes.py` — add ordering, limit, empty-child, sanitization, and route-cap tests.
- `tests/test_webhooks_core.py` — add direct listing/query-count tests if route instrumentation is unsuitable.

### Contracts
```python
def list_webhook_configs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return non-deleted configs ordered by id.

    Each item contains:
      id: int
      destination_host: str
      description: str
      enabled: bool
      created_at: str
      updated_at: str
      subscriptions: list[str]              # ordered by event_type
      recent_deliveries: list[dict[str, Any]]  # at most 10, id descending
    """
```

```sql
WITH ranked AS (
    SELECT id, config_id, event_type, status, attempt_count,
           last_status_code, last_error, created_at, delivered_at,
           ROW_NUMBER() OVER (
               PARTITION BY config_id
               ORDER BY id DESC
           ) AS delivery_rank
    FROM webhook_deliveries
    WHERE config_id IN (...)
)
SELECT id, config_id, event_type, status, attempt_count,
       last_status_code, last_error, created_at, delivered_at
FROM ranked
WHERE delivery_rank <= 10
ORDER BY config_id, id DESC;
```

### Acceptance Criteria
- [ ] Listing 20 configurations executes exactly three SQL statements inside `list_webhook_configs()`.
- [ ] The security-integrations GET route performs no separate display-only active-config count query.
- [ ] Configurations remain ordered by ascending ID.
- [ ] Subscriptions remain ordered lexically for each configuration.
- [ ] Each configuration receives at most ten deliveries ordered by descending delivery ID.
- [ ] Configurations without subscriptions or deliveries receive empty lists.
- [ ] Non-generic `last_error` values are exposed only as `connection`.
- [ ] Soft-deleted configurations do not appear.
- [ ] Create-time enforcement still rejects a twenty-first active configuration.
- [ ] No schema object or migration is added.

### Dependencies
- None

---

## PERF-006: Spool Audit CSV Exports

### Scope
**In scope**:
- Iterate audit query results without `fetchall()`.
- Write the CSV into a bounded `SpooledTemporaryFile`.
- Serve the spooled file with deterministic cleanup.
- Preserve every existing export security and formatting contract.
- Add output-parity and lifecycle tests.

**Out of scope**:
- Remove or raise the 10,000-row export limit.
- Implement a live streaming generator.
- Change audit filters, authorization, reauthentication, or hash representation.
- Cache audit exports.

### Technical Approach
- Extract a small audit-row projection helper only if it removes duplication in tests and keeps sanitization explicit.
- Open `tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)` to match account exports.
- Write the UTF-8 BOM directly to the binary spool.
- Reuse an `io.StringIO(newline="")` plus `csv.writer`; flush each completed row to the spool and reset the text buffer.
- Iterate `conn.execute(query, params)` directly.
- Convert `previous_hash` and `event_hash` BLOBs to lowercase hex before `_sanitize_cell`.
- Seek the spool to zero and call `send_file(..., mimetype="text/csv", as_attachment=True, download_name=filename)`.
- Register `spool.close` with `response.call_on_close` and close immediately on exceptions.
- Preserve authenticated `no-store, private` headers through the existing response hooks.

### Touchpoints
- `service_manager/routes.py` — replace `audit_csv()` materialization with spooling.
- `tests/test_feature_pack.py` — preserve filters, BOM, headers, hash encoding, authorization, and reauthentication assertions.
- `tests/test_task5_security.py` — retain CSV formula-injection protections if covered there.

### Contracts
```python
@routes.get("/admin/audit.csv")
@require_role("admin")
def audit_csv() -> ResponseReturnValue:
    """Return at most 10,000 filtered audit rows as a private UTF-8-BOM CSV."""
```

```text
id,occurred_at,usuario,action,target_type,target_id,metadata_json,source_ip,previous_hash,event_hash
```

```python
# Response requirements
Content-Type: text/csv
Content-Disposition: attachment; filename=auditoria_<UTC stamp>.csv
Cache-Control: no-store, private
```

### Acceptance Criteria
- [ ] `audit_csv()` does not call `fetchall()` for the export query.
- [ ] The response starts with a UTF-8 BOM and the existing header sequence.
- [ ] Export filters match the HTML audit filter semantics.
- [ ] Exported hash columns are lowercase 64-character hexadecimal strings.
- [ ] Spreadsheet-formula-leading values remain sanitized.
- [ ] The route exports no more than 10,000 rows.
- [ ] The route still requires an administrator and recent reauthentication.
- [ ] The response remains `no-store, private`.
- [ ] The spool closes after the response closes and closes immediately on an exception.
- [ ] A test using a low spool threshold verifies rollover without changing CSV output.

### Dependencies
- None
