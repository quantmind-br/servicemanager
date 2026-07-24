# PRD — Bulk Authorization Queries

**Source**: IDEATION_PERFORMANCE.md
**Generated**: 2026-07-24

## Implementation Order
1. PERF-003 — Batch bulk-operation authorization reads while preserving ordered failure semantics.

---

## PERF-003: Batch Bulk-Operation Authorization Without Changing Semantics

### Scope
**In scope**:
- Add one bulk authorization helper for ordered selections of at most 200 accounts.
- Batch-load initiating-service links.
- Batch-load linked services and caller memberships for all-linked-service checks.
- Preserve global-administrator, 404, 403, denial-audit, and webhook behavior.
- Replace authorization loops in all existing bulk account routes.
- Add mixed-failure and denial-side-effect coverage.

**Out of scope**:
- Change single-account authorization helpers or routes.
- Move authorization reads into the successful mutation transaction.
- Change role names, role ranks, bulk limits, selection deduplication, or mutation SQL.
- Batch AES-GCM encryption for bulk custom-field writes.
- Change successful audit or destructive-webhook payloads.

### Technical Approach
- Add `require_accounts_role()` beside `require_account_role()` in `service_manager/authorization.py`.
- Require a non-empty ordered list already validated and deduplicated by `_bulk_account_ids()`.
- Fetch all initiating-service links with one bounded `IN (...)` query and create `linked_to_initiating: set[int]`.
- If `all_linked_services` is false and the caller is not a global administrator, resolve the initiating-service role once.
- If `all_linked_services` is true and the caller is not a global administrator:
  - Fetch every selected account's `account_service` rows ordered by account/service.
  - Fetch the caller's memberships for the distinct linked service IDs in one query.
  - Build a service-to-role map and compare ranks in Python.
- Evaluate `account_ids` in caller-provided order:
  - If an account lacks the initiating link, abort 404 without denial audit/webhook.
  - If an account fails the required role, write one existing `authorization.failed` event and subscribed `authorization_failure` deliveries through `_record_authorization_denial()`, then abort 403.
- For ordinary bulk operations, preserve the existing service-target denial behavior.
- For all-linked-service checks, use the first failing account as `target_id` and the initiating service in denial metadata, matching `require_account_role()`.
- Return the same conceptual granted-role string as the single-resource helper.
- Replace per-account loops in bulk status, registration, field value, field creation, and delete routes.

### Touchpoints
- `service_manager/authorization.py` — add the bulk helper and reuse role-rank/denial primitives.
- `service_manager/routes.py` — replace five bulk authorization loops.
- `service_manager/db.py` — use existing primary keys and indexes; no schema change.
- `tests/test_authorization.py` — add direct helper semantics and atomic denial-side-effect tests.
- `tests/test_feature_pack.py` — extend bulk-route authorization coverage.

### Contracts
```python
def require_accounts_role(
    conn: sqlite3.Connection,
    account_ids: list[int],
    service_id: int,
    minimum_role: str,
    *,
    all_linked_services: bool = False,
) -> str:
    """Authorize an ordered, deduplicated bulk account selection.

    Raises:
      NotFound: first selected account not linked to initiating service.
      Forbidden: first selected account that fails the required role.

    Side effects on Forbidden:
      Append one authorization.failed audit event and enqueue subscribed
      authorization_failure deliveries atomically before aborting.
    """
```

```python
# Route usage
account_ids = _bulk_account_ids()
require_accounts_role(conn, account_ids, service_id, "editor")

require_accounts_role(
    conn,
    account_ids,
    service_id,
    "service_admin",
    all_linked_services=True,
)
```

### Acceptance Criteria
- [ ] A successful 200-account ordinary bulk authorization uses a constant number of SQL reads independent of account count.
- [ ] A successful 200-account all-linked-service authorization uses a constant number of SQL reads independent of account and link count.
- [ ] Ordered mixed selections preserve first-selected failure semantics.
- [ ] A missing initiating link returns 404 and writes no authorization-denial audit or webhook delivery.
- [ ] A global administrator still receives 404 for a missing initiating link.
- [ ] A non-global caller below the required initiating-service role receives 403.
- [ ] All-linked-service authorization fails when any selected account has any linked service below the required rank.
- [ ] The 403 denial target is the first failing selected account for all-linked-service checks.
- [ ] A 403 writes one `authorization.failed` audit event and subscribed `authorization_failure` deliveries atomically.
- [ ] Bulk status, registration, field update, field creation, and deletion use the new helper.
- [ ] The existing 200-account cap and order-preserving deduplication remain unchanged.
- [ ] Successful mutations retain their current transaction, audit, redirect, and destructive-webhook behavior.
- [ ] No database schema change is introduced.

### Dependencies
- None
