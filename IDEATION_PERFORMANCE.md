# Performance Optimization Decisions

## Decision Summary

Service Manager is a server-rendered Flask/SQLite application. The current static payload is already small—approximately 18.3 KB gzip for the primary JavaScript and CSS—and is served with deferred loading, content-versioned URLs, gzip, and one-year immutable caching. The current implementation priority is therefore bounded server rendering, bounded memory use, and set-based database access rather than asset optimization.

Measured baselines retained for implementation verification:

- Account page, 1,000 accounts without custom fields: 8.4 MB response, 478 ms, 40.3 MiB peak Python memory.
- Account page, 1,000 accounts with five custom fields each: 22.2 MB response, 973 ms, 105.7 MiB peak Python memory.
- Coverage model, 10,000 accounts × 20 services: 200,000 cell dictionaries, 401 ms, 58.9 MiB before template rendering.
- Bulk authorization, 200 accounts × 8 services: 2,000 SQL statements / 2.75 ms in-memory versus a set-based prototype at 0.31 ms.
- Webhook configuration listing, 20 configurations: 41 SQL statements in the current `2N+1` implementation.

Database schema changes remain subject to the controlled offline migration process. The runtime rejects databases whose schema differs from `service_manager.db.SCHEMA`.

## Phase 1 — Bounded Administrative Data Paths

### PERF-004: Consolidate Webhook Configuration Queries

**Decision:** Keep  
**Priority:** Medium  
**Effort:** Low

Replace the `2N+1` query pattern in `list_webhook_configs()` with three bounded set queries:

1. Fetch non-deleted configurations ordered by ID.
2. Fetch subscriptions for those configuration IDs ordered by `(config_id, event_type)` and group them in Python.
3. Fetch the latest ten deliveries per configuration with a ranked query ordered by `(config_id, id DESC)` and apply `_public_delivery()` to every result.

Derive the security-integrations page's capacity flag from the returned configuration count instead of issuing a separate count query. Keep create-time `_MAX_CONFIGS` enforcement authoritative.

Implementation notes:

- Preserve configurations with no subscriptions or deliveries.
- Preserve lexical subscription ordering, descending delivery-ID ordering, the ten-delivery limit, and generic error sanitization.
- Add focused tests for ordering, empty child collections, exactly ten deliveries, sanitization, and bounded statement count.
- Do not add a new database index in this phase; measure the ranked query first because an index change requires an offline migration.

### PERF-006: Spool Audit CSV Exports

**Decision:** Keep  
**Priority:** Medium  
**Effort:** Low

Replace `fetchall()` plus whole-document `StringIO.getvalue().encode()` in `/admin/audit.csv` with cursor iteration and `SpooledTemporaryFile`, following the existing account CSV export lifecycle.

Implementation notes:

- Preserve the 10,000-row limit, UTF-8 BOM, formula-injection sanitization, lowercase 64-character hash columns, filename format, filters, recent-reauthentication requirement, and private/no-store response policy.
- Use `send_file`, `response.call_on_close(spool.close)`, and explicit exception cleanup.
- Add tests for output parity and spool cleanup/rollover behavior without exposing audit data in shared caches.

## Phase 2 — Set-Based Bulk Authorization

### PERF-003: Batch Bulk-Operation Authorization Without Changing Semantics

**Decision:** Adjust  
**Priority:** High  
**Effort:** Medium

Add a bulk authorization helper that performs bounded set reads and then evaluates selected accounts in the caller-provided order. Do not require a single SQL statement; preserving authorization behavior is more important than minimizing the final one or two reads.

Adjusted scope:

- Accept the existing deduplicated, ordered list of at most 200 account IDs.
- Batch-load initiating-service links.
- For `all_linked_services=True`, batch-load every selected account's linked services and the caller's membership roles.
- Evaluate the prefetched result in selection order so the first failing selected account determines the existing 404/403 outcome and denial target.
- Preserve the rule that even global administrators receive 404 when an account is not linked to the initiating service.
- Preserve role ranks, the separate atomic `authorization.failed` audit plus `authorization_failure` webhook transaction, and successful mutation/audit transaction boundaries.
- Reuse the helper in bulk status, registration, field update, field creation, and deletion routes. Keep single-resource authorization unchanged.

Implementation notes:

- Keep authorization before the mutation transaction; changing concurrency/transaction semantics is out of scope.
- Add mixed-batch tests covering a missing link before/after an unauthorized account, global-admin link validation, multi-service delete denial, denial target metadata, and subscribed webhook delivery.

## Phase 3 — Bounded Account and Coverage Surfaces

### PERF-008: Delegate Dynamic Account-Table Events

**Decision:** Adjust  
**Priority:** Medium  
**Effort:** Medium

Refactor only the repeated account-table handlers that must work for lazy-inserted detail markup. This is a prerequisite for PERF-001, not a global rewrite of every listener in `app.js`.

Adjusted scope:

- Delegate account-table copy, reveal/copy-secret, edit, row-selection, expansion, and autosubmit actions from stable account-table containers.
- Keep global capture-phase CSRF synchronization and submit locking unchanged.
- Keep secret state bounded to actively revealed cells and retain abort/timer cleanup on visibility and page lifecycle events.
- Keep webhook, admin-user, authentication, and other unrelated handlers unchanged unless they receive dynamic markup in a later feature.
- Preserve Portuguese feedback strings and the existing prohibition on `localStorage` and `sessionStorage`.

### PERF-001: Paginate Account Summaries and Lazy-Load Custom Fields

**Decision:** Adjust  
**Priority:** High  
**Effort:** High

Bound the account list to 100 summary rows per response and load one account's custom-field editors only when its detail row is opened.

Adjusted scope:

- Move status, registration, rotation, email query, and email/status sorting into SQL.
- Change the text-search contract from “email or custom-field plaintext” to email-only search. Encrypted custom-field values must not be decrypted across the full service to support substring search.
- Use stable cursor pagination rather than deep `OFFSET` pagination. Preserve active filters and sort order in navigation URLs.
- Keep service-wide summary/status/rotation counts global. Label the visible result count as page-local.
- Fetch only account summary columns in `index()`; do not query or decrypt custom-field values there.
- Add `GET /accounts/<account_id>/details?service=<service_id>` returning an authorized, private/no-store HTML fragment. Authorize current read disclosure at viewer level; preserve stronger mutation permissions inside the fragment.
- Cache a loaded fragment only in the live DOM. Do not use browser storage.
- Define selection as current-page-only and state this in the UI. Navigation clears selection.
- Preserve `#row-<id>` focus after field mutations by adding a bounded focus mechanism that returns a page containing the target account, then expands the lazy detail row.

Implementation notes:

- Keep account filters in the current table headers.
- Update pinned tests for the email-only placeholder and page-local selection wording.
- Verify response bytes, route duration, peak memory, DOM nodes, filtering, sorting, focus redirects, lazy authorization, and no-store headers at 100, 1,000, and 10,000 accounts.

### PERF-002: Paginate Coverage with Server-Side Filters and Sparse In-Memory Cells

**Decision:** Adjust  
**Priority:** High  
**Effort:** Medium

Bound coverage to 100 accounts per response while preserving the existing persisted `account_service` semantics.

Adjusted scope:

- Apply `none-registered`, `multi-active`, and `missing-registration` filters to the complete accessible result set in SQL before pagination.
- Preserve the current meaning of missing and `nunca/0` links for coverage filtering.
- Keep only actual query rows in the Python link map; let the template render a default/missing state without allocating a dictionary for every absent pair.
- Compute registration and active counts in SQL.
- Use stable cursor pagination and preserve the selected coverage filter and selected service IDs in navigation URLs.
- Replace client-only row filtering with a GET form. Show page-local visible count and total filtered count.
- Keep all accessible service columns in this phase. Service-column virtualization and coverage export are out of scope.

Implementation notes:

- Do not alter account creation, service creation, import, export, deletion authorization, or the `account_service` schema.
- Benchmark multiple service counts because horizontal rendering remains proportional to accessible services.

## Deferred

### PERF-005: Audit Indexes and Keyset Pagination

**Trigger to reconsider:** Reopen when production evidence shows either (a) `audit_events` has reached 100,000 rows, (b) filtered/deep-page audit queries exceed 50 ms at p95, or (c) audit listing contributes material request latency after separating periodic chain-verification cost.

Before implementation, collect filter-combination frequency, selectivity, query plans, audit growth, database/WAL size, and append throughput. Decide indexes from observed query shapes. Any index addition requires a controlled offline migration and updates to canonical-schema and migration tests. Retain the existing page-number UX until keyset navigation behavior under concurrent appends is explicitly specified.

### PERF-007: Sparse Persisted Account-Service Memberships

**Trigger to reconsider:** Reopen only when the dense `account_service` table causes measured storage, backup, migration, or creation latency problems and product owners have defined explicit link/unlink semantics.

The current relationship simultaneously represents membership, status, registration, rotation overrides, export inclusion, and destructive-authorization scope. Existing `nunca/0` rows cannot be reliably classified as automatic placeholders versus deliberate memberships. This is a product and migration redesign, not a current query optimization.

### PERF-010: Route-Specific JavaScript Files

**Trigger to reconsider:** Reopen when the shared JavaScript exceeds 50 KB gzip, p75 parse/execute time exceeds 100 ms on supported low-end devices, or a route-specific feature can be isolated without creating a new shared-global contract.

If triggered, retain plain deferred same-origin files, content hashing, and strict CSP. Do not introduce a Node bundler solely for splitting.

## Dropped on Critical Review

| ID | Name | Why dropped |
|---|---|---|
| PERF-009 | Cache sort keys and consolidate full-page DOM scans | Pagination caps the page at 100 rows, making the bookkeeping and mutation synchronization more complex than the remaining work warrants. |
| PERF-011 | Precompressed Brotli assets | The current main assets total only 18.3 KB gzip and are immutable-cached; saving an estimated 2–4 KB on cold load does not justify Nginx module and image complexity. |

## Implementation Sequence

1. PERF-004 — consolidate webhook listing queries.
2. PERF-006 — spool audit CSV export.
3. PERF-003 — batch bulk authorization while preserving failure semantics.
4. PERF-008 — delegate dynamic account-table handlers.
5. PERF-001 — paginate account summaries and lazy-load custom fields.
6. PERF-002 — paginate and server-filter coverage.

## Verification Baseline

- Run focused route and unit tests for each phase, then the existing full suite.
- Preserve strict CSP, CSRF/origin protections, private/no-store caching, reauthentication, audit-chain integrity, and Portuguese UI contracts.
- For runtime changes, compare response size, route time, SQL statement count, peak process memory, DOM node count, and browser interaction latency against the retained baselines.
- For any future schema-bearing change, migrate offline, verify the migrated database, and deploy only after canonical-schema validation passes.
