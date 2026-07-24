# PRD — Bounded Account Surfaces

**Source**: IDEATION_PERFORMANCE.md
**Generated**: 2026-07-24

## Implementation Order
1. PERF-008 — Delegate account-table actions required by dynamic detail fragments.
2. PERF-001 — Paginate account summaries and lazy-load custom-field details.
3. PERF-002 — Paginate coverage and apply its filters server-side.

---

## PERF-008: Delegate Dynamic Account-Table Events

### Scope
**In scope**:
- Delegate repeated account-table actions from stable containers.
- Support account-detail controls inserted after initial page load.
- Preserve secret lifecycle, CSRF, submit locking, and feedback behavior.
- Keep selection state memory-only.

**Out of scope**:
- Rewrite every handler in `static/js/app.js`.
- Change webhook, admin-user, authentication, service-preference, or coverage handlers.
- Introduce a frontend framework, module bundler, local storage, or session storage.
- Change Portuguese UI strings except where PERF-001 adds explicit page-selection wording.

### Technical Approach
- Use the account table/tbody as the stable event root for repeated row behavior.
- Add delegated `click` handling for:
  - `[data-copy-value]` and `[data-copy-input]` inside the account surface.
  - `[data-secret-show]` and `[data-secret-copy]`.
  - `[data-edit-account]`.
  - `[data-expand]`.
- Add delegated `change` handling for `[data-row-select]` and `[data-autosubmit]`.
- Keep document capture-phase `submit` handling for CSRF synchronization, confirmation, and submit locks.
- Keep `secretState` keyed only by active secret cells. Retain per-cell `AbortController`, warning timer, expiry timer, `visibilitychange`, and `pagehide` cleanup.
- Ensure delegated handlers resolve controls with `event.target.closest(...)` and verify containment in the stable account root.
- Remove replaced one-time `querySelectorAll(...).forEach(addEventListener)` blocks only after delegated paths cover identical behavior.

### Touchpoints
- `static/js/app.js` — replace account-surface direct listeners with delegated dispatch.
- `templates/index.html` — retain data hooks used by delegated handlers.
- `tests/test_uiux.py` — preserve state, string, ordering, and no-browser-storage contracts.
- `tests/test_task6_ui.py` — preserve account controls and CSP-compatible external script behavior.

### Contracts
```javascript
accountsRoot?.addEventListener("click", async (event) => {
  const target = event.target.closest(
    "[data-copy-value], [data-copy-input], [data-secret-show], " +
    "[data-secret-copy], [data-edit-account], [data-expand]"
  );
  if (!target || !accountsRoot.contains(target)) return;
  // Dispatch to existing behavior helpers.
});

accountsRoot?.addEventListener("change", async (event) => {
  const control = event.target.closest("[data-row-select], [data-autosubmit]");
  if (!control || !accountsRoot.contains(control)) return;
  // Dispatch to selection or autosubmit behavior.
});
```

### Acceptance Criteria
- [ ] Copy, reveal, secret-copy, edit, selection, expansion, and autosubmit controls work in initial account rows.
- [ ] The same controls work in account detail fragments inserted after initial page load.
- [ ] Secret requests remain abortable and revealed values remask on timeout, document hiding, and page exit.
- [ ] Global CSRF synchronization and submit locking retain capture-phase behavior.
- [ ] Selection remains in memory only; `localStorage` and `sessionStorage` are not used.
- [ ] Existing Portuguese success and error messages remain unchanged.
- [ ] Replaced direct listener loops are removed rather than duplicated.
- [ ] Unrelated route handlers retain their existing behavior.

### Dependencies
- None

---

## PERF-001: Paginate Account Summaries and Lazy-Load Custom Fields

### Scope
**In scope**:
- Return at most 100 account summary rows per page.
- Apply email, status, registration, rotation, and sort controls on the server.
- Use stable cursor navigation.
- Load custom-field markup and plaintext values for one account on demand.
- Keep service-wide summary counts global.
- Define selection as current-page-only.
- Preserve field-mutation focus using a bounded target-page mechanism.

**Out of scope**:
- Search decrypted custom-field names or values from the account-list text filter.
- Persist selection across pages or navigation.
- Add shared or client-side caching of secret-bearing fragments.
- Add a searchable plaintext index for encrypted custom fields.
- Change custom-field mutation permissions or secret-at-rest encryption.

### Technical Approach
- Change the account text-filter label/placeholder to email-only.
- Parse and validate query parameters:
  - `q`: email substring.
  - `st`: allowed status or empty.
  - `reg`: `0`, `1`, or empty.
  - `rot`: allowed rotation state or empty.
  - `sort`: `email` or `status`.
  - `dir`: `asc` or `desc`.
  - `cursor`: opaque, signed/base64url cursor containing the active sort tuple and account ID.
  - `focus`: optional positive account ID used only to find a page containing a mutation target.
- Build one bounded summary query with `LIMIT 101`, stable ID tie-breaking, and the active filters.
- For rotation filters, express the current `_rotation_state` date rules in SQL or fetch a bounded candidate set only if equivalence is tested for every state.
- Run separate aggregate queries for global service-wide status and rotation counts; do not derive totals from the current page.
- Remove service-wide custom-field value loading/decryption from `index()`.
- Add a route returning a Jinja fragment for one account:
  - Verify the account is linked to the requested service.
  - Require viewer-level access for the read fragment.
  - Query and decrypt only that account's fields for that service.
  - Render edit/delete controls according to existing capabilities.
  - Return `Cache-Control: no-store, private`.
- Render an empty detail-row container with a detail URL. On first expansion, fetch and insert the fragment; keep it only in the live DOM.
- Use PERF-008 delegated handlers for inserted controls.
- Treat all selected IDs as belonging to the current page. Clear selection on navigation and display explicit Portuguese current-page wording.
- After field mutations, redirect with `focus=<account_id>#row-<account_id>`; resolve the bounded page and expand the detail after load.

### Touchpoints
- `service_manager/routes.py` — query parsing, cursor pagination, aggregate counts, focus resolution, and detail-fragment endpoint.
- `templates/index.html` — bounded summary rows, pagination navigation, lazy detail shell, email-only filter copy, and page-selection wording.
- `templates/_account_details.html` — new custom-field fragment reused by the lazy endpoint.
- `static/js/app.js` — server-filter navigation/debounce, lazy detail fetch, cursor links, focus expansion, and page-local selection.
- `service_manager/authorization.py` — reuse existing account/service viewer authorization.
- `tests/test_feature_pack.py` — filters, pagination, bulk selection, permissions, and field behavior.
- `tests/test_task6_ui.py` — detail hooks and account-page markup.
- `tests/test_uiux.py` — Portuguese strings, URL state, focus, selection, and no-storage contracts.

### Contracts
```http
GET /?service=<service_id>&q=<email>&st=<status>&reg=<0|1>&rot=<state>&sort=<email|status>&dir=<asc|desc>&cursor=<opaque>

200 text/html
Cache-Control: no-store, private
```

```http
GET /accounts/<account_id>/details?service=<service_id>
Accept: text/html

200 text/html
Cache-Control: no-store, private
403 caller lacks viewer access to the service
404 account is not linked to the requested service
```

```python
@dataclass(frozen=True, slots=True)
class AccountCursor:
    sort: Literal["email", "status"]
    direction: Literal["asc", "desc"]
    sort_value: str
    account_id: int
```

```html
<tr class="detail-row" id="detail-{{ account_id }}" hidden
    data-detail-url="{{ url_for('routes.account_details', account_id=account_id, service=service_id) }}">
  <td colspan="{{ table_colspan }}" data-detail-content></td>
</tr>
```

### Acceptance Criteria
- [ ] The initial account response contains at most 100 summary rows plus one lookahead row in the database result.
- [ ] `index()` does not query or decrypt custom-field values for the full service.
- [ ] Email, status, registration, rotation, email sort, and status sort are applied before pagination.
- [ ] Cursor navigation is stable when multiple accounts share the same sort value.
- [ ] Active filters and sort parameters survive next/previous navigation.
- [ ] Service-wide status and rotation counts are independent of the current page.
- [ ] The text filter is explicitly email-only and returns no custom-field plaintext matches.
- [ ] Opening one row requests only that account's custom-field fragment.
- [ ] The detail endpoint enforces viewer access, initiating-service linkage, and private/no-store caching.
- [ ] Lazy fragments expose edit/delete controls only to callers with the existing capabilities.
- [ ] Loaded details are retained only in the live DOM and are not placed in browser storage.
- [ ] Bulk selection and “select visible” apply only to the current page and clear on navigation.
- [ ] Field mutation redirects can locate, render, scroll to, and expand the target account without loading an unbounded account set.
- [ ] At 1,000 accounts with five fields, the initial response and peak route memory are at least 80% below the retained unbounded baseline.

### Dependencies
- PERF-008

---

## PERF-002: Paginate Coverage with Server-Side Filters and Sparse In-Memory Cells

### Scope
**In scope**:
- Apply coverage filters to the complete accessible account set on the server.
- Return at most 100 coverage accounts per page.
- Use stable cursor navigation.
- Compute coverage aggregates in SQL.
- Keep only queried links in Python rather than materializing absent cell dictionaries.
- Preserve current persisted account-service semantics.

**Out of scope**:
- Change the `account_service` schema or dense account/service creation behavior.
- Add link/unlink workflows.
- Virtualize or paginate service columns.
- Add a coverage export.
- Change service authorization or destructive-operation scope.

### Technical Approach
- Replace client-only coverage filtering with a GET form.
- Parse:
  - `filter`: empty, `none-registered`, `multi-active`, or `missing-registration`.
  - `services`: repeated accessible service IDs used only by `missing-registration`.
  - `cursor`: opaque email/ID cursor.
- Reject or ignore service IDs outside the caller's accessible services without leaking inaccessible service existence.
- Build SQL aggregates per accessible account:
  - `registered_count` across accessible services.
  - `active_count` across accessible services.
  - selected-service registration count for `missing-registration`.
- Apply the selected filter in `HAVING` before pagination.
- Query `LIMIT 101`, ordered by `email COLLATE NOCASE, id`.
- Fetch `account_service` rows only for page account IDs and accessible service IDs.
- Store those rows in `links_by_account[(account_id, service_id)]`; do not allocate default dictionaries.
- Let the template render current default/missing behavior when the map lookup returns `None`.
- Preserve selected filter/service parameters in cursor navigation.
- Show total filtered account count and current page range/count.
- Remove the full-table JavaScript row scan; retain only small form behavior needed to show selected-service controls for `missing-registration`.

### Touchpoints
- `service_manager/routes.py` — coverage filter validation, aggregate SQL, total count, cursor page, and page-link query.
- `templates/coverage.html` — GET filter form, sparse lookup, pagination, total/page count.
- `static/js/app.js` — remove full-table coverage filtering and retain conditional fieldset visibility.
- `tests/test_feature_pack.py` — coverage semantics, missing/default cells, filters, authorization, and pagination.
- `tests/test_uiux.py` — coverage controls and Portuguese count text.

### Contracts
```http
GET /coverage?filter=<mode>&services=<service_id>&services=<service_id>&cursor=<opaque>

200 text/html
Cache-Control: no-store, private
```

```python
@dataclass(frozen=True, slots=True)
class CoverageCursor:
    email: str
    account_id: int
```

```python
links_by_account: dict[tuple[int, int], dict[str, object]]
# Missing key: render the existing absent/default coverage cell behavior.
```

### Acceptance Criteria
- [ ] Coverage filters apply to the complete accessible result set before pagination.
- [ ] A page renders at most 100 accounts.
- [ ] Cursor ordering is stable for duplicate case-insensitive email values.
- [ ] `none-registered`, `multi-active`, and `missing-registration` retain current semantics.
- [ ] An empty selected-service set in `missing-registration` retains the current show-all behavior.
- [ ] Inaccessible service IDs do not expand the query scope or reveal service existence.
- [ ] Registration and active counts are computed in SQL.
- [ ] Python allocates link objects only for query-returned `account_service` rows.
- [ ] The template renders absent/default cells without prebuilding an account × service dictionary.
- [ ] Filter and selected-service parameters survive pagination.
- [ ] The page shows total filtered count and page-local count.
- [ ] The browser no longer scans and hides every coverage row client-side.
- [ ] Account creation, service creation, import/export, rotation, and authorization behavior remain unchanged.
- [ ] The 10,000-account × 20-service synthetic model no longer allocates 200,000 cell dictionaries.

### Dependencies
- None
