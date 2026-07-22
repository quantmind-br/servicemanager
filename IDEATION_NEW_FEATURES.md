# Feature Ideas Analysis Report

## Executive Summary

Service Manager is a Portuguese-language internal credential vault for organizing shared accounts by service. It already supports encrypted passwords and custom fields, per-service account state, CSV/XLSX import, role-based access, audited mutations, and encrypted backups.

The strongest near-term opportunities expose capabilities already present but not reachable through the interface: user administration and audit history. Other high-value extensions close natural workflow gaps around export, bulk maintenance, cross-service visibility, and credential rotation. The largest proposal—service-level permissions—should follow those improvements because it changes the current global authorization model.

Nine ideas are proposed: three small, three medium, two large, and one epic. Recommended sequence: FEAT-001, FEAT-005, FEAT-003, FEAT-004, then FEAT-006 and FEAT-007.

## Application Overview

**Purpose:** Securely store and manage service-account credentials, registration state, status, and service-specific fields.

**Target Users:** [INFERENCE] Small internal operations or administrative teams that share responsibility for accounts across multiple external services.

**Core Workflows:**
- Authenticate, reauthenticate for sensitive actions, and manage the current user's login and password.
- Create or select a service.
- Add, edit, filter, sort, reveal, copy, classify, and delete accounts.
- Track whether each account is registered and whether its state is active, unused, or inactive for the selected service.
- Add encrypted service-specific fields to accounts.
- Import accounts from validated CSV or XLSX files.
- Administer users through existing JSON/form endpoints.
- Record business and security mutations in an append-only HMAC-chained audit log.

**Current Capabilities:**
- Flask/Jinja server-rendered application with vanilla JavaScript and responsive CSS.
- SQLite data store using WAL and strict schema validation.
- AES-GCM encryption for passwords and custom-field values.
- Global `admin` and `operador` roles, secure sessions, CSRF protection, Argon2 password hashing, and login/reveal rate limiting.
- Per-service account status and registration flag; accounts are globally linked to every service.
- Thirty-second secret reveal/copy flow with recent reauthentication and audit events.
- CSV/XLSX templates and guarded bulk import for admins.
- Encrypted scheduled backups, restore tooling, health checks, and migration scripts.

## Feature Ideas

### Small Complexity (1-3 days)

#### FEAT-001: Admin User Management Interface

**Category:** workflow

**User Problem:**
Administrators can create users, change roles, and activate or deactivate accounts only by calling backend endpoints directly. Routine access management therefore requires technical knowledge and risks manual API mistakes.

**Description:**
Add an admin-only user page listing username, role, active state, and mandatory-password-change state. Provide forms to create users, change roles, and activate/deactivate users. Display the generated temporary password once, with explicit copy and dismissal controls. Require recent reauthentication before mutations, matching existing endpoint behavior.

**User Benefit:**
Administrators can manage access safely from the application without scripts or handcrafted HTTP requests.

**Dependencies:**
- Existing `/admin/users` endpoints and last-active-admin protection.
- Existing role guards, reauthentication flow, CSRF handling, copy feedback, and audit events.

**New Components Needed:**
- Admin user-management template and navigation entry.
- Browser-side handling for `204`, validation errors, and one-time temporary-password display.
- HTML response or page route for the existing user list.

**Affected Areas:**
- `service_manager/auth.py`
- `templates/base.html`
- `templates/admin_users.html`
- `static/js/app.js`
- `static/css/app.css`
- `tests/test_auth.py`
- `tests/test_uiux.py`

**Risks:**
- Temporary passwords must never persist in the DOM after dismissal or appear in logs.
- Role or active-state changes can invalidate sessions; UI must handle the current user being affected.
- Last active administrator protection must remain authoritative on the server.

**Priority Signals:**
- High value because the complete backend workflow already exists.
- Low schema and architectural risk.
- Removes a current operational dependency on direct API usage.

---

#### FEAT-002: Shareable and Persistent Account Views

**Category:** ux

**User Problem:**
Search text, status filters, registration filters, and sort order reset after navigation or refresh. Users repeatedly rebuild the same view while reviewing account groups.

**Description:**
Synchronize selected service, search query, column filters, and sort state with URL query parameters. Restore state on page load and update the URL with `history.replaceState`. Add a “Copiar link da visão” action so another authenticated user can open the same view.

**User Benefit:**
Users resume work after refresh, bookmark frequent views, and share precise account subsets without describing filter steps.

**Dependencies:**
- Existing client-side fuzzy filter, status/registration filters, sortable columns, and selected-service query parameter.

**New Components Needed:**
- URL state serializer/parser.
- Share-view control and accessible feedback.
- Validation and fallback for stale or invalid query values.

**Affected Areas:**
- `templates/index.html`
- `static/js/app.js`
- `static/css/app.css`
- `tests/test_uiux.py`

**Risks:**
- Search terms must remain non-sensitive; custom-field values currently participate in search, so the URL must store only user-entered query text and never derived row data.
- Browser history behavior must not create an entry for every keystroke.

**Priority Signals:**
- Frequent-workflow improvement using existing UI state.
- No database change.
- Independently deliverable before saved server-side presets.

---

#### FEAT-003: Non-Secret Inventory Export

**Category:** integration

**User Problem:**
Administrators can import account inventories but cannot export them for review, reconciliation, or controlled reporting.

**Description:**
Add admin-only CSV and XLSX export for the selected service. Export only inventory metadata: email, status, registration state, and configured custom-field names. Exclude account passwords and every custom-field value unconditionally; the current schema does not classify custom fields, and all field values are encrypted at rest. Include service name and export timestamp in the file metadata or filename.

**User Benefit:**
Teams can reconcile Service Manager with external processes, perform offline reviews, and create operational reports without copying table rows manually.

**Dependencies:**
- Existing service, account, and custom-field metadata queries; role guard; CSV generation; OpenPyXL dependency; and audit logging.

**New Components Needed:**
- Export routes and serializers.
- Admin export controls with format selection.
- Audit action recording export scope and row count, never exported values.

**Affected Areas:**
- `service_manager/routes.py`
- `templates/index.html`
- `tests/test_task7_imports.py`
- `tests/test_task5_security.py`

**Risks:**
- Accidental secret disclosure is the primary risk; passwords and all custom-field values must remain excluded. Field names are metadata only and may be omitted by administrators if their labels are sensitive.
- Spreadsheet formula injection must be neutralized for cells beginning with formula control characters.
- Large exports should use bounded memory, even though current inventory size is small.

**Priority Signals:**
- Natural counterpart to existing import.
- Clear administrative and audit value.
- Small scope because it exports only existing non-secret inventory metadata and requires no schema change.

---

### Medium Complexity (1-2 weeks)

#### FEAT-004: Bulk Account Actions

**Category:** productivity

**User Problem:**
Status, registration, deletion, and field operations must be repeated account by account. Large onboarding or cleanup jobs become slow and error-prone.

**Description:**
Add row selection with “select visible” support and a bulk-action bar. Initial actions: change status, mark registered/unregistered, and apply a custom field value to selected accounts. Restrict bulk deletion to admins and require a typed confirmation showing the selected count. Execute each operation in one transaction and one summarized audit event plus affected identifiers where safe.

**User Benefit:**
Users can complete routine service maintenance in seconds instead of repeating identical edits across many accounts.

**Dependencies:**
- Existing single-account status/registration updates.
- Existing `field_add` support for multiple `account_ids`.
- Existing filtering, confirmation dialog, transactions, role guards, and audit chain.

**New Components Needed:**
- Selection controls and bulk-action toolbar.
- Validated bulk routes with limits on selected IDs.
- Transactional batch update logic and partial-failure policy.

**Affected Areas:**
- `service_manager/routes.py`
- `templates/index.html`
- `static/js/app.js`
- `static/css/app.css`
- `tests/test_task6_ui.py`
- `tests/test_task5_security.py`

**Risks:**
- Bulk deletion has high blast radius and must not accept accounts outside the selected service.
- Large request bodies need explicit account-count limits.
- UI selection must remain consistent when filters or sorting change.

**Priority Signals:**
- Backend already contains a multi-account field path, reducing implementation risk.
- High value once inventories contain dozens or hundreds of accounts.
- Can ship incrementally, starting with non-destructive status and registration changes.

---

#### FEAT-005: Audit Log Viewer and Export

**Category:** data

**User Problem:**
The application records a strong tamper-evident history, but administrators cannot inspect it. Investigation, accountability, and compliance workflows require direct database access.

**Description:**
Add an admin-only audit page with pagination and filters for date, actor, action, target type, and source IP. Present safe metadata in readable form and show chain-health status. Add a filtered CSV export containing event metadata and hashes but no secret material. Sensitive access should require recent reauthentication.

**User Benefit:**
Administrators can answer who changed what and when, investigate authorization failures, and provide a verifiable operational record.

**Dependencies:**
- Existing append-only `audit_events` table, HMAC chain verification, safe metadata rules, user identities, and admin guards.

**New Components Needed:**
- Paginated audit-query service or route.
- Audit viewer template and filters.
- Safe CSV serializer and chain-health indicator.
- Database indexes if production query measurements show they are needed.

**Affected Areas:**
- `service_manager/audit.py`
- `service_manager/auth.py`
- `service_manager/routes.py`
- `service_manager/db.py`
- `templates/base.html`
- `templates/audit.html`
- `static/css/app.css`
- `scripts/migrate_auth_schema.py`
- `tests/test_task5_security.py`

**Risks:**
- Metadata and user-agent strings are untrusted display content and require normal template escaping and CSV injection protection.
- Viewer queries must not mutate, reorder, or prune the append-only chain.
- New indexes are schema changes and require the controlled migration-first deployment process.

**Priority Signals:**
- Unlocks value from an already implemented security subsystem.
- High operational value after suspicious login, reveal, or deletion events.
- Should precede external security alerts because it provides the investigation surface.

---

#### FEAT-006: Cross-Service Account Coverage Matrix

**Category:** data

**User Problem:**
The current page shows one service at a time, while accounts are linked globally to every service. Users cannot quickly see which services an account is registered or active on, or identify coverage gaps across the whole inventory.

**Description:**
Add a matrix/report view with accounts as rows and services as columns. Each cell summarizes registration and status. Provide filters for “not registered anywhere,” “active in multiple services,” and “missing registration in selected services.” Allow navigation from a cell to the existing service-specific row.

**User Benefit:**
Teams can identify duplicate usage, incomplete onboarding, and stale cross-service access from one screen.

**Dependencies:**
- Existing global `accounts`, `services`, and `account_service` relationship.
- Existing status/registration values and account-row anchors.

**New Components Needed:**
- Aggregate cross-service query.
- Responsive matrix or compact report template.
- Coverage filters and summary counts.

**Affected Areas:**
- `service_manager/routes.py`
- `templates/base.html`
- `templates/coverage.html`
- `static/js/app.js`
- `static/css/app.css`
- `tests/test_task6_ui.py`

**Risks:**
- A wide matrix becomes hard to use on mobile; compact cards or horizontally sticky headers may be necessary.
- Query and rendering costs grow with accounts multiplied by services.
- Current global-link behavior must remain clear: an unused cell is still an existing relationship with default state.

**Priority Signals:**
- Directly reflects the existing data model but is absent from the selected-service UI.
- High value for multi-service operations.
- No schema change required for the initial read-only report.

---

### Large Complexity (2-4 weeks)

#### FEAT-007: Credential Rotation Schedule and Reminders

**Category:** workflow

**User Problem:**
The vault stores credentials but does not track when an account password was last rotated or when it should be changed. Stale credentials can remain unnoticed.

**Description:**
Track `password_changed_at`, an optional rotation interval, and an optional next-due date for service accounts. Update the timestamp when a password changes. Show due-soon and overdue badges, dashboard counts, filters, and a guided rotation workflow that records completion without exposing the secret. Support per-service defaults with per-account overrides.

**User Benefit:**
Users can proactively maintain credentials, reduce long-lived password risk, and demonstrate rotation hygiene.

**Dependencies:**
- Existing encrypted password update flow, service/account model, filters, status summaries, and audit events.

**New Components Needed:**
- Account rotation metadata and migration.
- Rotation policy settings and precedence rules.
- Due-date calculation, dashboard/filter UI, and audited completion flow.
- Optional in-application reminder queue.

**Affected Areas:**
- `service_manager/db.py`
- `service_manager/routes.py`
- `service_manager/audit.py`
- `templates/index.html`
- `templates/rotation.html`
- `static/js/app.js`
- `static/css/app.css`
- `scripts/migrate_auth_schema.py`
- `tests/test_secure_schema.py`
- `tests/test_task6_ui.py`

**Risks:**
- Existing records lack trustworthy historical rotation dates and need an explicit “unknown” state.
- Changing an external service password and updating the vault is not atomic; the workflow must represent incomplete rotations.
- Schema migration requires backup, validation, and migration-first production cutover.

**Priority Signals:**
- Strong security and operational value for a credential manager.
- Best after audit viewing, which gives administrators evidence for rotation changes.
- Can begin with manual due-date tracking before adding notifications.

---

#### FEAT-008: Configurable Security Event Webhooks

**Category:** integration

**User Problem:**
Rate limits and audit events detect suspicious behavior, but administrators learn about it only by checking the application or database after the fact.

**Description:**
Add configurable outbound webhooks for selected high-signal events: repeated login failures, reveal-rate-limit activation, authorization failures, audit-chain degradation, user deactivation, and destructive admin actions. Deliver minimal signed JSON payloads through an asynchronous, retry-bounded queue. Provide test-delivery and event-selection controls.

**User Benefit:**
Teams receive timely alerts in Slack, Microsoft Teams, Discord, SIEM, or custom automation systems without giving those systems database access.

**Dependencies:**
- Existing `security_events`, audit actions, health state, and source-IP capture.
- Existing deployment secrets/configuration mechanism.

**New Components Needed:**
- Webhook configuration storage with encrypted signing secret.
- Delivery queue, retry schedule, timeout policy, and delivery log.
- SSRF-safe destination validation and signed payload format.
- Admin configuration and test-delivery UI.

**Affected Areas:**
- `service_manager/auth.py`
- `service_manager/audit.py`
- `service_manager/routes.py`
- `service_manager/db.py`
- `app.py`
- `templates/security_integrations.html`
- `docker/supervisor.py`
- `scripts/migrate_auth_schema.py`
- `tests/test_task5_security.py`
- `tests/test_task8_packaging.py`

**Risks:**
- User-configured URLs create SSRF risk; private, loopback, link-local, credential-bearing, and redirect destinations need strict handling.
- Synchronous delivery would slow or break security-sensitive requests; failures must never roll back the primary action.
- Payloads must exclude secrets and avoid leaking sensitive metadata.

**Priority Signals:**
- High value for teams with existing incident-response channels.
- More complex than the audit viewer because reliable delivery adds a new subsystem.
- Should follow FEAT-005 so alerts link to an internal investigation view.

---

### Epic Complexity (1-2 months)

#### FEAT-009: Service-Level Permissions and Ownership

**Category:** collaboration

**User Problem:**
Roles are global. Every active operator can reach every service, while administrators alone receive elevated actions. Teams cannot restrict sensitive services to their owners or delegate administration for one service.

**Description:**
Introduce service memberships with roles such as viewer, editor, and service administrator. Let global administrators assign users or groups to services. Enforce membership on every service-scoped query, mutation, reveal, import, export, and cross-service report. Add an ownership page and explicit handling for users with no assigned services.

**User Benefit:**
Organizations can use one Service Manager instance across teams while applying least privilege and clear service ownership.

**Dependencies:**
- Existing users, global roles, service selection, role guards, audit events, and account-service relationships.

**New Components Needed:**
- User-service membership schema and migration.
- Central service-authorization policy layer.
- Membership administration UI and permission-aware navigation.
- Full route, query, audit, and test review for authorization boundaries.

**Affected Areas:**
- `service_manager/db.py`
- `service_manager/auth.py`
- `service_manager/authorization.py`
- `service_manager/routes.py`
- `service_manager/audit.py`
- `templates/base.html`
- `templates/index.html`
- `templates/service_access.html`
- `scripts/migrate_auth_schema.py`
- `tests/test_auth.py`
- `tests/test_task5_security.py`
- `tests/test_task6_ui.py`
- `tests/test_task7_imports.py`

**Risks:**
- Missing one service filter could expose credentials across teams; authorization must be centralized rather than repeated ad hoc.
- Global accounts linked to all services complicate email edits and deletion semantics when users have access to only some services.
- Migration defaults must preserve current access until administrators explicitly narrow it.
- This is a security-sensitive schema change requiring migration-first deployment and broad regression coverage.

**Priority Signals:**
- High value only when multiple teams or trust boundaries share one deployment.
- Largest architectural and security risk among proposed ideas.
- Defer until user management, audit visibility, and cross-service semantics are mature.

---

## Summary

| Complexity | Count |
|------------|-------|
| Small | 3 |
| Medium | 3 |
| Large | 2 |
| Epic | 1 |

| Category | Count |
|----------|-------|
| Workflow | 2 |
| Integration | 2 |
| UX | 1 |
| Productivity | 1 |
| Data | 2 |
| Collaboration | 1 |
| Accessibility | 0 |

**Total Ideas:** 9
