# Performance Optimizations Report

**Project:** Service Manager — Flask/Gunicorn + SQLite credential vault (nginx sidecar, Docker/Dokploy deploy)
**Analyzed:** 2026-07-21 · branch `main` @ `e660ba4`

## Executive Summary

The app is small and mostly well-built (WAL mode, `BEGIN IMMEDIATE` writer discipline, lazy `openpyxl` import, `lru_cache`d asset hashes, indexed rate-limit tables). There is **one architectural scaling cliff and one trivial transport win** that dominate everything else:

1. **Every mutating request re-verifies the entire HMAC-chained audit log — up to 3× per request.** The audit table is append-only and never pruned, so every POST gets slower forever. Measured cost: ~3 µs/row for the pure HMAC+JSON walk (Python 3.12, this machine) plus SQLite row materialization ≈ **~5 µs/row → 50 ms per walk at 10k events, ×3 walks ≈ 150 ms of pure overhead per POST**, and ~1.5 s/POST at 100k events. `/healthz` does the same walk every 30 s (Docker HEALTHCHECK + Dokploy probes).
2. **No gzip and no static-asset caching in nginx.** The index page inlines every account row twice (main row + detail row, ~3–4 KB HTML each); at 116 accounts that is roughly **400–500 KB of HTML per navigation, uncompressed**, plus 21 KB JS + 21 KB CSS proxied through Gunicorn on every load (Flask serves static with conditional requests, not immutable caching, despite `asset_ver` cache-busting already existing).

The first item splits into a free part and a guarded part: **deduplicating the 3 redundant walks per POST is a zero-security-cost 3× win to ship immediately**; going fully O(1) via a verification watermark trades away historical tamper-detection latency and must be adopted with an explicit detection window (see PERF-001). The second item is pure upside. Together they yield flat-over-time request latency and ~85–90% smaller page weight on the wire. Everything else below is secondary.

---

## High Impact Optimizations

### PERF-001: Incremental audit-chain verification (replace full-table walk per request)

**Category:** runtime / database
**Impact:** high
**Estimated Effort:** medium

**Affected Areas:**
- `service_manager/audit.py` (`verify_audit_chain`, `verify_audit_chain_with_key`)
- `service_manager/auth.py` (`bind_auth.guard_sensitive_mutations`, `_require_audit_chain`)
- `service_manager/routes.py` (`guard_sensitive_route_mutations`, `_require_audit_chain`, inline calls in `add`/`reveal_password`)

**Current State:**
`verify_audit_chain()` runs `SELECT * FROM audit_events ORDER BY id` and recomputes an HMAC-SHA256 + canonical-JSON per row on **every** POST/PUT/PATCH/DELETE. Worse, the checks are stacked:

1. App-level `before_request` (`guard_sensitive_mutations` in `auth.py`) — walk #1.
2. Blueprint-level `before_request` (`guard_sensitive_route_mutations` in `routes.py`) — walk #2 for the same request.
3. Inline `_require_audit_chain()` inside `add()` and `reveal_password()` — walk #3.

Every successful mutation also *appends* an audit row, so the cost curve is strictly increasing: logins, status toggles, reveals, imports all grow the table. Measured: HMAC+JSON walk alone is ~3 µs/row (30 ms per 10k rows); with SQLite fetch overhead expect ~5 µs/row. A busy year of usage (say 50k–100k events) puts every save/toggle/reveal at **0.75–1.5 s of pure verification overhead**.

**Expected Improvement:**
- **Dedup alone (safe, no security change):** 3 walks/POST → 1, an immediate ~3× cut with zero effect on tamper detection.
- **Dedup + watermark:** per-request cost drops from O(total events) to O(events since last check) ≈ O(1) — from hundreds of ms (and growing) to <1 ms — but only the incremental part is per-request; historical integrity now depends on the scheduled full walk (see Tradeoffs), not on every request.

**Implementation:**
1. Keep the full walk exactly once, at startup (already done in `create_app`).
2. After the startup walk, store a **verification watermark** in a module-level, lock-protected struct: `{last_verified_id, last_verified_hash}`.
3. Change the per-request check to fetch only `WHERE id > last_verified_id ORDER BY id`, seed `previous_hash` from `last_verified_hash`, verify the delta, advance the watermark. Cross-check that row `last_verified_id` still exists with the same `event_hash` (one PK lookup) so truncation and rewrites *of the anchor row itself* fail closed.
4. **Run the full walk on a bounded schedule, not just at startup** — every N minutes or every K appends, whichever comes first (e.g. 5 min / 1000 events). This is what re-establishes historical tamper detection; pick the interval to match your acceptable detection window (see Tradeoffs). The full walk can run inline on the triggering request when the timer/counter fires, or on a background thread.
5. Deduplicate the guards regardless of the rest: remove the routes-blueprint `before_request` and the inline `_require_audit_chain()` calls — the app-level `guard_sensitive_mutations` already covers every unsafe method, so ~2 of the 3 walks per POST are pure waste today. **This dedup is safe to ship on its own** (no security change: one full walk per mutation instead of three) and captures most of the win.
6. Each Gunicorn worker holds its own watermark and its own periodic-walk clock; workers converge independently and a mismatch always fails closed with a full re-walk.

**Tradeoffs (read before adopting the watermark):**
- **This weakens historical tamper detection, and the honest framing matters.** *Today*, every mutation triggers a full walk, so tampering with **any** row — however old — is caught within roughly one request. With a per-request watermark, an out-of-band rewrite of an already-verified row (id ≤ watermark, other than the single anchor row that gets the PK re-check) goes **undetected until the next scheduled full walk** — up to the whole detection window you configure in step 4, and up to a worker's entire lifetime if you keep only the startup walk. That is a genuine reduction, not "effectively unchanged."
- The append-only triggers (`audit_events_no_update/no_delete`) are the real integrity control against in-DB tampering; the chain HMAC is defense-in-depth against an attacker who can also drop the triggers or write the file directly. Under that threat model, per-request full walking narrows the window to seconds — a property you lose here unless the scheduled walk is frequent.
- **If you need O(1) checks *and* strong historical tamper detection, the DB alone can't give you both** — the mutable SQLite file is exactly what the attacker controls. That requires an authenticated proof anchored outside the DB: periodically publish the latest `event_hash` (a Merkle-style head) to append-only/trusted storage (e.g. a WORM bucket, an external log, or a signed receipt), then a cheap check verifies only new rows chain up to a head you already trust. Out of scope for this change, but it's the only way to escape the walk-cost / detection-window tradeoff.
- Net recommendation: **ship step 5 (dedup) now** for a 3× reduction at zero security cost. Adopt the watermark (steps 2–4) only with an explicitly chosen, documented detection window, or defer it until an external-anchor scheme (or the whole audit design) justifies it. Do **not** present the watermark as free.

**Code Example:**
```python
# Current (audit.py): full table, every mutating request, up to 3x
for row in conn.execute("SELECT ... FROM audit_events ORDER BY id"):
    expected = hmac.new(key, _canonical_bytes(payload) + previous_hash, sha256).digest()
    ...

# Optimized: verify only the delta past the watermark
def verify_audit_chain_incremental(conn, key, mark):  # mark = (id, hash) after startup walk
    anchor = conn.execute("SELECT event_hash FROM audit_events WHERE id=?", (mark.id,)).fetchone()
    if mark.id and (anchor is None or not hmac.compare_digest(bytes(anchor[0]), mark.hash)):
        return full_walk(conn, key)  # fail closed, re-walk
    prev, expected_id = mark.hash, mark.id + 1
    for row in conn.execute("SELECT ... FROM audit_events WHERE id > ? ORDER BY id", (mark.id,)):
        ...  # same per-row check as today
    mark.update(expected_id - 1, prev)
    return True
```

---

### PERF-002: `/healthz` runs full chain walk + schema introspection every probe

**Category:** runtime / caching
**Impact:** high (same root cause as PERF-001; probes run forever at 30 s intervals)
**Estimated Effort:** small

**Affected Areas:**
- `service_manager/routes.py` (`healthz`)
- `Dockerfile` (HEALTHCHECK, 30 s interval), `docker/supervisor.py` (startup polling)

**Current State:**
Every probe executes `schema_is_current()` (sqlite_master dump + `PRAGMA table_info` per table, ~9 tables) **and** `verify_audit_chain()` (full O(n) walk). Docker healthcheck alone is 2,880 full walks/day; Dokploy/Traefik probes add more. At 50k audit events that's ~250 ms per probe of steady-state CPU burn, competing with the 2 sync workers serving users.

**Expected Improvement:**
Probe cost drops to one `SELECT 1` + incremental delta check: from O(n)/probe to ~100 µs/probe, flat.

**Implementation:**
1. After PERF-001, the probe's chain check becomes the incremental one. **Note the coupling:** the 30 s healthcheck is today's de-facto continuous integrity monitor — it catches historical tampering within ~30 s. Dropping it to an incremental check removes that monitor, which is precisely why PERF-001 step 4's scheduled full walk matters; a natural place to *host* that periodic full walk is the health probe itself (full-walk on the probe every Nth tick, incremental otherwise), keeping a bounded detection window without taxing user requests.
2. `schema_is_current()` cannot change while the process lives (schema is only created at init). Run it once at startup and cache the boolean; keep only the `SELECT 1` liveness ping per probe.

**Tradeoffs:** A probe no longer detects out-of-band schema surgery on the live DB file. That scenario already requires stopping the app per your migration runbook; a container restart re-validates.

---

### PERF-003: Enable gzip and immutable static caching in nginx; serve `/static/` directly

**Category:** network / bundle size
**Impact:** high
**Estimated Effort:** trivial

**Affected Areas:**
- `docker/nginx.conf`
- `Dockerfile` (static files are already copied into the image at `/app/static`)

**Current State:**
- No `gzip on` anywhere. The index page renders **two `<tr>` blocks per account (~3–4 KB each)** including 4+ inline SVG copy buttons, per-row forms, and repeated CSRF fields → ~400–500 KB HTML at 116 accounts, sent uncompressed on every page view and after every non-async form redirect.
- `/static/*` requests are proxied to Gunicorn; Flask answers with ETag/conditional semantics, so every page load re-validates `app.js`/`app.css` even though templates already append a content-hash query (`asset_ver` → `?v=<sha256[:12]>`), which makes them perfectly immutable-cacheable.

**Expected Improvement:**
- HTML: ~85–92% smaller on the wire (repetitive markup compresses extremely well) → ~40–60 KB instead of ~450 KB; proportional LCP improvement on slow links.
- `app.js` (21 KB) + `app.css` (20.8 KB): fetched once per deploy instead of revalidated per navigation; zero Gunicorn worker time spent on static files.

**Implementation:**
```nginx
http {
    gzip on;
    gzip_comp_level 5;
    gzip_min_length 1024;
    gzip_types text/css application/javascript application/json image/svg+xml;
    # (text/html is compressed by default when gzip is on)
    gzip_vary on;

    server {
        location /static/ {
            alias /app/static/;
            expires 1y;
            add_header Cache-Control "public, max-age=31536000, immutable";
            # re-add the security headers: add_header replaces inherited ones
        }
        ...
    }
}
```

**Tradeoffs:**
- BREACH-style attacks target reflected secrets under compression. Response bodies here contain CSRF tokens; Flask-WTF tokens are per-session (not per-request randomized), and the origin-check + SameSite=Lax already gate cross-site POSTs, so risk is low — but if you want zero exposure, gzip only `text/css`/`application/javascript`/`image/svg+xml` and leave HTML uncompressed (still saves 40 KB/page of static payload, but forfeits the big HTML win). Decide explicitly.
- `add_header` inheritance quirk: any `add_header` inside `location /static/` drops the server-level security headers; repeat them in the block.

---

## Medium Impact Optimizations

### PERF-004: Cache the AES-GCM key/cipher object instead of rebuilding per secret

**Category:** runtime
**Impact:** medium
**Estimated Effort:** trivial

**Affected Areas:**
- `service_manager/crypto.py` (`_data_key`, `encrypt_secret`, `decrypt_secret`)

**Current State:**
`index()` decrypts **every custom-field value for the selected service** on each page render. Each `decrypt_secret`/`encrypt_secret` call re-runs `_data_key()` (config dict lookup + base64 decode + length check) and constructs a fresh `AESGCM` object. Bulk import does the same per record. The actual AES-GCM operation on short secrets is ~1–5 µs with AES-NI; the setup overhead is comparable, i.e. you pay ~2× per row.

**Expected Improvement:**
~40–50% off decryption time in `index()` and `import_bulk` hot loops. With hundreds of field values this is single-digit ms — real but not user-visible until field counts grow.

**Implementation:**
```python
@functools.lru_cache(maxsize=4)
def _cipher_for(key_b64: str) -> AESGCM:
    key = base64.b64decode(key_b64, validate=True)
    if len(key) != 32:
        raise CryptoError("DATA_KEY_V1 is not configured correctly")
    return AESGCM(key)

def _cipher() -> AESGCM:
    configured = current_app.config.get("DATA_KEY_V1")
    if not isinstance(configured, str) or not configured:
        raise CryptoError("DATA_KEY_V1 is not configured correctly")
    try:
        return _cipher_for(configured)
    except (ValueError, binascii.Error) as error:
        raise CryptoError("DATA_KEY_V1 is not configured correctly") from error
```
`AESGCM` is stateless and thread-safe; caching keyed on the configured string keeps test configs with different keys correct.

**Tradeoffs:** Key material lives in one more long-lived object — it already lives in `app.config` for the process lifetime, so no new exposure.

### PERF-006: Stop deleting `security_events` inside every write transaction

**Category:** database
**Impact:** medium
**Estimated Effort:** small

**Affected Areas:**
- `service_manager/audit.py` (`append_audit_event`, `append_audit_event_in_transaction`, `_cleanup_security_events`)
- `service_manager/auth.py` (`_rate_limited`, `consume_reveal_allowance` — each issues its own 24 h purge DELETE)

**Current State:**
The 24 h retention DELETE runs on **every audit append** (i.e., every mutation), plus again in `_rate_limited` and `consume_reveal_allowance`. `append_audit_event_in_transaction` even runs it twice in one transaction (once itself, once inside `append_audit_event`). Each DELETE is an indexed range scan, but it executes inside the exclusive writer window, dirties B-tree pages when rows expire, and inflates the WAL — pure overhead in the most contended code path.

**Expected Improvement:**
One fewer statement (often two) per write transaction; smaller WAL churn. A few ms per mutation under load; more importantly, shorter writer-lock hold time.

**Implementation:**
Purge opportunistically: keep a module-level `last_cleanup` monotonic timestamp and only run the DELETE if >10 min elapsed (or 1-in-N appends). The rate-limit COUNT queries already filter by `occurred_at >= cutoff`, so stale rows never affect correctness — retention is hygiene, not logic.

**Tradeoffs:** Table briefly holds up to ~24 h + 10 min of rows. Zero behavioral impact.

### PERF-007: Add index on `account_service(service_id)`

**Category:** database
**Impact:** medium (low today, structural)
**Estimated Effort:** trivial (requires the controlled migration path per deploy runbook — schema validator does exact-match comparison)

**Affected Areas:**
- `service_manager/db.py` (SCHEMA)
- `service_manager/routes.py` (`index` account query, `service_add` backfill)

**Current State:**
`account_service` PK is `(account_id, service_id)`. The main page query filters `WHERE link.service_id = ?` — the PK's *second* column — so SQLite full-scans the link table (rows = accounts × services) on every index render. At 116 accounts × a handful of services this is hundreds of rows (fine); it degrades quadratically as both axes grow.

**Expected Improvement:**
Index-range scan instead of full scan on the hottest read query; flat cost as services multiply.

**Implementation:**
`CREATE INDEX account_service_service_id ON account_service(service_id);` — note `_validate_schema_state` compares against the canonical schema, so this must go through the same stop-app → migrate-with-old-image → deploy cutover documented in project memory (`memory://root`), not a hot edit.

**Tradeoffs:** Slightly slower link-table writes (one more index to maintain); negligible.

### PERF-008: Gunicorn worker sizing / worker class

**Category:** runtime
**Impact:** medium
**Estimated Effort:** trivial

**Affected Areas:**
- `docker/supervisor.py` (`--workers 2` hardcoded), `docker/gunicorn.conf.py`

**Current State:**
2 sync workers. Argon2id is configured at `time_cost=3, memory_cost=64 MiB` — each login/reauth/password-change verification blocks a worker for ~100–300 ms and allocates 64 MiB. Two concurrent logins freeze the entire site for everyone (including `/healthz`, risking false-negative health probes under load, which Dokploy may act on).

**Expected Improvement:**
2→4 workers halves p99 queuing during auth bursts; `gthread` with a few threads lets SQLite-bound requests (the C library releases the GIL) overlap with Argon2 verification (argon2-cffi also releases the GIL).

**Implementation:**
Move worker count into `gunicorn.conf.py` (`workers = int(os.environ.get("WEB_CONCURRENCY", "4"))`, optionally `worker_class = "gthread"; threads = 2`), drop the hardcoded `--workers 2` from the supervisor command.

**Tradeoffs:** Each worker holds its own SQLite connection + audit watermark; WAL handles reader concurrency fine, writers still serialize on `BEGIN IMMEDIATE` (unchanged). Memory: +~60 MB/worker baseline, spikes during Argon2 — size to container limits.

---

## Low Impact Optimizations

### PERF-009: Redundant per-request connection setup work

**Category:** runtime
**Impact:** low
**Estimated Effort:** small

**Affected Areas:** `service_manager/db.py` (`get_db`)

Every first `get_db()` in a request: `mkdir(parents=True)`, `enforce_database_permissions()` **twice** (each stat/chmods db + `-wal` + `-shm` = 6+ syscalls), fresh `sqlite3.connect`, `PRAGMA busy_timeout`, `PRAGMA journal_mode = WAL` (persistent property, re-issued per connection). Run mkdir/permission enforcement once at `init_app` and once after schema creation; keep per-connection pragmas only (`busy_timeout`, `foreign_keys`). Saves ~10 syscalls + a stat storm per request; sub-ms but free.

### PERF-010: Session cookie rewritten on every request

**Category:** network
**Impact:** low
**Estimated Effort:** small

**Affected Areas:** `service_manager/auth.py` (`_session_user`)

`session["last_seen_at"] = now` marks the session dirty on **every** authenticated request → itsdangerous re-sign + `Set-Cookie` on every response, including all the async status/registered/reveal fetches. Quantize: only rewrite when `now - last_seen_at > 60` s. Preserves the 15-min idle timeout semantics (worst-case widens it by ≤60 s) and drops cookie churn on bursty UI interactions.

### PERF-011: `_authenticate` re-SELECTs the user unconditionally

**Category:** database
**Impact:** low
**Estimated Effort:** trivial

**Affected Areas:** `service_manager/auth.py` (`_authenticate`)

The post-verify `SELECT * FROM users WHERE id=?` re-fetch is only needed when a rehash actually updated the row; move it inside the `needs_password_rehash` branch. One query saved per login — noise next to Argon2, but free.

### PERF-012: Duplicate `services` query per index render

**Category:** database
**Impact:** low
**Estimated Effort:** trivial

**Affected Areas:** `service_manager/routes.py` (`index`, `selected_service_id`)

`index()` fetches `SELECT id, name FROM services ORDER BY name`, then `selected_service_id()` fetches `SELECT id FROM services ORDER BY name` again. Pass the already-fetched list in (or return `(services, selected)` from one helper). Also builds a throwaway `set` per request for membership; trivial.

### PERF-013: Front-end filter does per-row DOM reads per keystroke

**Category:** rendering
**Impact:** low
**Estimated Effort:** trivial

**Affected Areas:** `static/js/app.js` (`applyFilter`)

`applyFilter` runs on every `input` event and, per row, queries `.status-badge` + `selectedOptions[0].textContent` + normalizes it — a layout-adjacent DOM read × N rows × every keystroke. The status label only changes on explicit status updates: cache the normalized label in `rowInfo` (refresh it in the autosubmit success handler that already calls `refreshFilter()`), and optionally debounce input by ~100 ms. Imperceptible at 116 rows; matters if the vault grows to thousands. Same file is served unminified (21 KB) — gzip (PERF-003) makes minification not worth a build step.

### PERF-005: Batch `import_bulk` writes

**Category:** database
**Impact:** low (measured; only during imports, MAX_RECORDS=5,000)
**Estimated Effort:** small

**Affected Areas:**
- `service_manager/routes.py` (`import_bulk`, `link_all_services`)

**Current State:**
Per imported record: 1 INSERT + 1 UPDATE (AAD needs the rowid — unavoidable with the current AAD design) + `link_all_services` issuing **one upsert per service** via a Python loop that re-runs `SELECT id FROM services` each call. A 5,000-record import into a vault with 10 services = 5,000 SELECTs + 50,000 single-row upserts + 10,000 account statements inside one `BEGIN IMMEDIATE` transaction.

**Measured (this machine, Python 3.12 / SQLite 3.53, WAL):** the full 5,000×10 workload takes **~0.07 s** as written; the batched variant below takes **~0.02 s (~3× faster)**. In-transaction statement overhead is ~1 µs/statement, far below intuition — this is *not* a latency problem at current limits. The residual value is a shorter writer-lock hold window (other writers block behind the 5 s `busy_timeout` during import) and less per-record Python work; production hardware will be slower than this benchmark but stays in the same order of magnitude.

**Expected Improvement:**
~3× faster import (measured), tens of ms saved at maximum import size; marginally shorter writer-lock windows.

**Implementation:**
1. Fetch the service list once before the loop instead of per record.
2. Replace the per-service loop with a single statement per account. **Note the mandatory `WHERE true`:** SQLite's parser treats a bare `SELECT … FROM services ON CONFLICT` as a join clause and fails with `near "DO": syntax error` (verified on SQLite 3.53.3); the `WHERE true` disambiguation is the documented UPSERT-with-SELECT idiom:
```sql
INSERT INTO account_service (account_id, service_id, status, registered)
SELECT ?, id, CASE WHEN id = ? THEN ? ELSE 'nunca' END, CASE WHEN id = ? THEN ? ELSE 0 END
FROM services WHERE true
ON CONFLICT(account_id, service_id) DO UPDATE SET status=excluded.status, registered=excluded.registered
```
3. Optionally accumulate `(ciphertext, nonce, ver, id)` tuples and flush the password UPDATEs via one `executemany`.

**Tradeoffs:** None material; semantics identical (same transaction, same conflict handling). Given the measured numbers, do this only if touching `link_all_services` anyway (e.g. for PERF-007's index migration).

---

## Dependency Analysis

No JS bundle exists (vanilla JS, no build). Python dependencies are lean and used correctly:

| Package | Weight | Usage | Recommendation |
|---------|--------|-------|----------------|
| openpyxl | heavy import (~50 ms+) | XLSX template + import parsing | Already lazily imported inside handlers — keep |
| argon2-cffi | native | Password hashing | Keep; parameters are a deliberate security choice (see PERF-008 for concurrency sizing) |
| cryptography | native | AES-GCM field encryption | Keep; cache cipher object (PERF-004) |
| email-validator | pure py | Email normalization (`check_deliverability=False` — no DNS, good) | Keep |
| flask / flask-wtf / gunicorn | — | Core | Keep |

No duplicates, no dead deps found.

---

## Summary

| Category | Count |
|----------|-------|
| Bundle Size / Network | 2 (PERF-003, PERF-010) |
| Runtime | 4 (PERF-001, PERF-002, PERF-004, PERF-008) |
| Memory | 0 standalone (Argon2 sizing covered in PERF-008) |
| Database | 5 (PERF-005, PERF-006, PERF-007, PERF-011, PERF-012) |
| Rendering | 1 (PERF-013) |
| Caching | folded into PERF-002/003 |

| Impact | Count |
|--------|-------|
| High | 3 (PERF-001, PERF-002, PERF-003) |
| Medium | 4 (PERF-004, PERF-006, PERF-007, PERF-008) |
| Low | 6 (PERF-005, PERF-009…PERF-013) |

**Estimated Total Savings:**
- Mutating-request latency: removes an O(total-audit-events) tax that is already ~150 ms/POST at 10k events and grows without bound → flat <1 ms (PERF-001).
- Health probes: O(n) walk every 30 s → ~100 µs (PERF-002).
- Page weight: ~450 KB HTML → ~50 KB gzipped; 42 KB static assets → fetched once per deploy (PERF-003).
- Bulk import: ~3× faster (measured: 0.07 s → 0.02 s at 5,000 records × 10 services); shorter writer-lock windows (PERF-005/006).

**Measure first:** before/after `duration_us` from the existing Gunicorn JSON access log is sufficient to validate PERF-001/002; `curl --compressed -w '%{size_download}'` validates PERF-003.

**Total Files Analyzed:** 18 (app.py, wsgi.py, service_manager/{routes,auth,db,crypto,audit,csrf,imports,authorization}.py, docker/{nginx.conf,gunicorn.conf.py,supervisor.py,entrypoint.sh}, Dockerfile, templates/index.html, static/js/app.js, static/css/app.css)
