# Repository Guidelines

Service Manager — a self-hosted password/credential vault. Flask 3.1 monolith, SQLite (WAL), AES-256-GCM encryption, Argon2id auth, HMAC-chained audit log. Portuguese UI. Deployed via Docker/Gunicorn/Nginx on Dokploy.

## Project Overview

- **Runtime:** Python `>=3.12,<3.13`. Package manager: `uv`.
- **Web:** Flask 3.1.3, blueprints, Jinja2 templates, vanilla JS/CSS (no framework, no build step).
- **Storage:** SQLite via `sqlite3` with `sqlite3.Row` factory. No ORM — raw SQL throughout. WAL mode.
- **Security:** AES-256-GCM field encryption (`cryptography`), Argon2id password hashing (`argon2-cffi`), HMAC-SHA256 chained audit log, CSRF via Flask-WTF + origin check, strict CSP headers.
- **Deployment:** Docker image → Gunicorn (gthread) behind Nginx (rate limit + CSP), supervised by `docker/supervisor.py`. Webhook delivery runs as a sibling worker process.

## Architecture & Data Flow

Three layers:

1. **`app.py`** — application factory `create_app(config)`. Reads env/config, validates production secrets, wires config, registers blueprints (`routes`, `auth`), initializes DB + CSRF, verifies the audit chain at startup, injects `asset_ver()` into Jinja globals, and installs error handlers + security headers (`after_request`).
2. **`service_manager/`** — domain modules: `auth`, `routes`, `authorization`, `db`, `crypto`, `audit`, `webhooks`, `csrf`, `imports`.
3. **Templates + static** — Jinja2 templates in `templates/`, single versioned `app.css` / `app.js` bundles in `static/`.

Request flow: **Nginx** (rate limit, CSP) → **Gunicorn** (gthread) → **Flask** → **SQLite**. The webhook worker runs as a separate supervised process.

## Key Directories

- `service_manager/` — core domain modules.
- `templates/` — Jinja2 templates (~19 files).
- `static/css/`, `static/js/` — single bundle each, versioned via content hash.
- `tests/` — pytest suites (~14 files, no shared `conftest.py`).
- `scripts/` — offline schema migrations + backup/restore CLIs.
- `docker/` — `Dockerfile` (repo root), `entrypoint.sh`, `supervisor.py`, `nginx.conf`, `gunicorn.conf.py`.

## Development Commands

- `uv run pytest -q` — run the test suite.
- `uv run pyright` — type check (standard mode; includes `app.py`, `service_manager`, `docker`, `scripts`, `tests`).
- `uv run pip-audit` — dependency vulnerability audit.
- `python3 app.py` — dev server (development env; audit key defaults, secrets optional).
- `uv run python scripts/backup.py ...` / `scripts/restore_backup.py ...` — backup/restore CLIs.

**Migrations run offline, before deploying.** The new image rejects an old schema — run the relevant `scripts/migrate_*.py` against a backup, validate with `scripts/verify_migrated_db.py`, then deploy.

## Code Conventions & Common Patterns

- **Raw SQL only** — no ORM. Use `get_db()` (Flask `g`-cached `sqlite3.Connection`, `sqlite3.Row` factory).
- **Writes** use the `transaction(conn)` context manager — issues `BEGIN IMMEDIATE` to take the writer lock upfront.
- **Portuguese UI strings are required** and pinned by tests — changing UI text breaks assertions.
- **Auth:** session-based (Flask signed cookies, 8h max / 15m idle). Login/session/decorators live in `service_manager/auth.py`.
- **RBAC:** `require_role(*roles)` decorator for route-level roles; `require_service_role(conn, service_id, minimum_role)` for per-service authorization (aborts 403, returns granted role).
- **Encryption:** AES-GCM with AAD binding via typed helpers in `service_manager/crypto.py`.
- **Audit:** HMAC-SHA256 chained. Use `append_audit_event(conn, ...)` inside a transaction; `append_audit_event_in_transaction(...)` for standalone non-business events.
- **CSRF:** Flask-WTF + origin check (`service_manager/csrf.py`). Reauth POST returns `204`.
- **Migration pattern:** snapshot → validate → build temp DB → validate → atomic place → cleanup.
- **Frontend:** no `sessionStorage` / `localStorage`. Avoid `form.submit()` for bulk operations — it bypasses the submit-event lock and can double-post.

## Important Files

- `app.py` — application factory, security headers, asset versioning.
- `service_manager/routes.py` — all business endpoints (largest module).
- `service_manager/auth.py` — session, login, `require_role`.
- `service_manager/db.py` — `SCHEMA` string, `get_db()`, `transaction()`.
- `service_manager/authorization.py` — RBAC, `require_service_role()`.
- `service_manager/crypto.py` — AES-GCM + Argon2 helpers.
- `service_manager/audit.py` — chained audit log.
- `service_manager/webhooks.py` — durable webhook delivery + degraded-audit recording.
- `service_manager/csrf.py` — Flask-WTF wrapper.
- `service_manager/imports.py` — CSV/XLSX import parser.
- `docker/entrypoint.sh` — secret presence + base64-key validation.
- `pyproject.toml` — dependencies + pyright config.

## Runtime & Tooling Preferences

- Python `>=3.12,<3.13`; package manager `uv`; type checker `pyright` (standard mode).
- No frontend build — single `app.css` + `app.js` bundles, versioned via `asset_ver()` (12-char SHA-256 content hash). Use versioned URLs when verifying deploys.
- **Four master keys** (base64-encoded 32-byte; validated by `docker/entrypoint.sh`; never echo full env — it leaks them):
  - `SECRET_KEY` — Flask session signing.
  - `DATA_KEY_V1` — AES-GCM field encryption.
  - `BACKUP_KEY_V1` — backup encryption.
  - `AUDIT_KEY_V1` — HMAC audit chain.

## Testing & QA

- pytest 9.1.1; plain `def test_*` functions, no classes.
- No shared `conftest.py` — each file self-contains its fixtures.
- `app` fixture uses `tmp_path` for an isolated SQLite DB.
- Auth helpers: `authenticate()`, `login_admin()`, `reauth()`. CSRF disabled in most suites (`WTF_CSRF_ENABLED: False`).
- Portuguese UI strings pinned in assertions — changing UI text breaks tests.
- Seed helpers use raw SQL `INSERT`s.
- Migration tests verify row preservation, schema shape, audit-chain integrity, FK integrity, and file permissions.

## Deployment

- Access the deploy server via SSH using `ssh quantmind` (Tailscale alias).
- **Always back up the database before any deploy, and confirm the backup succeeded.**
- Run schema migrations **offline** before pushing a new image — the new image rejects an old schema.
