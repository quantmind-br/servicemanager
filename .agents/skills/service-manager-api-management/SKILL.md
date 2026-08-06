---
name: service-manager-api-management
description: |
  Operate the Service Manager administrative HTTP API under /api/v1 with an unrestricted (no local allowlist) client for any method and subroute.
  Use when the user asks to consult, create, update, delete, import, export, audit, or automate Service Manager resources via the API; mentions /api/v1, smk_v1, SERVICE_MANAGER_URL, SERVICE_MANAGER_API_KEY, or servicemanager.quantmind.com.br; or needs API-key driven admin automation against this vault.
  Keywords: service manager, /api/v1, smk_v1, API key, services, accounts, fields, imports, exports, rotation, coverage, users, memberships, webhooks, audit, SERVICE_MANAGER_URL, SERVICE_MANAGER_API_KEY.
compatibility: |
  Python 3.12+ standard library only (no third-party deps, no skill-local venv).
  Requires SERVICE_MANAGER_URL and SERVICE_MANAGER_API_KEY in the process environment.
---

# Service Manager API Management

Drive the published admin contract at `/api/v1` with a generic, no-allowlist HTTP client. Active API keys authenticate as global `admin` (`g.current_user.role = "admin"`).

## Prerequisites

**Environment variables (REQUIRED — never accept key via argv, file, or chat paste into the CLI):**

```bash
export SERVICE_MANAGER_URL="https://servicemanager.quantmind.com.br"   # or http://127.0.0.1:8000 for local
export SERVICE_MANAGER_API_KEY="smk_v1_..."                            # admin key; never echo full value
```

**Script location:**

```
<SKILL_DIR>/scripts/service_manager_api.py
```

Run with system `python3` (stdlib only). Do **not** use `curl`/`httpie` for these calls — the script redacts tokens, enforces `/api/v1` namespace, and handles binary downloads/uploads uniformly.

## Before first call

1. Confirm both env vars are set (presence only; do not print values).
2. Run `doctor`:
   ```bash
   python3 <SKILL_DIR>/scripts/service_manager_api.py doctor
   ```
   Expect `authenticated: true`. On exit `3` / `401`, the key is missing, invalid, or revoked — do **not** fall back to session/login.
3. For endpoints not covered by shortcuts, read `references/ENDPOINTS.md` before building payloads. If the live instance disagrees with the reference, trust status/envelope from the instance, then refresh the reference from `service_manager/api.py`.

## Commands

```bash
python3 <SKILL_DIR>/scripts/service_manager_api.py doctor

python3 <SKILL_DIR>/scripts/service_manager_api.py request METHOD PATH \
  [--query KEY=VALUE ...] \
  [--json JSON | --json-file PATH | --data-file PATH --content-type TYPE | --form-file FIELD=PATH] \
  [--header NAME=VALUE ...] \
  [--output PATH]

# Thin shortcuts (compose generic request only)
python3 <SKILL_DIR>/scripts/service_manager_api.py services list
python3 <SKILL_DIR>/scripts/service_manager_api.py services create NAME
python3 <SKILL_DIR>/scripts/service_manager_api.py services delete ID --yes
python3 <SKILL_DIR>/scripts/service_manager_api.py api-keys list
python3 <SKILL_DIR>/scripts/service_manager_api.py api-keys create NAME
python3 <SKILL_DIR>/scripts/service_manager_api.py api-keys revoke ID --yes
```

- `PATH` may be relative (`services`) or absolute within the namespace (`/api/v1/services`). Absolute URLs and any path that escapes `/api/v1` after normalization are rejected.
- Always sends `Authorization: Bearer <key>`, `Accept: application/json`, `User-Agent: service-manager-api-management/1.0`.
- JSON responses print pretty UTF-8. Binary/download responses require `--output`; script writes bytes with mode `0600` and prints `saved: <path> (<n> bytes)`.
- Exit codes: `0` 2xx; `2` usage/config; `3` auth 401; `4` other 4xx; `5` 5xx; `6` transport/TLS. Errors redact `smk_v1_[A-Za-z0-9_-]{43}`.

## Operational discipline (unrestricted admin)

“Unrestricted” means **no local allowlist** and use of the global admin principal — **not** ignoring server authorization, validation, audit integrity, or human confirmation for destructive effects.

1. **Read before write** when a GET exists for the resource.
2. **Destructive confirmation**
   - Shortcuts `services delete` and `api-keys revoke` refuse without `--yes`.
   - For other destructive work via `request DELETE` or bulk-delete routes, obtain explicit user authorization for that specific effect before executing. The generic transport itself does not prompt (so scripted automation still works).
3. **One-time secrets** (`POST /api-keys` → `api_key`; `POST /users` → `temporary_password`; `POST /webhooks` → `signing_secret`):
   - Do not repeat full secrets in chat summaries.
   - If the user asks to persist, write only to the path they name with mode `0600`.
4. **Password reveals and exports** contain plaintext — always use `--output` to a `0600` file; do not dump into chat.
5. **After writes**, re-GET when available. Treat bare `204` as success.
6. **Errors**
   - `401`: do not attempt web session/login.
   - `409`: report the envelope as-is.
   - `429`: no automatic retry loops; wait for user guidance or apply backoff only if they requested resilient automation.
7. **No automatic mutation retries.**

## Common patterns

```bash
# List services
python3 scripts/service_manager_api.py services list

# Create then read
python3 scripts/service_manager_api.py services create "Acme Vault"
python3 scripts/service_manager_api.py request GET /api/v1/services/42

# Create account (JSON body)
python3 scripts/service_manager_api.py request POST /api/v1/services/42/accounts \
  --json '{"email":"a@example.com","password":"...","status":"nunca","registered":false}'

# Import CSV/XLSX (multipart field name must be file)
python3 scripts/service_manager_api.py request POST /api/v1/services/42/imports \
  --form-file file=/path/to/contas.csv

# Export with secrets to file
python3 scripts/service_manager_api.py request GET /api/v1/services/42/exports/accounts.csv \
  --output /tmp/export.csv

# Audit page
python3 scripts/service_manager_api.py request GET /api/v1/audit-events --query page=1
```

## Reference

Full route inventory (method, path, input shape, secrets/downloads): `references/ENDPOINTS.md`.

Derived from `@api.*` decorators in `service_manager/api.py`. Future routes under `/api/v1` are callable via `request` even if missing from the reference — when drift appears, update the reference from source, never invent payloads.
