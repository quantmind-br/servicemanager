# Service Manager `/api/v1` endpoint reference

Source of truth: decorators and handlers in `service_manager/api.py`.

The generic client accepts **any** future method/path under `/api/v1`. When this file drifts from a live instance, trust the instance status/envelope, then regenerate from source — never invent fields.

Auth: every route requires `Authorization: Bearer smk_v1_…`. Active keys run as global `admin`. Missing/invalid/revoked → `401` with `WWW-Authenticate: Bearer realm="service-manager"` and `Cache-Control: no-store`. JSON error shape: `{"error":{"code":"…","message":"…"}}`.

Success helpers: JSON via `_json` (`Cache-Control: no-store`); empty success via `_empty` → `204`; one-shot secrets also set `Cache-Control: no-store, private`.

Paths below are relative to `/api/v1`.

---

## API keys

| Method | Path | Input | Response | Notes |
|--------|------|-------|----------|-------|
| `GET` | `/api-keys` | none | `200 {"items":[{"id","name","created_at","last_used_at","revoked_at","active"}]}` | |
| `POST` | `/api-keys` | JSON `{"name": str}` | `201 {"id": int, "api_key": str}` | **Secret once** (`api_key`). `Cache-Control: no-store, private`. Conflict → `409 name_conflict`. |
| `DELETE` | `/api-keys/<key_id>` | none | `204` | Revokes key. |

## Services / accounts / fields / bulk

| Method | Path | Input | Response | Notes |
|--------|------|-------|----------|-------|
| `GET` | `/services` | none | `200 {"items":[{"id","name","rotation_days"}]}` | |
| `POST` | `/services` | JSON `{"name": str}` | `201 {"id": int}` | |
| `GET` | `/services/<service_id>` | none | `200 {"id","name","rotation_days"}` | |
| `DELETE` | `/services/<service_id>` | none | `204` | Destructive. |
| `PATCH` | `/services/<service_id>/rotation-policy` | JSON `{"rotation_days": int\|null}` | `204` | Requires rotation enabled; else `404`. |
| `GET` | `/services/<service_id>/accounts` | query: `q`, `status`, `registered` (`0`\|`1`), `rotation`, `sort` (`email`\|`status`), `direction`, `cursor` | `200 {"items":[…], "counts":{…}, "next_cursor", "previous_cursor"}` | Page size 100. |
| `POST` | `/services/<service_id>/accounts` | JSON `{"email","password","status","registered": bool}` | `201 {"id": int}` | `registered` defaults `false`. |
| `GET` | `/services/<service_id>/accounts/<account_id>` | none | `200 {"id","email","status","registered","password_changed_at","rotation_days","rotation_due_at","rotation","fields":[{"id","name","value"}]}` | Field values decrypted. |
| `PATCH` | `/services/<service_id>/accounts/<account_id>` | JSON `{"email", "password"?}` | `204` | Password optional (omit key to leave unchanged; empty string rules follow domain). |
| `DELETE` | `/services/<service_id>/accounts/<account_id>` | none | `204` | Destructive; requires service_admin on all linked services. |
| `POST` | `/services/<service_id>/accounts/<account_id>/password/reveal` | none | `200 {"value": str, "expires_in": 30}` | **Plaintext secret.** `Cache-Control: no-store, private`. Prefer `--output`. |
| `PATCH` | `/services/<service_id>/accounts/<account_id>/status` | JSON `{"status": str}` | `204` | Status ∈ `ativo`\|`nunca`\|`inativo`. |
| `PATCH` | `/services/<service_id>/accounts/<account_id>/registered` | JSON `{"registered": bool}` | `204` | |
| `PATCH` | `/services/<service_id>/accounts/<account_id>/rotation-policy` | JSON partial `rotation_days` / `rotation_due_at` (`YYYY-MM-DD` or null) | `204` | Rotation must be enabled. |
| `POST` | `/services/<service_id>/accounts/<account_id>/rotation` | JSON `{"outcome": str, "new_password"?: str}` | `204` | Rotation must be enabled. |
| `GET` | `/services/<service_id>/accounts/<account_id>/fields/<field_id>` | none | `200 {"id","name","value"}` | Value may be null. |
| `PUT` | `/services/<service_id>/accounts/<account_id>/fields/<field_id>` | JSON `{"value": str}` | `204` | |
| `DELETE` | `/services/<service_id>/accounts/<account_id>/fields/<field_id>` | none | `204` | |
| `POST` | `/services/<service_id>/fields` | JSON `{"name": str, "account_ids": [int…], "value"?: str}` | `201 {"id": int}` | Upserts field values across accounts (1–200 ids). |
| `POST` | `/services/<service_id>/accounts/bulk/status` | JSON `{"account_ids":[int…], "status": str}` | `204` | |
| `POST` | `/services/<service_id>/accounts/bulk/registered` | JSON `{"account_ids":[int…], "registered": bool}` | `204` | |
| `POST` | `/services/<service_id>/accounts/bulk/field` | JSON `{"account_ids":[int…], "field_id": int, "value": str}` | `204` | Set existing field. |
| `POST` | `/services/<service_id>/accounts/bulk/fields` | JSON `{"account_ids":[int…], "name"\|"field_name": str}` | `200 {"field_id": int, "created_count": int}` | Create/reuse empty field rows. |
| `POST` | `/services/<service_id>/accounts/bulk/delete` | JSON `{"account_ids":[int…]}` | `204` | **Destructive bulk.** |

`account_ids` must be a non-empty list of positive ints, deduped, max 200.

## Imports / exports

| Method | Path | Input | Response | Notes |
|--------|------|-------|----------|-------|
| `GET` | `/services/<service_id>/imports/template.csv` | none | `text/csv` attachment `modelo_credenciais.csv` | Download → use `--output`. |
| `GET` | `/services/<service_id>/imports/template.xlsx` | none | xlsx attachment `modelo_credenciais.xlsx` | Download → use `--output`. |
| `POST` | `/services/<service_id>/imports` | **multipart** field `file` (csv/xlsx) | `200 {"added": int, "skipped": int}` | Client: `--form-file file=/path`. |
| `GET` | `/services/<service_id>/exports/accounts.csv` | none | csv attachment with **passwords + field secrets** | `--output` (client writes `0600`). Audits `accounts.exported`. Limit 10000. |
| `GET` | `/services/<service_id>/exports/accounts.xlsx` | none | xlsx attachment with secrets | same as csv. |

## Rotation / coverage

| Method | Path | Input | Response | Notes |
|--------|------|-------|----------|-------|
| `GET` | `/services/<service_id>/rotation` | none | `200 {"service_id","service_name","items":[…]}` | Rotation enabled required; lists unknown/due_soon/overdue. |
| `GET` | `/coverage` | query `filter` ∈ `""`\|`none-registered`\|`multi-active`\|`missing-registration` | `200 {"items","services","next_cursor","previous_cursor"}` | Accessible services matrix. |

## Users / memberships / preferences

| Method | Path | Input | Response | Notes |
|--------|------|-------|----------|-------|
| `GET` | `/users` | none | `200 {"items":[{"id","username","role","is_active","must_change_password","created_at","updated_at"}]}` | |
| `POST` | `/users` | JSON `{"username","role"}` | `201 {"id": int, "temporary_password": str}` | **Secret once.** `Cache-Control: no-store, private`. |
| `GET` | `/users/<user_id>` | none | `200` user object | |
| `PATCH` | `/users/<user_id>` | JSON subset of `{"role", "is_active": bool}` only | `204` | At least one of role/is_active. |
| `GET` | `/memberships` | query optional `user_id`, `service_id` | `200 {"items":[{"user_id","service_id","role","created_at"}]}` | |
| `PUT` | `/services/<service_id>/members/<user_id>` | JSON `{"role": str}` | `204` | |
| `DELETE` | `/services/<service_id>/members/<user_id>` | none | `204` | |
| `GET` | `/users/<user_id>/service-preferences` | none | `200 {"service_ids":[int…], "initial_service_id": int\|null}` | |
| `PUT` | `/users/<user_id>/service-preferences` | JSON `{"service_ids":[int…], "initial_service_id": int\|null}` | `204` | `service_ids` must match exactly the target user's accessible set. |

## Webhooks / settings

| Method | Path | Input | Response | Notes |
|--------|------|-------|----------|-------|
| `GET` | `/webhooks` | none | `200 {"items","event_types","at_capacity"}` | Capacity 20. |
| `POST` | `/webhooks` | JSON `{"url","description"?, "enabled"?: bool, "event_types": [str…]}` | `201 {"id": int, "signing_secret": str}` | **Secret once.** `enabled` defaults true. |
| `GET` | `/webhooks/<config_id>` | none | `200` config object | |
| `PATCH` | `/webhooks/<config_id>` | JSON same shape as create | `204` | |
| `DELETE` | `/webhooks/<config_id>` | none | `204` | |
| `POST` | `/webhooks/<config_id>/test` | none | `204` | Enqueues test delivery. |
| `GET` | `/settings` | none | `200 {"rotation_enabled": bool}` | |
| `PATCH` | `/settings` | JSON `{"rotation_enabled": bool}` | `204` | |

## Audit

| Method | Path | Input | Response | Notes |
|--------|------|-------|----------|-------|
| `GET` | `/audit-events` | query: `page`, `action`, `target_type`, `actor`, `api_key`, `since`, `until`, `source_ip` | `200 {"items","page","has_next","filters","chain_healthy"}` | Page size 50. |
| `GET` | `/audit-events.csv` | same filters | csv download (BOM + chain hashes) | Use `--output`. Max 10000 rows. |

---

## Load-bearing examples

```http
POST /api/v1/services
{"name":"Skill smoke"}
→ 201 {"id": 12}

POST /api/v1/services/12/accounts
{"email":"a@example.com","password":"Segredo1","status":"nunca","registered":false}
→ 201 {"id": 34}

POST /api/v1/services/12/imports
Content-Type: multipart/form-data; field name=file
→ 200 {"added":N,"skipped":M}

POST /api/v1/api-keys
{"name":"agent"}
→ 201 {"id":1,"api_key":"smk_v1_…"}

DELETE /api/v1/api-keys/1
→ 204
```
