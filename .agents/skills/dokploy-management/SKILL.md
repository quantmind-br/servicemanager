---
name: dokploy-management
description: |
  Manage a remote Dokploy PaaS instance via its REST API: projects, applications, compose services, databases, Docker containers, domains, deployments, logs, servers, settings, backups, notifications, certificates, registries, users, organizations, RBAC, git providers, SSH keys, schedules, patches, audit logs, white-labeling, enterprise licenses, SSO/OIDC, and forward auth.
  Use when the user wants to deploy or administer Dokploy resources, manage databases or containers, configure domains/servers/backups, inspect logs, or automate Dokploy API tasks.
  Keywords: dokploy, paas, deploy, docker, traefik, application, compose, postgres, mysql, mariadb, mongo, redis, libsql, server, backup, domain, certificate, registry, notification, api, self-hosted, patch, license, sso, oidc, forward-auth, enterprise, rbac, logs.
compatibility: |
  Requires Python 3.10+ with httpx package installed.
  Setup: pip install httpx (in a virtual env recommended).
  The venv at <SKILL_DIR>/.venv/ already has it installed.
allowed-tools: Bash(python:*)
---

# Dokploy Remote Management Skill

Manage a remote Dokploy instance via its REST API (539 endpoints, 49 domains).

The endpoint registry is generated from a live Dokploy server's OpenAPI document (API v0.29.x,
fetched via `settings getOpenApiDocument`). Older self-hosted instances may not yet expose the newest
endpoints; they return a `404 NOT_FOUND` envelope while the registered endpoint stays valid for newer
servers. To regenerate the registry for a different server version, fetch that server's OpenAPI
document and rebuild `ENDPOINTS` from it.

## Prerequisites

**IMPORTANT:** Before running any command, check if the venv exists. If it does not, create it and install dependencies:

```bash
if [ ! -d "<SKILL_DIR>/.venv" ]; then
  cd <SKILL_DIR>
  python3 -m venv .venv
  .venv/bin/pip install httpx
fi

PYTHON=<SKILL_DIR>/.venv/bin/python3
```

**Environment variables (REQUIRED):**

```bash
export DOKPLOY_URL="https://your-dokploy-instance.com"
export DOKPLOY_API_KEY="your-api-key-here"
```

## Script Location

```
<SKILL_DIR>/scripts/dokploy.py
```

## Usage Pattern

```bash
$PYTHON scripts/dokploy.py <domain> <action> [--param-name value ...]
```

## Quick Reference

| Domain | Actions | Description |
|--------|---------|-------------|
| `project` | `all`, `create`, `one`, `update`, `remove`, `duplicate`, `search`, `allForPermissions`, `homeStats` | Manage projects (9 actions) |
| `application` | `one`, `create`, `deploy`, `redeploy`, `start`, `stop`, `update`, `delete`, `search`, `clearDeployments`, `readLogs`, `dropDeployment`, ... | Manage applications (31 actions, incl. zip-upload deploy + log streaming) |
| `compose` | `one`, `create`, `deploy`, `start`, `stop`, `update`, `delete`, `search`, `readLogs`, `saveEnvironment`, ... | Docker Compose services (31 actions) |
| `postgres` | `one`, `create`, `deploy`, `start`, `stop`, `update`, `remove`, `search`, `readLogs`, `changePassword`, ... | PostgreSQL databases (16 actions) |
| `mysql` | `one`, `create`, `deploy`, `start`, `stop`, `update`, `remove`, `search`, `readLogs`, `changePassword`, ... | MySQL databases (16 actions) |
| `mariadb` | `one`, `create`, `deploy`, `start`, `stop`, `update`, `remove`, `search`, `readLogs`, `changePassword`, ... | MariaDB databases (16 actions) |
| `mongo` | `one`, `create`, `deploy`, `start`, `stop`, `update`, `remove`, `search`, `readLogs`, `changePassword`, ... | MongoDB databases (16 actions) |
| `redis` | `one`, `create`, `deploy`, `start`, `stop`, `update`, `remove`, `search`, `readLogs`, `changePassword`, ... | Redis instances (16 actions) |
| `libsql` | `one`, `create`, `deploy`, `start`, `stop`, `update`, `remove`, `readLogs`, `saveEnvironment`, ... | libSQL/SQLite databases (14 actions) |
| `patch` | `create`, `one`, `byEntityId`, `update`, `delete`, `toggleEnabled`, `ensureRepo`, `cleanPatchRepos`, ... | File patches (12 actions) |
| `docker` | `getContainers`, `getConfig`, `restartContainer`, `startContainer`, `stopContainer`, `killContainer`, `removeContainer`, `uploadFileToContainer`, ... | Docker operations (12 actions, incl. file upload) |
| `domain` | `create`, `update`, `delete`, `one`, `byApplicationId`, `validateDomain`, `generateDomain`, ... | Domain management (9 actions) |
| `forward-auth` | `enable`, `disable`, `status`, `setAuthDomain`, `getAuthDomain`, `removeAuthDomain`, `deployOnServer`, `removeOnServer`, `listProviders`, `serverStatus` | Protect domains with SSO/OIDC via a Traefik forward-auth proxy — enterprise-gated (10 actions) |
| `server` | `all`, `one`, `create`, `update`, `remove`, `setup`, ... | Server management (17 actions) |
| `settings` | `getDokployVersion`, `getIp`, `health`, `cleanAll`, `getWebServerSettings`, `updateServerIp`, `getDockerDiskUsage`, ... | System settings (53 actions) |
| `backup` | `create`, `update`, `remove`, `one`, `manualBackup*`, ... | Backup management (12 actions) |
| `notification` | `all`, `create*`, `update*`, `test*`, `remove` (Slack, Telegram, Discord, Email, Resend, Gotify, Ntfy, Custom, Lark, Teams, Pushover, Mattermost) | Notifications — 12 providers (41 actions) |
| `user` | `all`, `get`, `one`, `update`, `remove`, `createApiKey`, `assignPermissions`, `getPermissions`, `sendInvitation`, `haveRootAccess`, ... | User management (23 actions) |
| `organization` | `all`, `create`, `update`, `delete`, `one`, `active`, `setDefault`, `inviteMember`, `updateMemberRole`, `allInvitations`, `removeInvitation` | Organizations (11 actions) |
| `deployment` | `all`, `allByCompose`, `allByServer`, `allByType`, `allCentralized`, `queueList`, `readLogs`, `killProcess`, `removeDeployment` | Deployments (9 actions) |
| `destination` | `all`, `create`, `update`, `remove`, `one`, `testConnection` | Backup destinations (6 actions) |
| `certificates` | `all`, `create`, `update`, `one`, `remove` | SSL certificates (5 actions) |
| `registry` | `all`, `create`, `update`, `remove`, `one`, `testRegistry`, `testRegistryById` | Docker registries (7 actions) |
| `ssh-key` | `all`, `create`, `update`, `remove`, `one`, `generate`, `allForApps` | SSH keys (7 actions) |
| `github` | `githubProviders`, `one`, `getGithubBranches`, ... | GitHub integration (6 actions) |
| `gitlab` | `gitlabProviders`, `one`, `create`, `update`, ... | GitLab integration (7 actions) |
| `gitea` | `giteaProviders`, `one`, `create`, `update`, ... | Gitea integration (8 actions) |
| `bitbucket` | `bitbucketProviders`, `one`, `create`, `update`, ... | Bitbucket integration (7 actions) |
| `git-provider` | `getAll`, `remove`, `allForPermissions`, `toggleShare` | Git providers (4 actions) |
| `environment` | `byProjectId`, `create`, `update`, `remove`, `one`, `duplicate`, `search` | Environments (7 actions) |
| `schedule` | `create`, `update`, `delete`, `list`, `one`, `runManually` | Scheduled tasks (6 actions) |
| `security` | `create`, `update`, `delete`, `one` | Basic auth security (4 actions) |
| `port` | `create`, `update`, `delete`, `one` | Port mappings (4 actions) |
| `mounts` | `create`, `update`, `remove`, `one`, `allNamedByApplicationId`, `listByServiceId` | Volume mounts (6 actions) |
| `redirects` | `create`, `update`, `delete`, `one` | URL redirects (4 actions) |
| `rollback` | `delete`, `rollback` | Rollback management (2 actions) |
| `cluster` | `addManager`, `addWorker`, `getNodes`, `removeWorker` | Swarm cluster (4 actions) |
| `swarm` | `getNodeApps`, `getNodeInfo`, `getNodes`, `getContainerStats` | Swarm info (4 actions) |
| `ai` | `create`, `delete`, `deploy`, `get`, `getAll`, `update`, `suggest`, `analyzeLogs`, `testConnection`, ... | AI features (12 actions) |
| `tag` | `all`, `one`, `create`, `update`, `remove`, `assignToProject`, `removeFromProject`, `bulkAssign` | Project tags (8 actions) |
| `custom-role` | `all`, `create`, `update`, `remove`, `getStatements`, `membersByRole` | Custom RBAC roles (6 actions) |
| `stripe` | `canCreateMoreServers`, `createCheckoutSession`, `createCustomerPortalSession`, `getCurrentPlan`, `getInvoices`, `getProducts`, `upgradeSubscription`, `updateInvoiceNotifications` | Billing (8 actions) |
| `license-key` | `validate`, `activate`, `deactivate`, `haveValidLicenseKey`, `getEnterpriseSettings`, `updateEnterpriseSettings` | Enterprise license keys (6 actions) |
| `sso` | `register`, `update`, `one`, `listProviders`, `deleteProvider`, `enforceSSO`, `getTrustedOrigins`, `addTrustedOrigin`, `showSignInWithSSO`, ... | SSO/OIDC providers — enterprise-gated (11 actions) |
| `whitelabeling` | `get`, `getPublic`, `update`, `reset` | White-label branding (4 actions) |
| `audit-log` | `all` | Audit log — admin-gated (1 action) |
| `admin` | `setupMonitoring` | Admin (1 action) |
| `volume-backups` | `create`, `delete`, `list`, `one`, `runManually`, `update` | Volume backups (6 actions) |
| `preview-deployment` | `all`, `delete`, `one`, `redeploy` | Preview deployments (4 actions) |

## Common Commands

### List all projects
```bash
$PYTHON scripts/dokploy.py project all
```

### Get Dokploy version
```bash
$PYTHON scripts/dokploy.py settings getDokployVersion
```

### Get system health
```bash
$PYTHON scripts/dokploy.py settings health
```

### Get server IP
```bash
$PYTHON scripts/dokploy.py settings getIp
```

### List Docker containers
```bash
$PYTHON scripts/dokploy.py docker getContainers
```

### Get a specific project
```bash
$PYTHON scripts/dokploy.py project one --project-id "abc123"
```

### Create a project
```bash
$PYTHON scripts/dokploy.py project create --name "My Project" --description "Description"
```

### Create an application
```bash
$PYTHON scripts/dokploy.py application create --name "my-app" --environment-id "env123"
```

### Deploy an application
```bash
$PYTHON scripts/dokploy.py application deploy --application-id "app123"
```

### Stop an application
```bash
$PYTHON scripts/dokploy.py application stop --application-id "app123"
```

### Create a PostgreSQL database
```bash
$PYTHON scripts/dokploy.py postgres create \
  --name "my-db" \
  --app-name "my-db-app" \
  --database-name "mydb" \
  --database-user "admin" \
  --database-password "secret" \
  --environment-id "env123"
```

### List all servers
```bash
$PYTHON scripts/dokploy.py server all
```

### List all users
```bash
$PYTHON scripts/dokploy.py user all
```

### Get current user
```bash
$PYTHON scripts/dokploy.py user get
```

### Create a notification (Discord)
```bash
$PYTHON scripts/dokploy.py notification createDiscord \
  --name "alerts" \
  --webhook-url "https://discord.com/api/webhooks/..." \
  --app-build-error true \
  --app-deploy true \
  --database-backup true \
  --dokploy-restart true \
  --docker-cleanup true \
  --server-threshold true \
  --decoration true
```

### Search projects/applications/compose
```bash
$PYTHON scripts/dokploy.py project search --q "my-project" --limit 10
$PYTHON scripts/dokploy.py application search --q "api" --limit 10
$PYTHON scripts/dokploy.py compose search --q "redis" --limit 10
```

### Manage file patches
```bash
# List patches for an application
$PYTHON scripts/dokploy.py patch byEntityId --id "APP_ID" --type application

# Create a patch
$PYTHON scripts/dokploy.py patch create --file-path "/app/config.json" \
  --content '{"key": "value"}' --type update --application-id "APP_ID"
```

### List all deployments (centralized)
```bash
$PYTHON scripts/dokploy.py deployment allCentralized
```

### Create a custom webhook notification
```bash
$PYTHON scripts/dokploy.py notification createCustom \
  --name "my-webhook" \
  --endpoint "https://example.com/webhook" \
  --app-build-error true --app-deploy true \
  --database-backup true --dokploy-restart true \
  --docker-cleanup true --server-threshold true
```

### File-upload endpoints (multipart/form-data)
A `file`-type flag takes a local path and is streamed as `multipart/form-data`.

```bash
# Deploy an application from a local zip (the app must use the `drop` source type)
$PYTHON scripts/dokploy.py application dropDeployment \
  --application-id "app123" \
  --zip "/path/to/build.zip" \
  --drop-build-path "/"

# Upload a file into a running container
$PYTHON scripts/dokploy.py docker uploadFileToContainer \
  --container-id "abc123" \
  --file "/path/to/local.conf" \
  --destination-path "/etc/app/local.conf"
```

### Stream service logs
```bash
$PYTHON scripts/dokploy.py application readLogs --application-id "app123" --tail 200
$PYTHON scripts/dokploy.py postgres readLogs --postgres-id "pg123" --tail 100
```

### Project tags
```bash
$PYTHON scripts/dokploy.py tag create --name "production" --color "#22c55e"
$PYTHON scripts/dokploy.py tag assignToProject --tag-id "TAG_ID" --project-id "PROJECT_ID"
```

### Enterprise license keys
```bash
# Check whether a valid license is active
$PYTHON scripts/dokploy.py license-key haveValidLicenseKey

# Read enterprise settings
$PYTHON scripts/dokploy.py license-key getEnterpriseSettings

# Activate a license key (camelCase params become kebab-case flags)
$PYTHON scripts/dokploy.py license-key activate --license-key "XXXX-XXXX"

# Validate the currently-stored license (takes no params)
$PYTHON scripts/dokploy.py license-key validate

# Toggle enterprise features
$PYTHON scripts/dokploy.py license-key updateEnterpriseSettings --enable-enterprise-features true
```

### SSO / OIDC providers (enterprise-gated)
These return `403 "Valid enterprise license required"` without an active enterprise license.
```bash
# List configured SSO providers
$PYTHON scripts/dokploy.py sso listProviders

# Whether the sign-in-with-SSO button should show
$PYTHON scripts/dokploy.py sso showSignInWithSSO

# Register a new OIDC provider (oidc-config is a JSON object)
$PYTHON scripts/dokploy.py sso register \
  --provider-id "okta" --issuer "https://example.okta.com" \
  --domains '["example.com"]' \
  --oidc-config '{"clientId":"...","clientSecret":"...","authorizationEndpoint":"...","tokenEndpoint":"..."}'
```

### Raw output (no wrapper)
```bash
$PYTHON scripts/dokploy.py --raw project all
```

### Custom timeout
```bash
$PYTHON scripts/dokploy.py --timeout 120 compose deploy --compose-id "comp123"
```

## CLI Flags

### Global flags
| Flag | Description | Default |
|------|-------------|---------|
| `--raw` | Output raw API response (no `{"success": true, "data": ...}` wrapper) | false |
| `--timeout` | Request timeout in seconds | 60 |

### Parameter naming
CLI flags use kebab-case, converted from the API's camelCase:
- `applicationId` → `--application-id`
- `environmentId` → `--environment-id`
- `composeId` → `--compose-id`
- `serverId` → `--server-id`

### Parameter types
| API Type | CLI Input | Example |
|----------|-----------|---------|
| `string` | Plain text | `--name "my-app"` |
| `number` / `integer` | Numeric string | `--port 3000` |
| `boolean` | `true`/`false`, `yes`/`no`, `1`/`0`, `on`/`off` | `--enabled true` |
| `array` | JSON array string | `--watch-paths '["src/", "lib/"]'` |
| `object` | JSON object string | `--metrics-config '{"cpu": true}'` |
| `file` | Local file path (uploaded as multipart/form-data) | `--zip /path/to/build.zip` |

## Common Workflows

### Full project setup
```bash
# 1. Create project
$PYTHON scripts/dokploy.py project create --name "production"

# 2. Get environments for the project
$PYTHON scripts/dokploy.py environment byProjectId --project-id "PROJECT_ID"

# 3. Create application in environment
$PYTHON scripts/dokploy.py application create --name "api" --environment-id "ENV_ID"

# 4. Configure and deploy
$PYTHON scripts/dokploy.py application deploy --application-id "APP_ID"
```

### Database management
```bash
# Create a PostgreSQL database
$PYTHON scripts/dokploy.py postgres create --name "db" --app-name "db-app" \
  --database-name "mydb" --database-user "user" --database-password "pass" \
  --environment-id "ENV_ID"

# Start it
$PYTHON scripts/dokploy.py postgres start --postgres-id "PG_ID"

# Create a backup
$PYTHON scripts/dokploy.py backup create --schedule "0 2 * * *" --prefix "daily" \
  --destination-id "DEST_ID" --database "mydb" --database-type postgres \
  --postgres-id "PG_ID"
```

### Server monitoring
```bash
# Check system health
$PYTHON scripts/dokploy.py settings health

# Get version
$PYTHON scripts/dokploy.py settings getDokployVersion

# List containers
$PYTHON scripts/dokploy.py docker getContainers

# Clean unused images
$PYTHON scripts/dokploy.py settings cleanUnusedImages
```

## Output Format

**Success:**
```json
{
  "success": true,
  "data": { ... }
}
```

**Error (stderr):**
```json
{
  "success": false,
  "error": "Error message",
  "status_code": 401,
  "detail": { ... }
}
```

**Exit codes:**
| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | API error or runtime error |
| `2` | Usage error (missing domain/action) |

## Technical Notes

- All 539 Dokploy API endpoints are supported (49 domains), generated from a live server's OpenAPI document (API v0.29.x)
- API uses tRPC-over-REST: `GET /api/<router>.<procedure>` for queries, `POST` for mutations
- Two endpoints accept `multipart/form-data` file uploads: `application dropDeployment` (zip) and `docker uploadFileToContainer` (file)
- Authentication via `x-api-key` header
- Automatic retry on 5xx errors (up to 2 retries with backoff)
- Default timeout: 60 seconds (configurable via `--timeout`)
- Single dependency: `httpx`
- Boolean parameters accept: `true`/`false`, `yes`/`no`, `1`/`0`, `on`/`off` (case-insensitive). Invalid values are rejected with an error.
- Array/object parameters accept JSON strings
- `file` parameters take a local path and are streamed as `multipart/form-data`
- Error messages redact sensitive data (API keys, tokens) from URLs and response details
