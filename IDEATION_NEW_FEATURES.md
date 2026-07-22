# Feature Ideas Analysis Report

## Executive Summary

Service Manager já oferece administração de usuários pela interface, filtros e ordenação persistentes na URL, exportação segura de inventário, ações em massa para status, cadastro e exclusão, visualização/exportação da auditoria e matriz de cobertura entre serviços.

Restam três propostas novas e quatro extensões dos fluxos entregues. FEAT-003-R melhora a identificação dos arquivos exportados. FEAT-004-R conclui campos customizados e confirmação digitada nas ações em massa. FEAT-005-R completa filtros por IP, reautenticação e hashes no CSV de auditoria. FEAT-006-R adiciona o filtro de ausência de cadastro nos serviços selecionados. FEAT-007 trata rotação de credenciais, FEAT-008 webhooks de segurança e FEAT-009 permissões por serviço.

## Application Overview

**Purpose:** Securely store and manage service-account credentials, registration state, status, and service-specific fields.

**Target Users:** [INFERENCE] Small internal operations or administrative teams that share responsibility for accounts across multiple external services.

**Core Workflows:**
- Autenticar e reautenticar para ações sensíveis; gerenciar login e senha do usuário atual.
- Administrar usuários, papéis e estado de acesso pela interface.
- Criar ou selecionar serviços; adicionar, editar, filtrar, ordenar, revelar, copiar e excluir contas.
- Compartilhar visões persistentes por URL e alterar status/cadastro ou excluir contas em massa.
- Importar contas e exportar inventário sem senhas nem valores de campos adicionais.
- Consultar a auditoria encadeada e a cobertura das contas entre serviços.

**Current Capabilities:**
- Aplicação Flask/Jinja em PT-BR com JavaScript simples e CSS responsivo.
- SQLite com WAL, validação estrita de schema e auditoria append-only encadeada por HMAC.
- Criptografia AES-GCM para senhas e valores de campos adicionais.
- Papéis globais `admin` e `operador`, sessões seguras, CSRF, Argon2 e rate limiting.
- Administração de usuários, exportação CSV/XLSX segura, ações em massa de status/cadastro/exclusão e visualizador de auditoria.
- Estado e cadastro por serviço, filtros persistentes e matriz de cobertura entre serviços.
- Backups criptografados, restauração, health checks e scripts de migração.

## Feature Ideas

### Small Complexity (1-3 days)

#### FEAT-003-R: Service-Named Export Metadata

**Category:** integration

**Remaining Scope:**
- Usar o nome seguro do serviço, não apenas seu ID, no nome ou metadados dos arquivos CSV/XLSX.
- Incluir timestamp completo e inequívoco da exportação, mantendo células protegidas contra formula injection.
- Definir limite explícito ou geração incremental para evitar crescimento de memória em inventários grandes; hoje linhas e XLSX são materializados integralmente.

**Affected Areas:**
- `service_manager/routes.py`
- `tests/test_feature_pack.py`

---

### Medium Complexity (1-2 weeks)

#### FEAT-004-R: Complete Bulk Field Actions and Typed Deletion Confirmation

**Category:** productivity

**Remaining Scope:**
- Aplicar um campo customizado e seu valor a todas as contas selecionadas usando o caminho multi-conta já existente.
- Exigir confirmação digitada com a quantidade selecionada antes da exclusão em massa, substituindo a confirmação simples atual.
- Manter seleção consistente após filtros e ordenação e preservar o limite de 200 contas.

**Affected Areas:**
- `service_manager/routes.py`
- `templates/index.html`
- `static/js/app.js`
- `tests/test_feature_pack.py`

---

#### FEAT-005-R: Complete Audit Investigation Controls

**Category:** data

**Remaining Scope:**
- Filtrar eventos por IP de origem.
- Exigir reautenticação recente para abrir e exportar a auditoria.
- Incluir os hashes do encadeamento no CSV filtrado, mantendo a proteção contra formula injection.

**Affected Areas:**
- `service_manager/routes.py`
- `templates/audit.html`
- `tests/test_feature_pack.py`

---

#### FEAT-006-R: Selected-Service Coverage Gap Filter

**Category:** data

**Remaining Scope:**
- Permitir selecionar serviços e filtrar contas sem cadastro em pelo menos um dos serviços escolhidos.
- Preservar o comportamento atual dos filtros “nenhum cadastro” e “ativa em mais de um serviço”.

**Affected Areas:**
- `templates/coverage.html`
- `static/js/app.js`
- `tests/test_feature_pack.py`

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
- Audit viewing already provides administrators evidence for rotation changes.
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
- Reliable delivery creates a new subsystem despite the existing audit investigation view.
- Best after defining the rotation and alert ownership model.

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
| Small extension | 1 |
| Medium extensions | 3 |
| Large | 2 |
| Epic | 1 |

| Category | Count |
|----------|-------|
| Integration | 2 |
| Productivity | 1 |
| Data | 2 |
| Workflow | 1 |
| Collaboration | 1 |

**Remaining Items:** 7 — FEAT-003-R, FEAT-004-R, FEAT-005-R, FEAT-006-R, FEAT-007, FEAT-008 and FEAT-009.
