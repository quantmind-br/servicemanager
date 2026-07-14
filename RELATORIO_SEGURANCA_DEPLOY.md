# Relatório de segurança para deploy remoto

**Data da análise:** 12/07/2026  
**Escopo:** `app.py`, `templates/index.html`, ambiente virtual e metadados de `credentials.db`.  
**Objetivo:** definir o trabalho necessário antes de expor o gerenciador de credenciais em um servidor remoto com login e senha.

> **Decisão de go/no-go:** **NÃO publicar a aplicação nem o banco atual.** Há segredos em texto puro, não existe autenticação/autorização/CSRF e o banco atual contém **116** contas, além de uma tabela de backup legado (`credentials_backup`) com outros **116** registros. O arquivo `credentials.db` está com permissão `0644`.

## Modelo de ameaça resumido

A aplicação guarda credenciais de terceiros e campos livres que podem conter outros segredos. Um atacante externo, uma sessão roubada, uma extensão de navegador maliciosa, um XSS, um usuário local do servidor ou o vazamento de um backup pode revelar ou alterar essas credenciais. O deploy deve proteger:

- acesso à interface e a cada operação sensível;
- segredos em trânsito, no banco, em cópias de segurança e no navegador;
- integridade contra CSRF, edição indevida e upload malicioso;
- operação do servidor, logs, dependências e recuperação após incidente.

## Achados e bloqueadores

### B1 — Banco atual e cópia legada contêm segredos; não podem ser publicados

**Evidência:** `credentials.db` possui 73.728 bytes, 116 linhas em `accounts` e 116 linhas em `credentials_backup`. A tabela de backup surgiu da migração em `init_db()` (`ALTER TABLE credentials RENAME TO credentials_backup`). `accounts.password` e `credentials_backup.password` preservam senhas de terceiros em texto puro.

**Impacto:** incluir o banco na imagem, no repositório, no volume exposto, em artefatos de CI ou em backups não cifrados equivale a divulgar as credenciais. O backup legado duplica a superfície de vazamento.

**Correção obrigatória antes do deploy:**

1. **Não enviar `credentials.db`, `credentials_backup`, dumps, CSVs/XLSXs de importação ou backups ao servidor remoto.** Não incluí-los em Git, imagem Docker, contexto de build, artefatos de CI ou anexos de suporte.
2. Criar um banco novo no servidor e migrar somente por um procedimento controlado, após criptografar os segredos descritos em B3. Se a migração do acervo atual for necessária, executá-la em ambiente confiável e destruir cópias temporárias.
3. Remover a tabela `credentials_backup` **somente depois** de uma migração validada e de um backup cifrado que atenda à retenção definida. Não manter duas cópias de senhas em texto puro.
4. Criar `.gitignore` e `.dockerignore` para `credentials.db`, `*.db`, `*.sqlite*`, `*.bak`, `*.csv`, `*.xlsx`, `.env` e diretórios de backup. Como o diretório analisado não é um repositório Git e não há arquivo de configuração de deploy/dependências, configurar essas exclusões antes de iniciar versionamento ou containerização.

### B2 — Não há autenticação, autorização, sessão ou proteção CSRF

**Evidência:** todas as rotas — inclusive `/`, `/add`, `/update/<id>`, `/delete/<id>`, `/import`, `/service/*` e `/field/*` — são públicas no código. `app.py` não define `SECRET_KEY`, login, usuário, papel, sessão, proteção CSRF ou controle de acesso. Os formulários POST não carregam token CSRF.

**Impacto:** qualquer pessoa que alcance o serviço pode ler todas as contas e alterar, excluir ou importar dados. Depois de adicionar login baseado em cookie, a ausência de CSRF permitiria que sites externos disparassem operações autenticadas no navegador da vítima.

**Correção obrigatória antes do deploy:**

1. Implementar autenticação de usuários da aplicação. Criar tabela de usuários separada da tabela de contas gerenciadas, com identificador único, status, data de criação e trilha de auditoria.
2. Proteger todas as rotas por padrão; liberar explicitamente somente a tela de login e os recursos estritamente necessários. Usar autorização por papel, no mínimo `admin` e `operador`; aplicar a verificação no servidor em cada operação, não no template.
3. Usar sessão de servidor ou cookie de sessão assinado com `SECRET_KEY` criptograficamente aleatória, fornecida por secret manager/variável de ambiente protegida — nunca no repositório ou na imagem. Configurar cookies `Secure`, `HttpOnly`, `SameSite=Lax` (ou `Strict` se o fluxo permitir), expiração curta, rotação de sessão após login e logout que invalide a sessão.
4. Aplicar CSRF a todo método que altera estado, inclusive importação e operações de serviço/campo. Validar `Origin`/`Referer` como defesa complementar.
5. Implementar limitação de tentativas de login por conta e IP, mensagens de erro sem enumeração de usuários, hash de senha de login com Argon2id (preferível) ou scrypt e fluxo seguro de criação/reset de senha. Registrar, sem segredos, falhas de login, logins, logout, alterações e revelações de credenciais.

### B3 — Senha de login e credenciais gerenciadas exigem tratamentos criptográficos distintos

**Evidência:** o campo `accounts.password` armazena senhas de contas gerenciadas em texto puro e é preenchido por `/add`, `/import` e `/update`. A estrutura atual não contém usuários de login nem hash de senha.

**Impacto:** uma cópia do banco revela imediatamente as credenciais externas. Aplicar hash a essas credenciais impediria a função do produto, que precisa revelá-las/copiá-las; mantê-las em texto puro não é aceitável.

**Correção obrigatória antes do deploy:**

- **Senha de login do usuário da aplicação:** guardar **somente hash não reversível**, usando **Argon2id** (recomendado) ou **scrypt**, com sal único e parâmetros de custo atuais. Nunca criptografar de forma reversível, nunca guardar texto puro e nunca reutilizar essa senha como chave de criptografia.
- **Credenciais gerenciadas pela aplicação:** guardar com **criptografia autenticada em repouso**, por exemplo AES-256-GCM ou ChaCha20-Poly1305. Cada registro deve conter `ciphertext`, `nonce` único e identificador de versão/chave; a autenticação deve cobrir também o contexto do registro (por exemplo, id da conta e nome do campo) como AAD. Criptografar `accounts.password` e **todos** os valores de `field_values` — não há mais classificação secreta/não secreta: todo campo adicional é cifrado em repouso com AAD `account:{account_id}:field:{field_id}`.
- **Chave de dados:** manter fora de SQLite, do repositório e da imagem. Usar secret manager/KMS do provedor ou, no mínimo, arquivo de segredo com permissões restritas, injetado em runtime. Separar chave de desenvolvimento, homologação e produção; versionar chaves para rotação e definir procedimento de restauração/rotação. A perda da chave torna os dados irrecuperáveis; a divulgação da chave junto com o DB invalida a criptografia.
- Implementar migração transacional, com backup cifrado controlado, que transforme o conteúdo atual **de texto puro para ciphertext criptografado** antes de qualquer deploy. Depois, verificar que nenhuma coluna/tabela legada conserva texto puro.

### B4 — A página entrega todos os segredos ao navegador

**Evidência:** a consulta do índice seleciona `a.password`; o template coloca cada senha em `data-pw` (linha 279), em input hidden (linha 289) e em argumentos JavaScript de `openEdit` (linha 301). Além disso, a consulta de `field_values` e o template renderizam todos os valores de campos no DOM, incluindo o texto copiável e argumentos JavaScript de edição (linhas 316–319). O navegador recebe todas as senhas e todos os valores de campo em uma única resposta, apesar de a interface mascarar apenas a senha visualmente.

**Impacto:** mascaramento visual não protege. Qualquer usuário autenticado, extensão, XSS, cache local ou inspeção de DOM pode ler todas as credenciais e campos secretos, inclusive os que não solicitou revelar. O valor em input hidden também volta ao servidor em uma simples alteração de status.

**Correção obrigatória antes do deploy:**

1. A senha principal da conta (`accounts.password`) nunca é selecionada, renderizada, serializada em JavaScript ou colocada em atributo HTML por padrão; só é entregue via endpoint de reveal autenticado. Os valores de `field_values` permanecem cifrados no SQLite, mas são descriptografados no servidor e enviados visíveis apenas na listagem autenticada com `Cache-Control: no-store, private` — não há classificação nem reveal separado para campos adicionais.
2. Criar endpoint `POST` autenticado para revelar/copiar a **senha principal** por vez. A ação exige sessão autenticada + CSRF + rate limit (20 revelações / 10 min por usuário); não exige reautenticação recente por senha. Retornar somente o valor solicitado com expiração curta (`expires_in` ≤ 30 s).
3. Registrar em auditoria quem revelou qual senha e quando, sem registrar o valor; aplicar rate limit e expiração curta ao resultado. Não persistir o valor em `localStorage`, logs ou histórico.
4. Para edição da conta, pedir explicitamente uma nova senha no modal; não pré-preencher a senha. Senha vazia preserva a atual. Campos adicionais são editados com input de texto visível e re-cifrados no servidor.
5. Responder páginas e endpoints de segredo com `Cache-Control: no-store, private` e `Pragma: no-cache` quando aplicável. Definir CSP que proíba JavaScript inline; mover handlers e scripts inline para arquivos estáticos com nonce/hash estrito. CSP reduz impacto de XSS, mas não substitui escape, autorização nem a remoção de segredos da página.

### B5 — Arquivo SQLite permissivo e sem proteção operacional de armazenamento

**Evidência:** `credentials.db` está em `0644` (`-rw-r--r--`), ou seja, legível por qualquer usuário local. Ele fica ao lado de `app.py`; não há configuração de volume, usuário de serviço ou backup no projeto.

**Impacto:** qualquer processo/conta local que consiga ler o diretório pode copiar o banco. Criptografia de aplicação (B3) reduz o efeito dessa cópia, mas permissões incorretas e backups sem proteção continuam sendo falhas graves.

**Correção obrigatória antes do deploy:**

- Executar o serviço com usuário Linux dedicado, sem shell e sem privilégios administrativos. Diretório de dados: `0700`; banco, WAL/SHM e backups: `0600`, pertencentes exclusivamente a esse usuário. Verificar permissões após cada deploy/restauração.
- Colocar o volume de dados **fora do web root e fora da imagem**; montar somente em runtime. Não expor diretórios, snapshots ou endpoints de download de banco.
- Fazer backups cifrados com chave separada, acesso mínimo, retenção definida e inventário de cópias. Executar e registrar teste periódico de restauração em ambiente isolado. Proteger também os arquivos `-wal` e `-shm` de SQLite.
- Preferir PostgreSQL gerenciado com criptografia, backups e controles de acesso administrados se houver múltiplos usuários, alta disponibilidade ou necessidade de auditoria centralizada. SQLite pode permanecer para uso pequeno e de usuário único se o volume, a exclusão mútua, os backups e as permissões forem controlados.

### B6 — Upload ilimitado e processamento de XLSX não confiável

**Evidência:** `/import` lê o arquivo inteiro com `f.read()` e o encaminha a `openpyxl.load_workbook()` para qualquer nome que termine em `.xlsx`; CSV e outras extensões caem no leitor CSV. Não há `MAX_CONTENT_LENGTH`, limite de linhas/células/tamanho de texto, validação de tipo real, timeout ou limite no proxy.

**Impacto:** upload grande, XLSX compactado malicioso (zip bomb) ou planilha de alta complexidade pode esgotar memória, CPU ou espaço e derrubar o serviço. Extensão e `accept` do navegador não são controles de segurança.

**Correção obrigatória antes do deploy:**

1. Definir `MAX_CONTENT_LENGTH` na aplicação e limite de corpo no reverse proxy; escolher valor baseado no caso de uso e documentá-lo (por exemplo, começar com 5 MiB e ajustar após testes).
2. Aceitar exclusivamente CSV UTF-8 e XLSX; validar extensão, `Content-Type` como sinal auxiliar e assinatura/formato do arquivo no servidor. Rejeitar qualquer tipo não permitido antes do parse.
3. Processar em streaming quando possível e impor limites explícitos: número de linhas, colunas, células, comprimento por campo e total de registros. Para XLSX, inspecionar o ZIP com limite de membros e tamanho descompactado antes de `openpyxl`; usar leitura `read_only=True` e recusar arquivos além dos limites.
4. Configurar no proxy limites de body, timeout de request/upstream e taxa de upload; registrar apenas metadados (tamanho, tipo, resultado), nunca conteúdo ou senhas importadas.

## Melhorias importantes antes de abrir acesso externo

| Prioridade | Medida | Evidência/risco atual |
|---|---|---|
| Alta | TLS obrigatório no reverse proxy, redirecionamento HTTP→HTTPS e HSTS após validar o domínio | A resposta local não possui `Strict-Transport-Security`; não existe configuração de proxy/TLS no projeto. |
| Alta | Adicionar cabeçalhos: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` ou `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, CSP restritiva e `Permissions-Policy` mínima | A resposta `GET /` não contém CSP, HSTS, `X-Frame-Options` nem `Cache-Control`. |
| Alta | Executar Flask atrás de Gunicorn/uWSGI e Nginx/Caddy; nunca usar o servidor de desenvolvimento | `app.py` chama `app.run(debug=True, ...)` quando executado diretamente. Mesmo limitado a loopback hoje, `debug=True` não pode chegar a produção. |
| Alta | Validar entrada no servidor: comprimento, formato de e-mail, valores de status permitidos e relação conta/serviço/campo | As rotas usam ids e valores de formulário diretamente; consultas parametrizadas evitam SQL injection, mas não garantem integridade/autorização. |
| Alta | Implementar auditoria imutável de operações sensíveis e alertas de anomalia | Não há trilha de auditoria. A auditoria deve excluir senha, chaves e conteúdo de campos secretos. |
| Média | Tratar erros com páginas genéricas, logs estruturados e monitoramento | `/import` captura `Exception` e descarta o detalhe; não há logging, health check nem configuração de observabilidade. |
| Média | Fixar e acompanhar dependências | Não há `requirements.txt`, `pyproject.toml` ou lockfile. O ambiente observado possui Flask 3.1.3 e openpyxl 3.1.5; `pip check` não encontrou requisitos quebrados, mas `pip-audit` não está instalado, portanto esta análise não confirmou CVEs. |
| Média | Isolar processo e rede | Executar como usuário não privilegiado, restringir egress/ingress por firewall, expor somente o proxy e manter SSH administrativo com chaves/MFA. |
| Média | Definir política de segurança de sessão | Timeout absoluto e por inatividade, logout, rotação da sessão, proteção contra fixation e revogação em troca de senha/papel. |

## Arquitetura mínima recomendada

```text
Navegador
  └─ HTTPS (TLS) + rate limits
       └─ Nginx/Caddy (body/timeouts, headers, apenas 443 público)
            └─ Gunicorn executado como usuário dedicado sem privilégios
                 └─ Flask: autenticação + autorização + CSRF + auditoria
                      ├─ Secret manager/KMS: chave de dados e SECRET_KEY
                      └─ Volume privado 0700: SQLite cifrado na aplicação
                           └─ backups cifrados, acesso separado e restauração testada
```

Para um único operador, o login usa nome de usuário e senha Argon2id; a autenticação por TOTP foi removida intencionalmente em 14/07/2026. O risco residual é maior sem MFA: roubo de senha ou força bruta bem-sucedido dá acesso direto. Mitigações: rate limit por IP/usuário, senha forte obrigatória na troca, Argon2id com rehash oportunista, rate limit dedicado nas revelações de senha (sem reautenticação por senha, que permanece exigida apenas para operações administrativas de usuários), revogação de sessão por `session_version` e auditoria append-only com cadeia HMAC. Reavaliar MFA se ameaça evoluir.

## Sequência de implementação e critérios de liberação

1. **Conter dados existentes:** retirar banco/exports/backups de quaisquer canais de publicação; criar exclusões de VCS/build; corrigir permissões locais para diretório `0700` e banco/backup `0600` enquanto os dados existirem.
2. **Reestruturar dados:** separar `users` de `accounts`; implementar hash Argon2id/scrypt para login e criptografia autenticada para credenciais gerenciadas; migrar e verificar o acervo sem texto puro residual.
3. **Controlar acesso:** login por nome de usuário e senha Argon2id, sessão segura, papéis, CSRF, reautenticação por senha para reveal/copy e auditoria.
4. **Reduzir exposição do cliente:** remover todos os segredos — senhas e valores secretos de campos — de `GET /`, DOM, atributos, inputs hidden e JavaScript; criar reveal pontual autenticado; aplicar `no-store` e CSP sem inline script.
5. **Endurecer upload e validações:** impor limites de aplicação/proxy e validar formatos antes de parsear.
6. **Empacotar e operar:** lockfile/dependências auditadas, Gunicorn + proxy TLS, usuário dedicado, volume privado, logs sem segredos, backups cifrados e restauração testada.
7. **Validar antes do go-live:** teste de autorização entre papéis, CSRF, rate limit, sessão, recuperação de backup, tentativa de upload excedendo limites, inspeção de resposta para confirmar ausência de segredos e varredura de imagem/artefatos para garantir que o DB não foi incluído.

## Critérios de bloqueio de deploy

O deploy remoto permanece bloqueado enquanto qualquer item abaixo for verdadeiro:

- `credentials.db`, `credentials_backup`, dumps ou backups com o acervo atual puderem entrar em repositório, imagem, artefato ou servidor de produção;
- credenciais gerenciadas permanecerem em texto puro ou a chave de criptografia estiver junto do banco;
- senha de login não estiver em hash Argon2id/scrypt não reversível;
- for possível abrir a lista, revelar segredo ou alterar estado sem autenticação, autorização e CSRF;
- `GET /` continuar entregando qualquer segredo — senha ou valor de campo secreto — no HTML/DOM/JavaScript;
- o banco/backup não estiver em volume privado com diretório `0700` e arquivos `0600` sob usuário dedicado;
- TLS, cookies seguros, rate limits e headers de proteção não estiverem configurados no proxy;
- upload não tiver limites de tamanho/processamento e validação de formato;
- backup cifrado e restauração testada não existirem.

## Limites desta análise

A análise original foi estática/local antes da implementação. Após a implementação, o projeto possui `pyproject.toml`, `uv.lock`, 222 testes automatizados (`uv run --frozen --python 3.12 python -m pytest -q`), `pip-audit` limpo e `node --check` válido. A configuração do servidor, DNS, TLS (Let's Encrypt via Traefik), firewall, secret manager e pipeline foram revisados durante o deploy de produção em `servicemanager.quantmind.com.br`.



## Cutover de autenticação — remoção de TOTP (14/07/2026)

A autenticação agora usa `users.username` + senha Argon2id, sem TOTP, códigos de recuperação nem rotas de bootstrap. O `users.id=1` foi migrado para `username=admin`, preservando hash, papel, estado, timestamps, `session_version` e a cadeia de auditoria (25 eventos byte-idênticos).

- **Schema:** 8 tabelas canônicas; `users` sem colunas TOTP/recovery/bootstrap; `accounts.email` mantido como e-mail de conta de serviço.
- **Seed idempotente:** `ADMIN_USERNAME`/`ADMIN_PASSWORD` criam admin somente em DB vazio; inertes em DB existente.
- **Reauth por senha:** a reautenticação para revelações usa senha atual (5 min), sem TOTP nem recovery.
- **Risco residual:** sem MFA, roubo de senha dá acesso direto. Mitigações ativas: rate limit, Argon2id, rehash oportunista, revogação por `session_version`, auditoria append-only HMAC.
- **Rotas removidas:** `/bootstrap`, `/bootstrap/issue-totp`, `/enroll-totp`, `/enroll-totp/issue`, `/admin/users/<id>/reset-mfa` retornam 404.
- **Migração:** snapshot SQLite `backup()` incorporou WAL; mapa `{"1":"admin"}`; destino atômico `0600` sem sidecars; digest semântico local↔remoto idêntico.
- **Auditoria:** evento 26 `auth.schema_migrated` anexado pelo caminho normal após startup saudável; cadeia válida; IDs contíguos apesar de `sqlite_sequence` preservado.
- **Dependências removidas:** `pyotp`, `qrcode`. `email-validator` mantido para `accounts.email`.
- **Bloqueio pendente:** smoke autenticado em produção bloqueado por handoff de senha admin ausente; autoDeploy permanece `false`.

## Task6 — correções de interface preservadas (13/07/2026)

- A criação de serviço insere, na mesma transação que cria o serviço e seu evento de auditoria, um vínculo `account_service` com estado `nunca` para cada conta existente. Cada linha exibida mantém, assim, a relação exigida pelos controles de edição, status e campos.
- Controles `.button-quiet` usam texto escuro nos painéis claros; o cabeçalho mantém contraste branco por seletor específico. Em hover/foco, o controle usa fundo navy e texto branco.
- Administradores podem reclassificar campos existentes. A rota converte todos os valores na mesma transação entre plaintext e envelopes AES-GCM com AAD `account:{account_id}:field:{field_id}`, restaura o trigger de representação antes do commit e grava `field.reclassified` sem valor secreto. Operadores recebem `403`.
- A listagem de um serviço parte de `account_service` e faz `JOIN` com `accounts`; contas sem vínculo para o serviço selecionado não são exibidas. Relações esparsas migradas são preservadas e cada ação mostrada continua tendo o vínculo que as rotas exigem.
- Regressões para classificação de campos, vínculos de serviço e ausência de contas desvinculadas permanecem cobertas pelos testes de interface; o fluxo TOTP/bootstrap antigo foi removido no cutover de 14/07/2026.

## Task7 — correções finais 2 (13/07/2026)

- DONE: XLSX rejeita caminhos ZIP absolutos Windows/UNC, MIME incompatível (mantendo `application/octet-stream` como fallback explícito) e macros declaradas por tipos OOXML, inclusive macro-sheet padrão, ou relacionamentos, sem depender do nome do membro.
- Verificação local com bancos temporários: `uv run pytest -q tests/test_task7_imports.py tests/test_task5_security.py tests/test_auth.py` (92 passed). Nenhum `credentials.db`, deploy ou configuração global foi usado.

## Task7 — correções finais 3 (13/07/2026)

- DONE: CSV usa dialeto estrito; aspas malformadas retornam erro de formato antes da transação, sem criar contas nem eventos de auditoria.
- Verificação local com banco temporário: `uv run pytest -q tests/test_task7_imports.py` (27 passed). Nenhum `credentials.db`, deploy ou configuração global foi usado.

## Task7 — correções finais 4 (13/07/2026)

- DONE: Falhas ao abrir ou ler metadados XLSX (`[Content_Types].xml` e `.rels`), incluindo compressão ZIP não suportada, são convertidas em erro seguro de formato; `/import` redireciona sem mutar contas nem divulgar o erro do arquivo.
- Verificação local com banco temporário: `uv run pytest -q tests/test_task7_imports.py` (31 passed). Nenhum `credentials.db`, deploy ou configuração global foi usado.

## Redesign de interface e campo "cadastro" (14/07/2026)

- **Schema:** `account_service` ganhou `registered INTEGER NOT NULL DEFAULT 0 CHECK (registered IN (0, 1))` (credencial possui cadastro básico no serviço, sem produto ativo). Validadores congelados (`_secure_db.EXPECTED_SECURE_COLUMNS`, `verify_migrated_db.EXPECTED_COLUMNS`) atualizados; o schema canônico continua sendo derivado de `service_manager.db.SCHEMA`.
- **Migração:** `scripts/migrate_registered_column.py` — offline, snapshot `backup()`, valida o schema pré-migração congelado + integridade + cadeia de auditoria (HMAC) na origem, reconstrói o banco pelo schema canônico com `registered=0`, revalida equivalência linha a linha, sequências e cadeia no destino, e faz colocação atômica `0600` com rollback. Reexecutar sobre um banco já migrado falha com "source schema is incompatible".
- **Rotas:** `POST /accounts/<id>/registered` (aceita apenas `0`/`1`, audita `account.registered_updated`); `/add` aceita `registered=1` apenas para o serviço ativo; `link_all_services` zera `registered` nos demais vínculos.
- **Interface:** tema escuro; barra de serviços com adição/exclusão no topo; tabela principal Email · Senha (revelação autorizada) · Status (badge de 3 estados) · Cadastro (toggle) · Ações; linhas expansíveis com edição da conta e campos adicionais; filtro fuzzy client-side (subsequência, insensível a acentos) apenas sobre email, rótulo de status e campos não secretos presentes no DOM; nenhum segredo entra em `data-search`.
- **CSRF/CSP preservados:** todos os formulários mantêm `csrf_token` oculto + `service_id`; sem scripts ou estilos inline; auto-submit usa `requestSubmit()` (dispara a sincronização de token).
- Verificação local: `uv run pytest -q` (227 passed) + smoke em navegador com banco temporário (login, reauth, revelação, toggle de cadastro persistido, mudança de status, filtro, expansão). Nenhum `credentials.db` foi usado.

## Cofre tabular: cópia, edição inline e fim da classificação (14/07/2026)

- **Schema:** `custom_fields` perdeu `is_secret`; `field_values` passou a exigir sempre o envelope AES-GCM (`value_ciphertext`, `value_nonce`, `value_key_version` `NOT NULL`) — removidas a coluna `value_plaintext` e os três triggers de representação (`field_values_require_secret_representation_insert/update`, `custom_fields_preserve_value_representation`). Validadores congelados (`_secure_db`, `verify_migrated_db`) e `compare_business_data` atualizados; o schema canônico continua derivado de `service_manager.db.SCHEMA`.
- **Migração:** `scripts/migrate_unclassified_fields.py` — offline e atômica no padrão de `migrate_registered_column.py`: valida o schema pré-cutover congelado (registered + is_secret + representações mistas + triggers) + integridade + FK + cadeia HMAC na origem; reconstrói pelo schema canônico convertendo cada `value_plaintext` legado para envelope AES-GCM com AAD `account:{account_id}:field:{field_id}` e copiando envelopes já cifrados byte a byte; revalida equivalência semântica (decrypt), sequências e cadeia; colocação atômica `0600` com rollback. Reexecutar sobre banco já migrado falha com "source schema is incompatible".
- **Senha principal:** continua ausente do GET; revelada apenas pelo endpoint `POST /api/accounts/<id>/secrets/password/reveal` sob sessão + CSRF + rate limit (20/10 min), **sem** reautenticação recente por senha. `require_recent_reauth`/`/reauth` permanecem exclusivamente para operações administrativas de usuários (`POST /admin/users`, mudança de papel e ativação).
- **Campos adicionais:** cifrados em repouso, porém descriptografados no servidor e enviados **visíveis** na listagem autenticada (`Cache-Control: no-store, private`). Removidos os endpoints `POST /field/<id>/classification` e `POST /api/accounts/<account>/fields/<field>/reveal` (agora 404). O reveal separado de campo deixou de existir; a busca `data-search` agora inclui nomes e valores adicionais descriptografados.
- **Interface:** expansão movida para junto do e-mail; “Editar” abre um único `<dialog>` reutilizável (e-mail + senha opcional, senha vazia preserva); cada valor exibido (e-mail, status, cadastro, senha, nome/valor de campo) tem botão de cópia em um clique via `navigator.clipboard.writeText()` sem fallback inseguro; a senha usa célula inline com `Exibir`/`Copiar` por linha (estado por célula, retorno ao marcador em timeout ≤ 30 s, `visibilitychange` e `pagehide`); campos adicionais em tabela `Campo · Valor · Ações`. CSP mantida sem script/estilo inline.
- Verificação local: `uv run --frozen --python 3.12 python -m pytest -q` (229 passed) + `node --check static/js/app.js`. Smoke em banco temporário: GET autenticado sem a senha principal e com valores de campo visíveis; `Exibir`/`Copiar` da senha sem `/reauth`; cópia de e-mail/status/cadastro/campo; modal de edição; endpoints removidos retornam 404. Nenhum `credentials.db` foi usado.
