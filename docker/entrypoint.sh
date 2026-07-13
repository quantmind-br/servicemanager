#!/bin/sh
set -eu

fail() {
    printf '%s\n' "ERROR: $1" >&2
    exit 1
}

require_secret() {
    name="$1"
    eval "value=\${$name-}"
    [ -n "$value" ] || fail "$name must be configured"
}


require_base64_key() {
    name="$1"
    python -c 'import base64, os, sys; value = os.environ[sys.argv[1]]; decoded = base64.b64decode(value, validate=True); raise SystemExit(len(decoded) != 32)' "$name" \
        || fail "$name must be a base64-encoded 32-byte key"
}

require_cidr() {
    name="$1"
    eval "value=\${$name-}"
    [ -n "$value" ] || fail "$name must be configured"
    python -c 'import ipaddress, os, sys; ipaddress.ip_network(os.environ[sys.argv[1]], strict=False)' "$name" \
        || fail "$name must be a valid proxy CIDR"
}

write_trusted_proxy_config() {
    output_path="/tmp/nginx/trusted_proxy.conf"
    if [ "${SERVICE_MANAGER_TEST_HOOKS:-}" = "1" ] && [ -n "${TRUSTED_PROXY_CONFIG_PATH:-}" ]; then
        output_path="$TRUSTED_PROXY_CONFIG_PATH"
    fi
    mkdir -p "$(dirname "$output_path")"
    python -c 'import ipaddress, os; cidr = str(ipaddress.ip_network(os.environ["TRAEFIK_TRUSTED_CIDR"], strict=False)); print(f"set_real_ip_from {cidr};\nreal_ip_header X-Forwarded-For;\nreal_ip_recursive on;\ngeo $realip_remote_addr $trusted_forwarded_peer {{\n    default 0;\n    {cidr} 1;\n}}")' > "$output_path"
}


require_secret SECRET_KEY
require_secret DATA_KEY_V1
require_secret BACKUP_KEY_V1
require_secret AUDIT_KEY_V1
require_cidr TRAEFIK_TRUSTED_CIDR
require_base64_key SECRET_KEY
require_base64_key DATA_KEY_V1
require_base64_key BACKUP_KEY_V1
require_base64_key AUDIT_KEY_V1

DATABASE_PATH="${DATABASE_PATH:-/data/service-manager.db}"
export DATABASE_PATH
if [ "${REQUIRE_EXISTING_DATABASE:-false}" = "true" ]; then
    [ -f "$DATABASE_PATH" ] || fail "DATABASE_PATH must reference an existing database when REQUIRE_EXISTING_DATABASE=true"
    python -c 'import os, sqlite3, sys; from pathlib import Path; from service_manager.db import schema_is_current; conn = sqlite3.connect(Path(os.environ["DATABASE_PATH"]).resolve().as_uri() + "?mode=ro", uri=True); ok = schema_is_current(conn); conn.close(); sys.exit(0 if ok else 1)' 2>/dev/null \
        || fail "DATABASE_PATH must contain the migrated secure schema when REQUIRE_EXISTING_DATABASE=true"
fi

mkdir -p /tmp/nginx /tmp/nginx/client_temp /tmp/nginx/proxy_temp /tmp/nginx/fastcgi_temp /tmp/nginx/uwsgi_temp /tmp/nginx/scgi_temp
write_trusted_proxy_config

exec python /app/docker-supervisor.py
