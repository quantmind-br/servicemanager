from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from service_manager.audit import append_audit_event, verify_audit_chain
from service_manager.db import get_db, schema_is_current, transaction


def record() -> None:
    app = create_app()
    with app.app_context():
        conn = get_db()
        if not schema_is_current(conn) or not verify_audit_chain(conn):
            raise RuntimeError("database schema or audit chain is unhealthy")
        with transaction(conn):
            if conn.execute("SELECT 1 FROM audit_events WHERE action = 'auth.schema_migrated'").fetchone() is None:
                append_audit_event(conn, action="auth.schema_migrated", target_type="database")
        if not verify_audit_chain(conn):
            raise RuntimeError("database audit chain is unhealthy after append")


def main() -> int:
    try:
        record()
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: auth schema migration recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
