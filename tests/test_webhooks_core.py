from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import socket
import sqlite3
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service_manager.crypto import (
    encrypt_secret_with_key,
    webhook_signing_secret_aad,
    webhook_url_aad,
)
from service_manager.db import SCHEMA
from service_manager.webhooks import (
    WebhookError,
    deliver_once,
    list_webhook_configs,
    enqueue_webhook_event,
    purge_webhook_deliveries,
    run_worker,
    validate_webhook_url,
)

DATA_KEY = base64.b64encode(b"d" * 32).decode("ascii")
GLOBAL_IP = "93.184.216.34"
HOST = "hooks.example.test"


def _make_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()
    return conn


def _resolver(mapping: dict[str, list[str]]):
    def resolve(host, port, *args, **kwargs):
        if host not in mapping:
            raise socket.gaierror(f"no such host: {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port)) for addr in mapping[host]]

    return resolve


class _FakeResponse:
    def __init__(self, status: int):
        self.status = status

    def read(self, amt: int | None = None) -> bytes:
        return b""


class _FakeConnection:
    """Captures the request and returns a preset status."""

    def __init__(self, status: int, log: dict):
        self._status = status
        self._log = log

    def factory(self, hostname, resolved_ip, timeout):
        self._log["hostname"] = hostname
        self._log["resolved_ip"] = resolved_ip
        self._log["timeout"] = timeout
        return self

    def request(self, method, path, body=None, headers=None):
        self._log["method"] = method
        self._log["path"] = path
        self._log["body"] = body
        self._log["headers"] = headers

    def getresponse(self):
        return _FakeResponse(self._status)

    def close(self):
        self._log["closed"] = True


def _insert_config(conn: sqlite3.Connection, url: str, secret_bytes: bytes, *, enabled: int = 1, deleted: str | None = None) -> int:
    now = datetime.now(UTC).isoformat()
    cur = conn.execute(
        """
        INSERT INTO webhook_configs (destination_host, url_ciphertext, url_nonce, url_key_version,
            signing_secret_ciphertext, signing_secret_nonce, signing_secret_key_version,
            enabled, created_at, updated_at, deleted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (HOST, b"x", b"y", 1, b"x", b"y", 1, enabled, now, now, deleted),
    )
    cid = cur.lastrowid
    if cid is None:
        raise RuntimeError("webhook insert did not return an id")
    url_enc = encrypt_secret_with_key(DATA_KEY, url, aad=webhook_url_aad(cid))
    secret_b64 = base64.urlsafe_b64encode(secret_bytes).decode("ascii")
    sec_enc = encrypt_secret_with_key(DATA_KEY, secret_b64, aad=webhook_signing_secret_aad(cid))
    conn.execute(
        """
        UPDATE webhook_configs SET url_ciphertext=?, url_nonce=?, url_key_version=?,
            signing_secret_ciphertext=?, signing_secret_nonce=?, signing_secret_key_version=?
        WHERE id=?
        """,
        (url_enc.ciphertext, url_enc.nonce, url_enc.key_version,
         sec_enc.ciphertext, sec_enc.nonce, sec_enc.key_version, cid),
    )
    conn.commit()
    return cid


# --------------------------------------------------------------------------
# URL validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.test/hook",              # not https
        "https://127.0.0.1/hook",                       # loopback raw-ip
        "https://10.0.0.5/hook",                        # private raw-ip
        "https://203.0.113.10/hook",                    # raw-ip host
        "https://user:pw@hooks.example.test/hook",      # userinfo
        "https://hooks.example.test/hook#frag",         # fragment
        "https://hooks.example.test:8443/hook",         # non-443 port
        "https:///hook",                                # no hostname
        "https://hooks.example.test/" + "a" * 2100,     # oversized
    ],
)
def test_validate_rejects_bad_urls(url):
    resolver = _resolver({HOST: [GLOBAL_IP]})
    with pytest.raises(WebhookError):
        validate_webhook_url(url, resolver=resolver)


def test_validate_rejects_private_resolution():
    resolver = _resolver({"internal.test": ["10.1.2.3"]})
    with pytest.raises(WebhookError):
        validate_webhook_url("https://internal.test/hook", resolver=resolver)


def test_validate_rejects_dns_failure():
    resolver = _resolver({})
    with pytest.raises(WebhookError):
        validate_webhook_url("https://nope.test/hook", resolver=resolver)


def test_validate_accepts_global_https_and_returns_host():
    resolver = _resolver({HOST: [GLOBAL_IP]})
    assert validate_webhook_url(f"https://{HOST}:443/hook?a=1", resolver=resolver) == HOST


# --------------------------------------------------------------------------
# Enqueue
# --------------------------------------------------------------------------


def test_enqueue_is_transactional_and_targets_subscribed_configs(tmp_path):
    conn = _make_db(tmp_path / "db.sqlite")
    cid = _insert_config(conn, f"https://{HOST}/hook", b"s" * 32)
    conn.execute("INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, 'login_failures')", (cid,))
    # unsubscribed config
    cid2 = _insert_config(conn, f"https://{HOST}/two", b"t" * 32)
    conn.commit()

    conn.execute("BEGIN IMMEDIATE")
    count = enqueue_webhook_event(conn, "login_failures", {"source_ip": "1.2.3.4", "ip_count": 5})
    conn.commit()

    assert count == 1
    rows = conn.execute("SELECT config_id, status, attempt_count, event_type, payload_json FROM webhook_deliveries").fetchall()
    assert len(rows) == 1
    assert rows[0]["config_id"] == cid
    assert rows[0]["status"] == "pending"
    assert rows[0]["attempt_count"] == 0
    payload = json.loads(rows[0]["payload_json"])
    assert payload["event"] == "login_failures"
    assert payload["details"] == {"source_ip": "1.2.3.4", "ip_count": 5}
    assert set(payload) == {"id", "event", "occurred_at", "instance", "details"}


def test_enqueue_test_event_targets_single_config(tmp_path):
    conn = _make_db(tmp_path / "db.sqlite")
    cid = _insert_config(conn, f"https://{HOST}/hook", b"s" * 32)
    conn.execute("BEGIN IMMEDIATE")
    count = enqueue_webhook_event(conn, "test", {"info": "hi"}, config_id=cid)
    conn.commit()
    assert count == 1
    assert conn.execute("SELECT event_type FROM webhook_deliveries").fetchone()["event_type"] == "test"


def test_enqueue_rejects_secret_marker_keys_but_allows_scalar_string_values(tmp_path):
    conn = _make_db(tmp_path / "db.sqlite")
    conn.execute("BEGIN IMMEDIATE")
    # Markers in keys are rejected.
    with pytest.raises(WebhookError):
        enqueue_webhook_event(conn, "login_failures", {"password": "hunter2"})
    # Non-scalar values are rejected.
    with pytest.raises(WebhookError):
        enqueue_webhook_event(conn, "login_failures", {"data": ["not", "scalar"]})
    # A string VALUE that merely contains a marker (e.g. an endpoint name) is allowed.
    enqueue_webhook_event(conn, "authorization_failure", {"endpoint": "routes.reveal_password", "method": "POST"})
    conn.rollback()


# --------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------


def _lease(conn: sqlite3.Connection, delivery_id: int) -> str:
    token = secrets.token_hex(16)
    conn.execute(
        "UPDATE webhook_deliveries SET status='delivering', lease_token=?, leased_at=? WHERE id=?",
        (token, datetime.now(UTC).isoformat(), delivery_id),
    )
    conn.commit()
    return token


def _enqueue_one(conn: sqlite3.Connection, cid: int) -> int:
    conn.execute("INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, 'login_failures')", (cid,))
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    enqueue_webhook_event(conn, "login_failures", {"source_ip": "1.2.3.4"})
    conn.commit()
    return conn.execute("SELECT id FROM webhook_deliveries ORDER BY id DESC LIMIT 1").fetchone()["id"]


def test_deliver_signs_payload_and_ignores_proxies(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:9")
    secret_bytes = b"s" * 32
    conn = _make_db(tmp_path / "db.sqlite")
    cid = _insert_config(conn, f"https://{HOST}/hook?x=1", secret_bytes)
    did = _enqueue_one(conn, cid)
    token = _lease(conn, did)

    log: dict = {}
    fake = _FakeConnection(200, log)
    resolver = _resolver({HOST: [GLOBAL_IP]})

    ok = deliver_once(conn, did, data_key_b64=DATA_KEY, public_origin=f"https://{HOST}",
                      resolver=resolver, connection_factory=fake.factory)
    assert ok is True

    payload_bytes = conn.execute("SELECT payload_json FROM webhook_deliveries WHERE id=?", (did,)).fetchone()[0].encode()
    expected = "v1=" + hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest()
    assert log["headers"]["X-ServiceManager-Signature"] == expected
    assert log["headers"]["Content-Type"] == "application/json"
    assert log["headers"]["User-Agent"] == "ServiceManager-Webhook/1"
    assert log["resolved_ip"] == GLOBAL_IP
    assert log["hostname"] == HOST
    assert log["path"] == "/hook?x=1"
    assert log["closed"] is True

    row = conn.execute("SELECT status, delivered_at, last_status_code FROM webhook_deliveries WHERE id=?", (did,)).fetchone()
    assert row["status"] == "succeeded"
    assert row["delivered_at"] is not None
    assert row["last_status_code"] == 200


def test_deliver_disabled_config_terminal_fails(tmp_path):
    conn = _make_db(tmp_path / "db.sqlite")
    cid = _insert_config(conn, f"https://{HOST}/hook", b"s" * 32)
    did = _enqueue_one(conn, cid)
    token = _lease(conn, did)
    conn.execute("UPDATE webhook_configs SET enabled=0 WHERE id=?", (cid,))
    conn.commit()

    resolver = _resolver({HOST: [GLOBAL_IP]})
    ok = deliver_once(conn, did, data_key_b64=DATA_KEY, public_origin="", resolver=resolver,
                      connection_factory=_FakeConnection(200, {}).factory)
    assert ok is False
    row = conn.execute("SELECT status, last_error FROM webhook_deliveries WHERE id=?", (did,)).fetchone()
    assert row["status"] == "failed"
    assert row["last_error"] == "disabled"


def test_deliver_retry_schedule_then_failed(tmp_path):
    conn = _make_db(tmp_path / "db.sqlite")
    cid = _insert_config(conn, f"https://{HOST}/hook", b"s" * 32)
    did = _enqueue_one(conn, cid)
    resolver = _resolver({HOST: [GLOBAL_IP]})
    factory = _FakeConnection(500, {}).factory

    expected_delays = [30, 60, 300, 900]
    for attempt, delay in enumerate(expected_delays, start=1):
        token = _lease(conn, did)
        before = datetime.now(UTC)
        ok = deliver_once(conn, did, data_key_b64=DATA_KEY, public_origin="", resolver=resolver, connection_factory=factory)
        assert ok is False
        row = conn.execute("SELECT status, attempt_count, next_attempt_at, last_error FROM webhook_deliveries WHERE id=?", (did,)).fetchone()
        assert row["status"] == "retry"
        assert row["attempt_count"] == attempt
        assert row["last_error"] == "http"
        nxt = datetime.fromisoformat(row["next_attempt_at"])
        actual = (nxt - before).total_seconds()
        assert abs(actual - delay) < 5

    # fifth attempt => failed
    token = _lease(conn, did)
    ok = deliver_once(conn, did, data_key_b64=DATA_KEY, public_origin="", resolver=resolver, connection_factory=factory)
    assert ok is False
    row = conn.execute("SELECT status, attempt_count FROM webhook_deliveries WHERE id=?", (did,)).fetchone()
    assert row["status"] == "failed"
    assert row["attempt_count"] == 5


def test_terminal_update_requires_lease_ownership(tmp_path):
    # A worker only mutates a row it still owns: the terminal/retry updates key on
    # WHERE status='delivering' AND lease_token=?. If ownership was lost (reclaimed
    # by another worker), the conditional update matches zero rows.
    conn = _make_db(tmp_path / "db.sqlite")
    cid = _insert_config(conn, f"https://{HOST}/hook", b"s" * 32)
    did = _enqueue_one(conn, cid)
    my_token = _lease(conn, did)

    # Another worker reclaims the stale row with its own token.
    conn.execute("UPDATE webhook_deliveries SET lease_token='other-owner' WHERE id=?", (did,))
    conn.commit()

    # My finalize keyed on my (now stale) token must affect 0 rows.
    cur = conn.execute(
        "UPDATE webhook_deliveries SET status='succeeded' WHERE id=? AND status='delivering' AND lease_token=?",
        (did, my_token),
    )
    conn.commit()
    assert cur.rowcount == 0
    row = conn.execute("SELECT status, lease_token FROM webhook_deliveries WHERE id=?", (did,)).fetchone()
    assert row["status"] == "delivering"
    assert row["lease_token"] == "other-owner"


# --------------------------------------------------------------------------
# Worker claim / stale lease
# --------------------------------------------------------------------------


def test_worker_reclaims_stale_lease(tmp_path):
    db_path = tmp_path / "db.sqlite"
    conn = _make_db(db_path)
    cid = _insert_config(conn, f"https://{HOST}/hook", b"s" * 32)
    did = _enqueue_one(conn, cid)
    # Simulate a stale 'delivering' row leased long ago.
    stale = (datetime.now(UTC) - timedelta(seconds=120)).isoformat()
    conn.execute("UPDATE webhook_deliveries SET status='delivering', lease_token='dead', leased_at=? WHERE id=?", (stale, did))
    conn.commit()
    conn.close()

    stop = threading.Event()
    log: dict = {}
    fake = _FakeConnection(200, log)
    resolver = _resolver({HOST: [GLOBAL_IP]})

    t = threading.Thread(
        target=run_worker,
        args=(str(db_path), DATA_KEY, f"https://{HOST}", stop),
        kwargs={"resolver": resolver, "connection_factory": fake.factory},
    )
    t.start()
    deadline = datetime.now(UTC) + timedelta(seconds=10)
    status = None
    check = sqlite3.connect(db_path)
    check.row_factory = sqlite3.Row
    while datetime.now(UTC) < deadline:
        status = check.execute("SELECT status FROM webhook_deliveries WHERE id=?", (did,)).fetchone()["status"]
        if status == "succeeded":
            break
        threading.Event().wait(0.1)
    stop.set()
    t.join(timeout=10)
    check.close()
    assert status == "succeeded"


# --------------------------------------------------------------------------
# Purge
# --------------------------------------------------------------------------


def test_purge_only_removes_old_terminal_rows(tmp_path):
    conn = _make_db(tmp_path / "db.sqlite")
    cid = _insert_config(conn, f"https://{HOST}/hook", b"s" * 32)
    old = (datetime.now(UTC) - timedelta(days=100)).isoformat()
    recent = (datetime.now(UTC) - timedelta(days=1)).isoformat()

    def add(status, created):
        conn.execute(
            "INSERT INTO webhook_deliveries (config_id, event_type, payload_json, status, next_attempt_at, created_at) VALUES (?, 'test', '{}', ?, ?, ?)",
            (cid, status, created, created),
        )

    add("succeeded", old)   # purged
    add("failed", old)      # purged
    add("pending", old)     # kept (not terminal)
    add("retry", old)       # kept
    add("delivering", old)  # kept
    add("succeeded", recent)  # kept (recent)
    conn.commit()

    removed = purge_webhook_deliveries(conn, now=datetime.now(UTC))
    assert removed == 2
    remaining = {r["status"] for r in conn.execute("SELECT status FROM webhook_deliveries").fetchall()}
    assert remaining == {"pending", "retry", "delivering", "succeeded"}
    assert conn.execute("SELECT COUNT(*) FROM webhook_deliveries").fetchone()[0] == 4


# --------------------------------------------------------------------------
# Bounded listing (PERF-004)
# --------------------------------------------------------------------------


class _ExecCounter:
    """Wrap a connection, counting only direct execute() calls."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self.calls = 0

    def execute(self, statement, params=()):
        self.calls += 1
        return self._conn.execute(statement, params)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _insert_delivery(conn, cid, *, status="succeeded", last_error=None):
    now = datetime.now(UTC).isoformat()
    cur = conn.execute(
        "INSERT INTO webhook_deliveries (config_id, event_type, payload_json, status, next_attempt_at, created_at, last_error) "
        "VALUES (?, 'login_failures', '{}', ?, ?, ?, ?)",
        (cid, status, now, now, last_error),
    )
    conn.commit()
    return cur.lastrowid


def test_list_webhook_configs_uses_three_queries_for_twenty(tmp_path):
    conn = _make_db(tmp_path / "wh.db")
    for i in range(20):
        _insert_config(conn, f"https://{HOST}/hook{i}", b"s" * 32)
    assert sqlite3.sqlite_version_info >= (3, 25, 0)
    proxy = _ExecCounter(conn)
    result = list_webhook_configs(proxy)
    assert proxy.calls == 3
    assert len(result) == 20
    ids = [c["id"] for c in result]
    assert ids == sorted(ids)


def test_list_webhook_configs_empty_uses_one_query(tmp_path):
    conn = _make_db(tmp_path / "wh.db")
    proxy = _ExecCounter(conn)
    result = list_webhook_configs(proxy)
    assert result == []
    assert proxy.calls == 1


def test_list_webhook_configs_preserves_child_contracts(tmp_path):
    conn = _make_db(tmp_path / "wh.db")
    cid1 = _insert_config(conn, f"https://{HOST}/one", b"s" * 32)
    cid2 = _insert_config(conn, f"https://{HOST}/two", b"t" * 32)
    _insert_config(conn, f"https://{HOST}/gone", b"u" * 32, deleted=datetime.now(UTC).isoformat())
    # Subscriptions inserted out of lexical order for the first config.
    conn.execute("INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, 'reveal_rate_limit')", (cid1,))
    conn.execute("INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, 'authorization_failure')", (cid1,))
    conn.execute("INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, 'login_failures')", (cid1,))
    conn.commit()
    # 12 deliveries on the first config; the two newest carry a generic and a non-generic error.
    delivery_ids = []
    for i in range(12):
        if i == 10:
            did = _insert_delivery(conn, cid1, status="failed", last_error="timeout")
        elif i == 11:
            did = _insert_delivery(conn, cid1, status="failed", last_error="http://internal.host/secret-path")
        else:
            did = _insert_delivery(conn, cid1)
        delivery_ids.append(did)
    result = list_webhook_configs(conn)
    assert [c["id"] for c in result] == [cid1, cid2]
    first, second = result
    assert first["subscriptions"] == ["authorization_failure", "login_failures", "reveal_rate_limit"]
    recent = first["recent_deliveries"]
    assert [d["id"] for d in recent] == sorted(delivery_ids, reverse=True)[:10]
    assert all("config_id" not in d for d in recent)
    errors = {d["id"]: d["last_error"] for d in recent}
    assert errors[delivery_ids[10]] == "timeout"
    assert errors[delivery_ids[11]] == "connection"
    assert second["subscriptions"] == []
    assert second["recent_deliveries"] == []
