"""Read-path tests for the Machines area: activity + live-session inventory.

Covers the three read routes added for machines-area-spec.md §8 / §8.2:
owner scoping, the admin-only `scope=all` view, hash-only payloads, the
per-server subset, the live-terminal inventory, and the property that none of
them consume the connection rate-limit budget.

Fixture shape mirrors tests/test_ssh_api.py (same in-memory sqlite + patched
``ssh_remote._session``), so the routes are exercised through HTTP exactly as
the browser does.
"""

import hashlib
from collections import defaultdict, deque
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.ssh_routes as ssh_routes
from src import ssh_client, ssh_remote

_AUDIT_KEYS = {"id", "server_id", "server_label", "event", "created_at",
               "exit_code", "command_hash"}


@pytest.fixture
def env(monkeypatch, tmp_path):
    import core.database as cdb
    import src.constants as consts
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    monkeypatch.setattr(consts, "DATA_DIR", str(tmp_path))
    eng = create_engine(f"sqlite:///{tmp_path}/t.db")
    cdb.Base.metadata.create_all(bind=eng)
    maker = sessionmaker(bind=eng)

    @contextmanager
    def _fake():
        db = maker()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    monkeypatch.setattr(ssh_remote, "_session", _fake)
    monkeypatch.setattr(ssh_routes, "_hits", defaultdict(deque))
    monkeypatch.setattr(ssh_routes, "get_current_user", lambda req: "alice")
    monkeypatch.setattr(ssh_client, "_sessions", {})

    app = FastAPI()
    app.include_router(ssh_routes.setup_ssh_routes())
    client = TestClient(app, raise_server_exceptions=False)
    return SimpleNamespace(client=client, app=app)


def _create(owner, label="Home", host="h", port=2222):
    return ssh_remote.create_server(
        owner, label=label, host=host, port=port, username="alice",
        auth_type="key", password="", sudo_password="",
    )


def _as(monkeypatch, user):
    monkeypatch.setattr(ssh_routes, "get_current_user", lambda req: user)


# ── GET /api/ssh/audit — owner scope and payload ────────────────────────────

def test_audit_is_owner_scoped_and_hash_only(env, monkeypatch):
    alice_srv = _create("alice")
    bob_srv = _create("bob", label="Bob")
    ssh_remote.audit("alice", alice_srv["id"], "exec", "uptime -a", 0)
    ssh_remote.audit("bob", bob_srv["id"], "exec", "id", 0)

    r = env.client.get("/api/ssh/audit")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scope"] == "self"
    assert body["admin"] is False  # no auth_manager configured → fail closed

    rows = body["rows"]
    assert rows, "the caller's own rows must be returned"
    assert all(row["server_id"] == alice_srv["id"] for row in rows)
    assert bob_srv["id"] not in r.text

    # server_created is written on create, so assert membership not equality.
    events = sorted(row["event"] for row in rows)
    assert "exec" in events and "server_created" in events

    exec_row = next(row for row in rows if row["event"] == "exec")
    assert set(exec_row) == _AUDIT_KEYS
    assert exec_row["command_hash"] == hashlib.sha256(b"uptime -a").hexdigest()
    assert exec_row["server_label"] == "Home"
    assert exec_row["created_at"]  # serialized, not a raw datetime
    assert exec_row["exit_code"] == 0

    # The command text itself never reaches the client.
    assert "uptime" not in r.text


def test_audit_event_filter(env):
    srv = _create("alice")
    ssh_remote.audit("alice", srv["id"], "exec", "date", 0)
    ssh_remote.audit("alice", srv["id"], "upload", "", 0)

    r = env.client.get("/api/ssh/audit", params={"event": "exec"})
    assert r.status_code == 200, r.text
    assert [row["event"] for row in r.json()["rows"]] == ["exec"]


def test_audit_limit_is_clamped(env):
    srv = _create("alice")
    for i in range(5):
        ssh_remote.audit("alice", srv["id"], "exec", f"cmd-{i}", 0)

    assert len(env.client.get("/api/ssh/audit", params={"limit": 2}).json()["rows"]) == 2
    # 0 clamps up to 1 rather than returning nothing or everything.
    assert len(env.client.get("/api/ssh/audit", params={"limit": 0}).json()["rows"]) == 1
    assert env.client.get("/api/ssh/audit", params={"limit": 9999}).status_code == 200


def test_audit_label_is_best_effort_for_a_deleted_machine(env):
    """Audit rows outlive their machine (server_id has no FK)."""
    srv = _create("alice")
    ssh_remote.audit("alice", srv["id"], "exec", "id", 0)
    ssh_remote.delete_server("alice", srv["id"])

    rows = env.client.get("/api/ssh/audit").json()["rows"]
    assert all(row["server_id"] == srv["id"] for row in rows)
    deleted = [row for row in rows if row["event"] == "server_deleted"]
    assert deleted and deleted[0]["server_label"] == ""


# ── GET /api/ssh/audit?scope=all — admin only ───────────────────────────────

def test_scope_all_is_forbidden_for_non_admins(env):
    _create("alice")
    bob_srv = _create("bob", label="Bob")

    assert env.client.get("/api/ssh/audit", params={"scope": "all"}).status_code == 403

    env.app.state.auth_manager = SimpleNamespace(is_admin=lambda user: False)
    r = env.client.get("/api/ssh/audit", params={"scope": "all"})
    assert r.status_code == 403
    assert bob_srv["id"] not in r.text


def test_scope_all_reaches_other_owners_for_admins(env):
    alice_srv = _create("alice")
    bob_srv = _create("bob", label="Bob")
    env.app.state.auth_manager = SimpleNamespace(is_admin=lambda user: True)

    r = env.client.get("/api/ssh/audit", params={"scope": "all"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scope"] == "all"
    assert body["admin"] is True
    assert {row["server_id"] for row in body["rows"]} >= {alice_srv["id"], bob_srv["id"]}

    # …and a plain (self-scoped) read still narrows to the caller.
    self_body = env.client.get("/api/ssh/audit").json()
    assert all(row["server_id"] == alice_srv["id"] for row in self_body["rows"])
    assert self_body["admin"] is True


# ── GET /api/ssh/servers/{id}/audit — per-machine subset ────────────────────

def test_per_server_audit_filters_and_404s_another_owner(env, monkeypatch):
    first = _create("alice", label="One", host="one")
    second = _create("alice", label="Two", host="two")
    ssh_remote.audit("alice", first["id"], "exec", "date", 0)
    ssh_remote.audit("alice", second["id"], "upload", "", 0)

    r = env.client.get(f"/api/ssh/servers/{first['id']}/audit")
    assert r.status_code == 200, r.text
    rows = r.json()["rows"]
    assert rows
    assert all(row["server_id"] == first["id"] for row in rows)
    assert second["id"] not in r.text

    _as(monkeypatch, "bob")
    assert env.client.get(f"/api/ssh/servers/{first['id']}/audit").status_code == 404


# ── GET /api/ssh/terminals — live session inventory ─────────────────────────

def test_terminals_lists_only_the_callers_live_sessions(env, monkeypatch):
    alice_srv = _create("alice", label="Home", port=2222)
    bob_srv = _create("bob", label="Bob", host="bob", port=22)
    monkeypatch.setattr(ssh_client, "_sessions", {
        "s1": SimpleNamespace(id="s1", owner="alice", server_id=alice_srv["id"], closed=False),
        "s2": SimpleNamespace(id="s2", owner="bob", server_id=bob_srv["id"], closed=False),
        # A closed session must not occupy the cap or the list.
        "s3": SimpleNamespace(id="s3", owner="alice", server_id=alice_srv["id"], closed=True),
    })

    r = env.client.get("/api/ssh/terminals")
    assert r.status_code == 200, r.text
    sessions = r.json()["sessions"]
    assert [s["session_id"] for s in sessions] == ["s1"]
    assert sessions[0]["server_id"] == alice_srv["id"]
    assert sessions[0]["server_label"] == "Home"
    assert sessions[0]["port"] == 2222
    assert bob_srv["id"] not in r.text


def test_terminals_is_empty_without_sessions(env):
    assert env.client.get("/api/ssh/terminals").json() == {"sessions": []}


# ── Reads are not connection-touching ──────────────────────────────────────

def test_read_routes_do_not_consume_the_rate_limit(env, monkeypatch):
    monkeypatch.setattr(ssh_routes, "_RATE_LIMIT", 1)
    srv = _create("alice")

    assert env.client.get("/api/ssh/audit").status_code == 200
    assert env.client.get(f"/api/ssh/servers/{srv['id']}/audit").status_code == 200
    assert env.client.get("/api/ssh/terminals").status_code == 200
    assert not ssh_routes._hits["alice"], "reads must not spend a connection budget"

    # The budget is genuinely still free for connection-touching calls: a
    # missing server still counts (LookupError → 404), so the second call 429s.
    assert env.client.post("/api/ssh/servers/nope/exec",
                           json={"cmd": "id"}).status_code == 404
    assert env.client.post("/api/ssh/servers/nope/exec",
                           json={"cmd": "id"}).status_code == 429


def test_internal_tool_cannot_read_activity(env, monkeypatch):
    _as(monkeypatch, "internal-tool")
    assert env.client.get("/api/ssh/audit").status_code == 401
    assert env.client.get("/api/ssh/terminals").status_code == 401
