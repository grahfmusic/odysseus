"""HTTP tests for routes/ssh_routes.py: owner scope, redaction, rate limit."""

from contextlib import contextmanager

from collections import defaultdict, deque

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.ssh_routes as ssh_routes
from src import ssh_remote


@pytest.fixture
def client(monkeypatch, tmp_path):
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

    app = FastAPI()
    app.include_router(ssh_routes.setup_ssh_routes())
    return TestClient(app, raise_server_exceptions=False)


def test_crud_round_trip_with_redaction(client):
    r = client.post("/api/ssh/servers", json={
        "label": "Home", "host": "alice@h", "port": 2222,
        "username": "alice", "password": "s3cret",
    })
    assert r.status_code == 200, r.text
    srv = r.json()["server"]
    assert srv["has_password"] is True
    assert "password" not in srv and "sudo_password" not in srv

    r = client.get("/api/ssh/servers")
    assert r.status_code == 200
    assert len(r.json()["servers"]) == 1
    assert "s3cret" not in r.text

    r = client.patch(f"/api/ssh/servers/{srv['id']}", json={"label": "H2"})
    assert r.json()["server"]["label"] == "H2"

    r = client.delete(f"/api/ssh/servers/{srv['id']}")
    assert r.json() == {"ok": True}
    assert client.get("/api/ssh/servers").json() == {"servers": []}


def test_cross_owner_denied(client, monkeypatch):
    r = client.post("/api/ssh/servers", json={"label": "A", "host": "h"})
    sid = r.json()["server"]["id"]
    monkeypatch.setattr(ssh_routes, "get_current_user", lambda req: "bob")
    assert client.get("/api/ssh/servers").json() == {"servers": []}
    assert client.delete(f"/api/ssh/servers/{sid}").status_code == 404
    assert client.post(f"/api/ssh/servers/{sid}/exec",
                       json={"cmd": "id"}).status_code == 404


def test_internal_tool_rejected(client, monkeypatch):
    monkeypatch.setattr(ssh_routes, "get_current_user", lambda req: "internal-tool")
    r = client.get("/api/ssh/servers")
    assert r.status_code == 401


def test_invalid_host_rejected(client):
    r = client.post("/api/ssh/servers", json={"label": "X", "host": "-o ProxyCommand=x"})
    assert r.status_code == 400


def test_rate_limit(client, monkeypatch):
    monkeypatch.setattr(ssh_routes, "_RATE_LIMIT", 2)
    body = {"cmd": "id"}
    # No servers exist; LookupError -> 404 still counts as a hit.
    assert client.post("/api/ssh/servers/nope/exec", json=body).status_code == 404
    assert client.post("/api/ssh/servers/nope/exec", json=body).status_code == 404
    assert client.post("/api/ssh/servers/nope/exec", json=body).status_code == 429
