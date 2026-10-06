"""HTTP tests for the Phase-2 interactive terminal routes (routes/ssh_routes.py).

The route layer is exercised with the transport stubbed: what matters here is
owner scoping, the server binding, the SSE frame shape, input caps, and that a
finished or dropped stream frees the remote PTY.
"""

import json
from collections import defaultdict, deque

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.ssh_routes as ssh_routes
from src import ssh_client, ssh_remote


class FakeSession:
    def __init__(self, owner="alice", server_id="srv1", chunks=("hi\n", None)):
        self.id = "sess1"
        self.owner = owner
        self.server_id = server_id
        self._chunks = list(chunks)
        self.written = []
        self.resized = []
        self.closed = False

    def write(self, data):
        self.written.append(data)

    def resize(self, cols, rows):
        self.resized.append((cols, rows))

    def read(self, wait=0.25):
        return self._chunks.pop(0) if self._chunks else None

    def exit_status(self):
        return 7

    def close(self):
        self.closed = True


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(ssh_routes, "get_current_user", lambda req: "alice")
    monkeypatch.setattr(ssh_routes, "_hits", defaultdict(deque))
    app = FastAPI()
    app.include_router(ssh_routes.setup_ssh_routes())
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _clean_sessions():
    ssh_client._reset_sessions_for_tests()
    yield
    ssh_client._reset_sessions_for_tests()


def _register(monkeypatch, session):
    """Make the route layer see ``session`` for owner 'alice'."""
    def _get(owner, session_id):
        if owner != session.owner or session_id != session.id:
            raise LookupError("terminal session not found")
        return session
    monkeypatch.setattr(ssh_client, "get_terminal", _get)
    monkeypatch.setattr(ssh_client, "close_terminal",
                        lambda owner, sid: session.close())
    monkeypatch.setattr(ssh_client, "close_terminal_by_id",
                        lambda sid: (_ for _ in ()).throw(LookupError(sid))
                        if sid != session.id else session.close())


class TestOpen:
    def test_open_returns_session_details(self, client, monkeypatch):
        monkeypatch.setattr(ssh_remote, "open_terminal_for", lambda owner, ref, **kw: {
            "session_id": "abc", "server_id": ref, "target": "alice@box",
            "port": 22, "label": "Box"})
        r = client.post("/api/ssh/servers/srv1/terminal", json={"cols": 120, "rows": 40})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True and body["session_id"] == "abc"
        assert body["target"] == "alice@box"

    def test_open_clamps_size_and_forwards_it(self, client, monkeypatch):
        seen = {}

        def _open(owner, ref, **kw):
            seen.update(kw)
            return {"session_id": "abc", "server_id": ref}
        monkeypatch.setattr(ssh_remote, "open_terminal_for", _open)
        assert client.post("/api/ssh/servers/srv1/terminal",
                           json={"cols": 99999, "rows": 0}).status_code == 200
        assert seen == {"cols": 400, "rows": 5}

    def test_open_rejects_non_numeric_size(self, client):
        r = client.post("/api/ssh/servers/srv1/terminal", json={"cols": "wide"})
        assert r.status_code == 400

    def test_open_maps_domain_errors(self, client, monkeypatch):
        def _raise(msg, exc):
            def _f(owner, ref, **kw):
                raise exc(msg)
            return _f
        monkeypatch.setattr(ssh_remote, "open_terminal_for",
                            _raise("server has no pinned host key — run Test first", ValueError))
        assert client.post("/api/ssh/servers/srv1/terminal", json={}).status_code == 400
        monkeypatch.setattr(ssh_remote, "open_terminal_for",
                            _raise("server not found", LookupError))
        assert client.post("/api/ssh/servers/srv1/terminal", json={}).status_code == 404
        monkeypatch.setattr(ssh_remote, "open_terminal_for",
                            _raise("AuthenticationException", ssh_client.SshClientError))
        assert client.post("/api/ssh/servers/srv1/terminal", json={}).status_code == 400

    def test_open_requires_authentication(self, client, monkeypatch):
        monkeypatch.setattr(ssh_routes, "get_current_user", lambda req: None)
        assert client.post("/api/ssh/servers/srv1/terminal", json={}).status_code == 401

    def test_open_rejects_the_internal_loopback_identity(self, client, monkeypatch):
        monkeypatch.setattr(ssh_routes, "get_current_user", lambda req: "internal-tool")
        assert client.post("/api/ssh/servers/srv1/terminal", json={}).status_code == 401


class TestStream:
    def test_stream_emits_frames_then_exit_code_and_closes_pty(self, client, monkeypatch):
        session = FakeSession()
        _register(monkeypatch, session)
        r = client.get("/api/ssh/servers/srv1/terminal/sess1/stream")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        frames = [json.loads(line[6:]) for line in r.text.splitlines()
                  if line.startswith("data: ")]
        assert {"stream": "stdout", "data": "hi\n"} in frames
        assert frames[-1] == {"exit_code": 7}
        assert session.closed is True

    def test_stream_unknown_session_is_404(self, client, monkeypatch):
        monkeypatch.setattr(ssh_client, "get_terminal",
                            lambda owner, sid: (_ for _ in ()).throw(LookupError("nope")))
        assert client.get("/api/ssh/servers/srv1/terminal/zz/stream").status_code == 404

    def test_stream_rejects_a_server_the_session_does_not_belong_to(self, client, monkeypatch):
        _register(monkeypatch, FakeSession(server_id="other"))
        assert client.get("/api/ssh/servers/srv1/terminal/sess1/stream").status_code == 404

    def test_stream_is_owner_scoped(self, client, monkeypatch):
        _register(monkeypatch, FakeSession(owner="bob"))
        assert client.get("/api/ssh/servers/srv1/terminal/sess1/stream").status_code == 404


class TestInputAndResize:
    def test_input_reaches_the_channel(self, client, monkeypatch):
        session = FakeSession(chunks=())
        _register(monkeypatch, session)
        r = client.post("/api/ssh/servers/srv1/terminal/sess1/input", json={"data": "ls\n"})
        assert r.status_code == 200 and session.written == ["ls\n"]

    def test_empty_input_is_accepted_without_a_write(self, client, monkeypatch):
        session = FakeSession(chunks=())
        _register(monkeypatch, session)
        r = client.post("/api/ssh/servers/srv1/terminal/sess1/input", json={"data": ""})
        assert r.json() == {"ok": True, "bytes": 0} and session.written == []

    def test_oversized_input_is_rejected(self, client, monkeypatch):
        session = FakeSession(chunks=())
        _register(monkeypatch, session)
        r = client.post("/api/ssh/servers/srv1/terminal/sess1/input",
                        json={"data": "x" * (ssh_routes.MAX_TERMINAL_INPUT_CHARS + 1)})
        assert r.status_code == 400 and session.written == []

    def test_resize_is_clamped(self, client, monkeypatch):
        session = FakeSession(chunks=())
        _register(monkeypatch, session)
        r = client.post("/api/ssh/servers/srv1/terminal/sess1/resize",
                        json={"cols": 1, "rows": 9999})
        assert r.status_code == 200 and session.resized == [(20, 200)]

    def test_input_on_a_dead_session_is_404(self, client, monkeypatch):
        monkeypatch.setattr(ssh_client, "get_terminal",
                            lambda owner, sid: (_ for _ in ()).throw(LookupError("gone")))
        assert client.post("/api/ssh/servers/srv1/terminal/zz/input",
                           json={"data": "x"}).status_code == 404


class TestClose:
    def test_close_closes_and_audits(self, client, monkeypatch):
        session = FakeSession(chunks=())
        _register(monkeypatch, session)
        audited = []
        monkeypatch.setattr(ssh_remote, "audit",
                            lambda *a, **kw: audited.append(a))
        monkeypatch.setattr(ssh_client, "get_terminal",
                            lambda owner, sid: session)
        r = client.delete("/api/ssh/servers/srv1/terminal/sess1")
        assert r.json() == {"ok": True}
        assert session.closed is True
        assert any(row[2] == "terminal_closed" for row in audited)

    def test_close_unknown_session_is_404(self, client, monkeypatch):
        monkeypatch.setattr(ssh_client, "get_terminal",
                            lambda owner, sid: (_ for _ in ()).throw(LookupError("gone")))
        assert client.delete("/api/ssh/servers/srv1/terminal/zz").status_code == 404
