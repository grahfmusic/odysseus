"""HTTP tests for the Phase-2 interactive terminal routes (routes/ssh_routes.py).

The route layer is exercised with the transport stubbed: what matters here is
owner scoping, the server binding, the SSE frame shape, input caps, and that a
finished or dropped stream frees the remote PTY.

``TestLiveTerminalLoop`` is the exception: it drives a **real paramiko PTY**
against a throwaway local sshd. The stubbed tests can only prove what the routes
do with a session object; they cannot prove a remote shell survives a window
being hidden, which is the property spec §7.3 / AC5 is about. That class skips
when no sshd is available (see ``tests/helpers/ssh_fixture.py``).
"""

import json
import time
import uuid
from collections import defaultdict, deque
from contextlib import contextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.ssh_routes as ssh_routes
from src import ssh_client, ssh_remote
from tests.helpers.ssh_fixture import ssh_endpoint  # noqa: F401 (pytest fixture)


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


# ── Real PTY (spec §7.3 / AC5) ──────────────────────────────────────────────

@pytest.fixture
def ssh_db(monkeypatch, tmp_path):
    """Isolate core.database + DATA_DIR per test (mirrors test_ssh_servers.py)."""
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
    return tmp_path


def _read_until(session, needle, timeout=25.0):
    """Poll a live PTY until ``needle`` appears in its output (or time runs out)."""
    deadline = time.time() + timeout
    buf = ""
    while time.time() < deadline:
        chunk = session.read(wait=0.25)
        if chunk:
            buf += chunk
            if needle in buf:
                break
    return buf


@pytest.mark.ssh_integration
class TestLiveTerminalLoop:
    """A real PTY against a real sshd — the half the mocks cannot reach.

    ``_showDetail``/``_hideDetail`` deliberately issue no request, so hiding the
    Machines window is faithful to "make no call and keep the shell alive". The
    old teardown-on-hide (abort + DELETE) is exactly what this test would fail
    on: the second command below would land in a dead channel.
    """

    def _machine(self, owner, endpoint):
        import subprocess
        paths = ssh_remote.user_key_paths(owner)
        paths["private"].write_bytes(endpoint.private_key.read_bytes())
        paths["private"].chmod(0o600)
        derived = subprocess.run(["ssh-keygen", "-y", "-f", str(paths["private"])],
                                 capture_output=True, text=True, timeout=30)
        assert derived.returncode == 0, derived.stderr
        paths["public"].write_text(derived.stdout.strip() + "\n", encoding="utf-8")
        srv = ssh_remote.create_server(owner, label="Lab", host=endpoint.host,
                                       port=endpoint.port, username=endpoint.user)
        pinned = ssh_remote.test_connection(owner, srv["id"])
        assert pinned["ok"] is True, pinned
        return srv

    def test_a_hidden_area_keeps_the_pty_alive_until_disconnect(self, ssh_db,
                                                               ssh_endpoint, client):
        owner = "alice"
        srv = self._machine(owner, ssh_endpoint)
        opened = ssh_remote.open_terminal_for(owner, srv["id"], cols=100, rows=30)
        sid = opened["session_id"]
        session = ssh_client.get_terminal(owner, sid)
        try:
            first = "first-" + uuid.uuid4().hex[:8]
            session.write(f"echo {first}\n")
            out = _read_until(session, first)
            assert first in out, f"the PTY never echoed its own command: {out!r}"

            # The live-session inventory (Machines §8.2) sees it while it runs.
            live = client.get("/api/ssh/terminals").json()["sessions"]
            assert [s["session_id"] for s in live] == [sid]
            assert live[0]["server_id"] == srv["id"]
            assert live[0]["server_label"] == "Lab"
            assert live[0]["port"] == ssh_endpoint.port

            # HIDE: no request is sent, so nothing may change. The remote shell
            # must still answer a brand-new command (AC5).
            second = "second-" + uuid.uuid4().hex[:8]
            session.write(f"echo {second}\n")
            assert second in _read_until(session, second), "the PTY died while hidden"
            assert ssh_client.session_count(owner) == 1

            # Disconnect is the one path that ends it — via the very route the
            # UI's Disconnect button calls.
            r = client.delete(f"/api/ssh/servers/{srv['id']}/terminal/{sid}")
            assert r.json() == {"ok": True}, r.text
            assert ssh_client.session_count(owner) == 0
            assert client.get("/api/ssh/terminals").json() == {"sessions": []}
            assert client.delete(
                f"/api/ssh/servers/{srv['id']}/terminal/{sid}").status_code == 404

            # …and the close is on the record (hash-only audit read, §8).
            closed = ssh_remote.list_audit(owner, limit=20, event="terminal_closed")
            assert [row["server_id"] for row in closed] == [srv["id"]]
            assert closed[0]["server_label"] == "Lab"
        finally:
            try:
                ssh_client.close_terminal_by_id(sid)
            except Exception:  # already closed by the assertion path above
                pass
