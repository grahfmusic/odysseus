"""Phase-2 credential paths: password auth, SFTP, terminal, pin invalidation.

The transports are stubbed — what is under test is the *policy* in
``src.ssh_remote``: which transport a server's auth_type selects, that a
password is handed to paramiko rather than assembled into an argv, that a
timeout is reported as an error instead of hanging, and that re-pointing a row
drops the old host's pinned key.
"""

from contextlib import contextmanager

import base64
import types

import pytest

from src import ssh_client, ssh_remote
from tests.helpers.ssh_fixture import has_sftp, ssh_endpoint  # noqa: F401 (fixtures)


@pytest.fixture
def ssh_db(monkeypatch, tmp_path):
    """Isolate core.database + DATA_DIR per test (same shape as test_ssh_servers)."""
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


def _install_key(owner="alice"):
    """Create the managed private key so key-based plans are usable."""
    paths = ssh_remote.user_key_paths(owner)
    paths["private"].write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n", encoding="utf-8")
    paths["private"].chmod(0o600)
    return paths


def _pin(owner, server_id, fingerprints="SHA256:pin"):
    """Pin a fingerprint directly (skips the network Test step)."""
    with ssh_remote._session() as db:
        from core.database import SshServer
        row = db.query(SshServer).filter(SshServer.id == server_id).first()
        row.host_key_fingerprint = fingerprints


class TestResolveAuth:
    def test_key_auth_uses_argv_path(self, ssh_db):
        _install_key()
        plan, err = ssh_remote._resolve_auth(
            "alice", {"auth_type": "key", "username": "a"}, {})
        assert err == "" and plan == {"paramiko": False, "password": "",
                                      "key_path": ssh_remote.user_key_paths("alice")["private"]}

    def test_key_auth_without_a_key_is_an_error(self, ssh_db):
        plan, err = ssh_remote._resolve_auth(
            "alice", {"auth_type": "key", "username": "a"}, {})
        assert plan is None and "generate one first" in err

    def test_password_auth_requires_a_stored_password(self, ssh_db):
        plan, err = ssh_remote._resolve_auth(
            "alice", {"auth_type": "password", "username": "a"}, {})
        assert plan is None and "no password stored" in err

    def test_password_auth_requires_a_username(self, ssh_db):
        plan, err = ssh_remote._resolve_auth(
            "alice", {"auth_type": "password", "username": ""}, {"password": "pw"})
        assert plan is None and "username is required" in err

    def test_password_auth_selects_paramiko_without_a_key(self, ssh_db):
        plan, err = ssh_remote._resolve_auth(
            "alice", {"auth_type": "password", "username": "a"}, {"password": "pw"})
        assert err == "" and plan["paramiko"] is True
        assert plan["password"] == "pw" and plan["key_path"] is None

    def test_both_prefers_the_password_transport_with_the_key_attached(self, ssh_db):
        _install_key()
        plan, _ = ssh_remote._resolve_auth(
            "alice", {"auth_type": "both", "username": "a"}, {"password": "pw"})
        assert plan["paramiko"] is True and plan["password"] == "pw"
        assert plan["key_path"] is not None

    def test_both_without_a_password_falls_back_to_the_key(self, ssh_db):
        _install_key()
        plan, _ = ssh_remote._resolve_auth(
            "alice", {"auth_type": "both", "username": "a"}, {})
        assert plan == {"paramiko": False, "password": "",
                        "key_path": ssh_remote.user_key_paths("alice")["private"]}

    def test_terminal_forces_paramiko_even_for_a_key_only_server(self, ssh_db):
        _install_key()
        plan, err = ssh_remote._resolve_auth(
            "alice", {"auth_type": "key", "username": "a"}, {}, force_paramiko=True)
        assert err == "" and plan["paramiko"] is True and plan["password"] == ""

    def test_both_without_credentials_is_an_error(self, ssh_db):
        plan, err = ssh_remote._resolve_auth(
            "alice", {"auth_type": "both", "username": "a"}, {})
        assert plan is None and "no password stored and no SSH key" in err


class TestCollectPins:
    def test_prefers_the_full_keyscan_set(self, ssh_db, monkeypatch):
        monkeypatch.setattr(ssh_remote, "capture_host_key", lambda h, p: {
            "lines": ["box ssh-ed25519 AAA", "box ssh-rsa BBB"],
            "fingerprints": ["SHA256:ed", "SHA256:rsa"], "fingerprint": "SHA256:ed"})
        prints, lines, primary = ssh_remote._collect_pins("box", 22)
        assert prints == ["SHA256:ed", "SHA256:rsa"] and primary == "SHA256:ed"
        assert lines == ["box ssh-ed25519 AAA", "box ssh-rsa BBB"]

    def test_negotiated_key_is_added_when_missing_from_the_scan(self, ssh_db, monkeypatch):
        monkeypatch.setattr(ssh_remote, "capture_host_key", lambda h, p: {
            "lines": ["box ssh-rsa BBB"], "fingerprints": ["SHA256:rsa"],
            "fingerprint": "SHA256:rsa"})
        prints, lines, primary = ssh_remote._collect_pins(
            "box", 22, fallback_fingerprint="SHA256:ed", fallback_line="box ssh-ed25519 AAA")
        assert prints == ["SHA256:ed", "SHA256:rsa"] and primary == "SHA256:ed"

    def test_falls_back_to_the_negotiated_key_without_keyscan(self, ssh_db, monkeypatch):
        def boom(h, p):
            raise RuntimeError("ssh-keyscan not found — install openssh-client")
        monkeypatch.setattr(ssh_remote, "capture_host_key", boom)
        prints, lines, primary = ssh_remote._collect_pins(
            "box", 22, fallback_fingerprint="SHA256:ed", fallback_line="box ssh-ed25519 AAA")
        assert prints == ["SHA256:ed"] and primary == "SHA256:ed"
        assert lines == ["box ssh-ed25519 AAA"]

    def test_without_a_fallback_a_scan_failure_propagates(self, ssh_db, monkeypatch):
        monkeypatch.setattr(ssh_remote, "capture_host_key",
                            lambda h, p: (_ for _ in ()).throw(RuntimeError("nope")))
        with pytest.raises(RuntimeError):
            ssh_remote._collect_pins("box", 22)


class TestPasswordTestConnection:
    def _server(self, owner="alice", **kw):
        kw.setdefault("username", "alice")
        return ssh_remote.create_server(owner, label="Box", host="box", port=2222, **kw)

    def test_pins_the_negotiated_key_and_writes_the_pin_file(self, ssh_db, monkeypatch):
        srv = self._server(auth_type="password", password="pw")
        monkeypatch.setattr(ssh_remote, "capture_host_key",
                            lambda h, p: (_ for _ in ()).throw(RuntimeError("no keyscan")))
        monkeypatch.setattr(ssh_client, "test_login", lambda *a, **kw: {
            "ok": True, "exit_code": 0, "stderr": "", "latency_ms": 5,
            "fingerprint": "SHA256:fp1", "key_line": "box ssh-ed25519 AAA"})
        res = ssh_remote.test_connection("alice", srv["id"])
        assert res["ok"] is True and res["pinned"] is True and res["latency_ms"] == 5
        assert ssh_remote.resolve_server("alice", srv["id"])["host_key_fingerprint"] == "SHA256:fp1"
        pin = ssh_remote._pinned_known_hosts_path(srv["id"])
        assert "box ssh-ed25519 AAA" in pin.read_text(encoding="utf-8")

    def test_pins_every_key_type_reported_by_keyscan(self, ssh_db, monkeypatch):
        srv = self._server(auth_type="password", password="pw")
        monkeypatch.setattr(ssh_remote, "capture_host_key", lambda h, p: {
            "lines": ["box ssh-ed25519 AAA", "box ssh-rsa BBB"],
            "fingerprints": ["SHA256:ed", "SHA256:rsa"], "fingerprint": "SHA256:ed"})
        monkeypatch.setattr(ssh_client, "test_login", lambda *a, **kw: {
            "ok": True, "exit_code": 0, "stderr": "", "latency_ms": 1,
            "fingerprint": "SHA256:ed", "key_line": "box ssh-ed25519 AAA"})
        ssh_remote.test_connection("alice", srv["id"])
        stored = ssh_remote.resolve_server("alice", srv["id"])["host_key_fingerprint"]
        assert stored == "SHA256:ed,SHA256:rsa"

    def test_changed_host_key_fails_closed(self, ssh_db, monkeypatch):
        srv = self._server(auth_type="password", password="pw")
        _pin("alice", srv["id"], "SHA256:old")
        def _boom(*a, **kw):
            raise ssh_client.HostKeyChangedError("HOST KEY CHANGED — refusing to connect.")
        monkeypatch.setattr(ssh_client, "test_login", _boom)
        res = ssh_remote.test_connection("alice", srv["id"])
        assert res["ok"] is False and "CHANGED" in res["error"]
        # The bad result did not overwrite the pin.
        assert ssh_remote.resolve_server("alice", srv["id"])["host_key_fingerprint"] == "SHA256:old"

    def test_auth_failure_is_reported_without_a_traceback(self, ssh_db, monkeypatch):
        srv = self._server(auth_type="password", password="pw")
        def _boom(*a, **kw):
            raise ssh_client.SshClientError("AuthenticationException: Authentication failed.")
        monkeypatch.setattr(ssh_client, "test_login", _boom)
        res = ssh_remote.test_connection("alice", srv["id"])
        assert res["ok"] is False and "Authentication failed" in res["error"]
        assert "Traceback" not in res["error"]

    def test_remote_failure_surfaces_stderr(self, ssh_db, monkeypatch):
        srv = self._server(auth_type="password", password="pw")
        monkeypatch.setattr(ssh_client, "test_login", lambda *a, **kw: {
            "ok": False, "exit_code": 1, "stderr": "permission denied",
            "latency_ms": 1, "fingerprint": "SHA256:fp", "key_line": "box ssh-ed25519 AAA"})
        res = ssh_remote.test_connection("alice", srv["id"])
        assert res["ok"] is False and res["error"] == "permission denied"

    def test_missing_password_is_reported_before_dialling(self, ssh_db, monkeypatch):
        srv = self._server(auth_type="password")
        monkeypatch.setattr(ssh_client, "test_login",
                            lambda *a, **kw: pytest.fail("must not dial without a password"))
        res = ssh_remote.test_connection("alice", srv["id"])
        assert res["ok"] is False and "no password stored" in res["error"]


class TestPasswordExec:
    def _pinned_password_server(self, **kw):
        srv = ssh_remote.create_server("alice", label="Box", host="box", port=22,
                                       username="alice", auth_type="password",
                                       password="pw", **kw)
        _pin("alice", srv["id"])
        return srv

    def test_password_is_passed_to_paramiko_and_output_returned(self, ssh_db, monkeypatch):
        srv = self._pinned_password_server()
        seen = {}

        def _run(host, port, username, cmd, **kw):
            seen.update({"host": host, "port": port, "user": username, "cmd": cmd, **kw})
            return {"stdout": "ok\n", "stderr": "", "exit_code": 0}
        monkeypatch.setattr(ssh_client, "run_command", _run)
        res = ssh_remote.exec_one_shot("alice", srv["id"], "echo ok")
        assert res["exit_code"] == 0 and res["output"] == "ok\n"
        assert seen["password"] == "pw" and seen["cmd"] == "echo ok"
        assert seen["expected_fingerprints"] == ["SHA256:pin"]

    def test_stored_sudo_password_is_forwarded_as_an_argument_not_an_argv(self, ssh_db, monkeypatch):
        srv = self._pinned_password_server(sudo_password="sudopw")
        seen = {}
        monkeypatch.setattr(ssh_client, "run_command",
                            lambda *a, **kw: seen.update(kw) or {
                                "stdout": "", "stderr": "", "exit_code": 0})
        ssh_remote.exec_one_shot("alice", srv["id"], "sudo whoami")
        assert seen["sudo_password"] == "sudopw"

    def test_timeout_maps_to_exit_code_124(self, ssh_db, monkeypatch):
        srv = self._pinned_password_server()
        def _boom(*a, **kw):
            raise ssh_client.SshTimeoutError("command timed out after 5s")
        monkeypatch.setattr(ssh_client, "run_command", _boom)
        res = ssh_remote.exec_one_shot("alice", srv["id"], "sleep 99", timeout=5)
        assert res["exit_code"] == 124 and "timed out" in res["error"]

    def test_unpinned_server_refuses_before_connecting(self, ssh_db, monkeypatch):
        srv = ssh_remote.create_server("alice", label="B", host="box", username="a",
                                       auth_type="password", password="pw")
        monkeypatch.setattr(ssh_client, "run_command",
                            lambda *a, **kw: pytest.fail("must not connect unpinned"))
        res = ssh_remote.exec_one_shot("alice", srv["id"], "id")
        assert res["exit_code"] == 1 and "run Test first" in res["error"]

    def test_transport_error_is_reported_cleanly(self, ssh_db, monkeypatch):
        srv = self._pinned_password_server()
        def _boom(*a, **kw):
            raise ssh_client.SshClientError("AuthenticationException: nope")
        monkeypatch.setattr(ssh_client, "run_command", _boom)
        res = ssh_remote.exec_one_shot("alice", srv["id"], "id")
        assert res["exit_code"] == 1 and "AuthenticationException" in res["error"]


class TestSudoPiping:
    """§6.2: the stored sudo password goes over stdin on *both* transports."""

    def test_paramiko_path_uses_sudo_s_not_an_argv(self, ssh_db, monkeypatch):
        srv = ssh_remote.create_server("alice", label="B", host="box", username="a",
                                       auth_type="password", password="pw",
                                       sudo_password="s3cret")
        _pin("alice", srv["id"])
        seen = {}
        monkeypatch.setattr(ssh_client, "run_command",
                            lambda *a, **kw: seen.update(kw) or {
                                "stdout": "", "stderr": "", "exit_code": 0})
        ssh_remote.exec_one_shot("alice", srv["id"], "sudo whoami")
        assert seen["sudo_password"] == "s3cret"

    def test_argv_path_pipes_the_sudo_password_on_stdin(self, ssh_db, monkeypatch):
        """Key-only servers keep the argv transport, but the secret still must not
        appear in the command line — it is rewritten to `sudo -S` and fed on stdin."""
        _install_key()
        srv = ssh_remote.create_server("alice", label="B", host="box", username="a",
                                       auth_type="key", sudo_password="s3cret")
        _pin("alice", srv["id"])
        assert ssh_remote._resolve_auth(
            "alice", ssh_remote.resolve_server("alice", srv["id"]),
            {"password": "", "sudo_password": "s3cret"})[0]["paramiko"] is False
        seen = {}

        class _Result:
            returncode = 0
            stdout = "ok\n"
            stderr = ""

        def _run(argv, **kw):
            seen["argv"] = argv
            seen["input"] = kw.get("input")
            return _Result()

        monkeypatch.setattr(ssh_remote, "subprocess", types.SimpleNamespace(run=_run))
        res = ssh_remote.exec_one_shot("alice", srv["id"], "sudo whoami")
        assert res["exit_code"] == 0, res
        assert seen["argv"][-1] == "sudo -S -p \'\' whoami", seen["argv"]
        assert seen["input"] == "s3cret\n", seen
        assert not any("s3cret" in str(a) for a in seen["argv"]), seen["argv"]

    def test_argv_path_without_a_stored_password_leaves_the_command_alone(self, ssh_db, monkeypatch):
        _install_key()
        srv = ssh_remote.create_server("alice", label="B", host="box", username="a",
                                       auth_type="key")
        _pin("alice", srv["id"])
        seen = {}

        class _Result:
            returncode = 0
            stdout = ""
            stderr = ""

        def _run(argv, **kw):
            seen["argv"] = argv
            seen["input"] = kw.get("input")
            return _Result()

        monkeypatch.setattr(ssh_remote, "subprocess", types.SimpleNamespace(run=_run))
        ssh_remote.exec_one_shot("alice", srv["id"], "sudo whoami")
        # No stored password means the remote host decides (it may have NOPASSWD).
        assert seen["argv"][-1] == "sudo whoami"
        assert seen["input"] is None


class TestPasswordTransfer:
    def test_paramiko_transfer_passes_the_password_and_paths(self, ssh_db, monkeypatch, tmp_path):
        srv = ssh_remote.create_server("alice", label="B", host="box", username="a",
                                       auth_type="password", password="pw")
        _pin("alice", srv["id"])
        seen = {}
        monkeypatch.setattr(ssh_client, "sftp_transfer",
                            lambda host, port, user, direction, **kw:
                            seen.update({"direction": direction, **kw}) or {"ok": True})
        local = tmp_path / "f.txt"
        local.write_text("hi", encoding="utf-8")
        res = ssh_remote.transfer("alice", srv["id"], "upload", str(local), "/tmp/f.txt")
        assert res["exit_code"] == 0 and seen["direction"] == "upload"
        assert seen["password"] == "pw" and seen["remote_path"] == "/tmp/f.txt"


class TestTerminalApi:
    def test_open_requires_a_pin(self, ssh_db, monkeypatch):
        srv = ssh_remote.create_server("alice", label="B", host="box", username="a",
                                       auth_type="password", password="pw")
        monkeypatch.setattr(ssh_client, "open_terminal",
                            lambda *a, **kw: pytest.fail("must not connect unpinned"))
        with pytest.raises(ValueError, match="run Test first"):
            ssh_remote.open_terminal_for("alice", srv["id"])

    def test_open_returns_the_session_and_audits(self, ssh_db, monkeypatch):
        _install_key()
        srv = ssh_remote.create_server("alice", label="Box", host="box", port=22,
                                       username="a", auth_type="key")
        _pin("alice", srv["id"])
        fake = type("S", (), {"id": "sess123"})()
        seen = {}
        monkeypatch.setattr(ssh_client, "open_terminal",
                            lambda owner, host, port, user, **kw:
                            seen.update({"owner": owner, "host": host, **kw}) or fake)
        info = ssh_remote.open_terminal_for("alice", srv["id"], cols=90, rows=20)
        assert info["session_id"] == "sess123" and info["target"] == "a@box"
        assert seen["expected_fingerprints"] == ["SHA256:pin"]
        assert seen["cols"] == 90 and seen["rows"] == 20
        with ssh_remote._session() as db:
            from core.database import SshAuditLog
            events = [r.event for r in db.query(SshAuditLog).all()]
        assert "terminal_open" in events

    def test_close_audits_and_is_owner_scoped(self, ssh_db, monkeypatch):
        seen = {}

        class _Session:
            server_id = "srv1"
        monkeypatch.setattr(ssh_client, "get_terminal", lambda owner, sid: _Session())
        monkeypatch.setattr(ssh_client, "close_terminal",
                            lambda owner, sid: seen.update({"owner": owner, "sid": sid}))
        monkeypatch.setattr(ssh_remote, "audit",
                            lambda owner, sid, event, cmd, code: seen.update({"event": event}))
        ssh_remote.close_terminal_for("alice", "sess1")
        assert seen["owner"] == "alice" and seen["sid"] == "sess1"
        assert seen["event"] == "terminal_closed"

    def test_close_unknown_session_raises_lookup(self, ssh_db, monkeypatch):
        monkeypatch.setattr(ssh_client, "get_terminal",
                            lambda owner, sid: (_ for _ in ()).throw(LookupError("gone")))
        with pytest.raises(LookupError):
            ssh_remote.close_terminal_for("alice", "zz")


class TestPinInvalidation:
    def test_repointing_the_host_clears_the_pin_and_the_file(self, ssh_db):
        srv = ssh_remote.create_server("alice", label="B", host="box")
        _pin("alice", srv["id"], "SHA256:old")
        pin = ssh_remote._pinned_known_hosts_path(srv["id"])
        pin.parent.mkdir(parents=True, exist_ok=True)
        pin.write_text("box ssh-ed25519 AAA\n", encoding="utf-8")

        updated = ssh_remote.update_server("alice", srv["id"], host="other-box")
        assert updated["host_key_fingerprint"] is None
        assert updated["last_test_result"] is None
        assert pin.exists() is False

    def test_changing_only_the_label_keeps_the_pin(self, ssh_db):
        srv = ssh_remote.create_server("alice", label="B", host="box")
        _pin("alice", srv["id"], "SHA256:old")
        updated = ssh_remote.update_server("alice", srv["id"], label="Renamed")
        assert updated["host_key_fingerprint"] == "SHA256:old"

    def test_changing_the_port_clears_the_pin(self, ssh_db):
        srv = ssh_remote.create_server("alice", label="B", host="box", port=22)
        _pin("alice", srv["id"], "SHA256:old")
        assert ssh_remote.update_server("alice", srv["id"], port=2222)["host_key_fingerprint"] is None


@pytest.mark.ssh_integration
class TestParamikoAgainstRealSshd:
    """The paramiko path end-to-end against the fixture's real sshd (skipped if none).

    auth_type ``both`` with a deliberately wrong password proves paramiko is
    really in use (OpenSSH argv has no password concept) while the key carries
    the login, and exercises connect → fingerprint → exec → SFTP → terminal.
    """

    def _provision(self, ssh_endpoint, tmp_path):
        import shutil
        import subprocess
        owner = "alice"
        paths = ssh_remote.user_key_paths(owner)
        paths["private"].write_bytes(ssh_endpoint.private_key.read_bytes())
        paths["private"].chmod(0o600)
        if shutil.which("ssh-keygen"):
            r = subprocess.run(["ssh-keygen", "-y", "-f", str(paths["private"])],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                paths["public"].write_text(r.stdout.strip() + "\n", encoding="utf-8")
        return ssh_remote.create_server(
            owner, label="PK", host=ssh_endpoint.host, port=ssh_endpoint.port,
            username=ssh_endpoint.user, auth_type="both", password="not-the-password")

    def test_paramiko_test_and_exec(self, ssh_db, ssh_endpoint, tmp_path):
        srv = self._provision(ssh_endpoint, tmp_path)
        first = ssh_remote.test_connection("alice", srv["id"])
        assert first["ok"] is True, first
        assert first["fingerprint"].startswith("SHA256:")

        res = ssh_remote.exec_one_shot("alice", srv["id"], "echo paramiko-ok")
        assert res["exit_code"] == 0 and "paramiko-ok" in res["output"], res

        # The pin is enforced on later connections too, not just the first.
        with ssh_remote._session() as db:
            from core.database import SshServer
            row = db.query(SshServer).filter(SshServer.id == srv["id"]).first()
            row.host_key_fingerprint = "SHA256:bogus"
        changed = ssh_remote.exec_one_shot("alice", srv["id"], "echo nope")
        assert changed["exit_code"] == 1 and "CHANGED" in changed["error"]

    def test_paramiko_sftp_round_trip(self, ssh_db, ssh_endpoint, tmp_path):
        if not has_sftp:
            pytest.skip("no sftp-server binary — the fixture sshd has no sftp subsystem")
        srv = self._provision(ssh_endpoint, tmp_path)
        assert ssh_remote.test_connection("alice", srv["id"])["ok"] is True

        local = tmp_path / "up.txt"
        local.write_text("payload\n", encoding="utf-8")
        remote_path = f"/tmp/odysseus-sftp-{srv['id']}.txt"
        try:
            up = ssh_remote.transfer("alice", srv["id"], "upload", str(local), remote_path)
            assert up["exit_code"] == 0, up
            back = tmp_path / "down.txt"
            down = ssh_remote.transfer("alice", srv["id"], "download", str(back), remote_path)
            assert down["exit_code"] == 0, down
            assert back.read_text(encoding="utf-8") == "payload\n"
        finally:
            import os
            try:
                os.unlink(remote_path)
            except OSError:
                pass

    def test_terminal_relay_round_trip(self, ssh_db, ssh_endpoint, tmp_path):
        srv = self._provision(ssh_endpoint, tmp_path)
        assert ssh_remote.test_connection("alice", srv["id"])["ok"] is True
        info = ssh_remote.open_terminal_for("alice", srv["id"], cols=100, rows=30)
        try:
            session = ssh_client.get_terminal("alice", info["session_id"])
            session.write("echo terminal-ok\n")
            collected = ""
            for _ in range(60):
                chunk = session.read(wait=0.25)
                if chunk is None:
                    break
                collected += chunk
                if "terminal-ok" in collected:
                    break
            assert "terminal-ok" in collected
        finally:
            ssh_remote.close_terminal_for("alice", info["session_id"])
        with pytest.raises(LookupError):
            ssh_client.get_terminal("alice", info["session_id"])
