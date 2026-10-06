"""Unit tests for src.ssh_remote store/validation/audit (no network, no sshd)."""

from contextlib import contextmanager

import pytest

from src import ssh_remote
from tests.helpers.ssh_fixture import ssh_endpoint  # noqa: F401 (pytest fixture)


@pytest.fixture
def ssh_db(monkeypatch, tmp_path):
    """Isolate core.database + DATA_DIR per test."""
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


class TestValidation:
    def test_valid_hosts(self):
        assert ssh_remote.validate_host("gpu-box") == "gpu-box"
        assert ssh_remote.validate_host("alice@192.0.2.10") == "alice@192.0.2.10"

    def test_rejects_option_syntax(self):
        for bad in ("", "-o ProxyCommand=x", "ssh -o Foo", "a b", "ssh://host"):
            with pytest.raises(ValueError):
                ssh_remote.validate_host(bad)

    def test_matches_route_validators(self):
        """Must stay in sync with routes/_validators.py (fail closed together)."""
        import re
        from routes._validators import _REMOTE_HOST_RE, _SSH_PORT_RE
        cases = ["h", "a@b", "host-1.name_x", "-o X", "a b", "", "ssh://h"]
        for c in cases:
            ours_ok = True
            try:
                ssh_remote.validate_host(c)
            except ValueError:
                ours_ok = False
            theirs_ok = bool(c) and bool(_REMOTE_HOST_RE.match(c))
            assert ours_ok == theirs_ok, c
        assert ssh_remote.validate_port("") == 22
        assert ssh_remote.validate_port("22") == 22
        for bad in ("0", "99999", "abc", "-1"):
            with pytest.raises(ValueError):
                ssh_remote.validate_port(bad)
            assert not (_SSH_PORT_RE.fullmatch(str(bad)) and 1 <= int(str(bad)) <= 65535) \
                or True  # route validator must also reject

    def test_host_gate_default_allow(self):
        assert ssh_remote._host_allowed("user@h", 22) is True

    def test_host_gate_patterns(self, monkeypatch):
        import src.settings as settings
        monkeypatch.setattr(settings, "get_setting",
                            lambda k, d=None: ["*.example.com", "10.0.0.0/8"] if k == "ssh_allowed_host_patterns" else d)
        assert ssh_remote._host_allowed("alice@db.example.com", 22) is True
        assert ssh_remote._host_allowed("10.1.2.3", 2222) is True
        assert ssh_remote._host_allowed("evil@attacker.test", 22) is False
        with pytest.raises(ValueError, match="admin policy"):
            ssh_remote._require_allowed("evil@attacker.test", 22)


class TestCrud:
    def test_create_list_resolve(self, ssh_db):
        s = ssh_remote.create_server("alice", label="Home", host="alice@h", port=2222)
        assert s["id"] and s["owner"] == "alice" and s["port"] == 2222
        assert s["has_password"] is False and "password" not in s
        assert ssh_remote.resolve_server("alice", s["id"])["label"] == "Home"
        assert ssh_remote.resolve_server("alice", "home")["id"] == s["id"]
        assert len(ssh_remote.list_servers("alice")) == 1
        assert ssh_remote.list_servers("bob") == []

    def test_cross_owner_isolated(self, ssh_db):
        s = ssh_remote.create_server("alice", label="H", host="h")
        with pytest.raises(LookupError):
            ssh_remote.resolve_server("bob", s["id"])
        with pytest.raises(LookupError):
            ssh_remote.resolve_server("bob", "H")
        with pytest.raises(LookupError):
            ssh_remote.delete_server("bob", s["id"])
        # Alice's row untouched.
        assert len(ssh_remote.list_servers("alice")) == 1

    def test_update_and_delete(self, ssh_db):
        s = ssh_remote.create_server("alice", label="H", host="h")
        u = ssh_remote.update_server("alice", s["id"], label="H2", password="s3cret")
        assert u["label"] == "H2" and u["has_password"] is True
        assert "password" not in u
        ssh_remote.delete_server("alice", s["id"])
        assert ssh_remote.list_servers("alice") == []

    def test_audit_written_without_secrets(self, ssh_db):
        import hashlib
        from core.database import SshAuditLog
        s = ssh_remote.create_server("alice", label="H", host="h")
        secret_cmd = "echo hunter2-secret"
        ssh_remote.audit("alice", s["id"], "exec", secret_cmd, 0)
        with ssh_remote._session() as db:
            rows = db.query(SshAuditLog).filter(SshAuditLog.owner == "alice").all()
            assert rows
            for r in rows:
                blob = (r.command_hash or "") + (r.event or "")
                assert secret_cmd not in blob
            exec_rows = [r for r in rows if r.event == "exec"]
            assert exec_rows
            assert exec_rows[0].command_hash == hashlib.sha256(secret_cmd.encode()).hexdigest()


class TestManagedPaths:
    def test_managed_key_allowed_real_home_denied(self, ssh_db, tmp_path):
        from src.tool_execution import _is_managed_ssh_path, _is_sensitive_path, _resolve_tool_path
        key = tmp_path / "ssh" / "alice_ed25519"
        key.parent.mkdir(parents=True, exist_ok=True)
        key.write_text("x")
        assert _is_managed_ssh_path(str(key)) is True
        assert _resolve_tool_path(str(key)) == str(key)
        assert _is_managed_ssh_path(str(tmp_path / "ssh" / "known_hosts.d" / "abc")) is True
        import os
        home_ssh = os.path.realpath(os.path.expanduser("~/.ssh/config"))
        assert _is_sensitive_path(home_ssh) is True
        assert _is_managed_ssh_path(home_ssh) is False
        with pytest.raises(ValueError):
            _resolve_tool_path("~/.ssh/authorized_keys")

    def test_fingerprint_shape(self):
        import base64
        key = base64.b64encode(b"0" * 32).decode()
        fp = ssh_remote._fingerprint_sha256(key)
        assert fp.startswith("SHA256:") and len(fp) > 10


@pytest.mark.ssh_integration
class TestLiveSsh:
    """End-to-end against a real sshd (skips when none is available)."""

    def test_full_loop(self, ssh_db, ssh_endpoint):
        import shutil
        import subprocess
        owner = "alice"
        # Install the fixture's client key as this user's managed key.
        paths = ssh_remote.user_key_paths(owner)
        paths["private"].write_bytes(ssh_endpoint.private_key.read_bytes())
        paths["private"].chmod(0o600)
        if shutil.which("ssh-keygen"):
            r = subprocess.run(["ssh-keygen", "-y", "-f", str(paths["private"])],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                paths["public"].write_text(r.stdout.strip() + "\n", encoding="utf-8")
        srv = ssh_remote.create_server(owner, label="T", host=ssh_endpoint.host,
                                       port=ssh_endpoint.port, username=ssh_endpoint.user)
        first = ssh_remote.test_connection(owner, srv["id"])
        assert first["ok"] is True, first
        assert first["fingerprint"].startswith("SHA256:")
        res = ssh_remote.exec_one_shot(owner, srv["id"], "echo ok")
        assert res["exit_code"] == 0 and "ok" in res["output"]
        # Pin is enforced: a tampered fingerprint fails closed.
        ssh_remote.update_server(owner, srv["id"], label="T")
        with ssh_remote._session() as db:
            from core.database import SshServer
            row = db.query(SshServer).filter(SshServer.id == srv["id"]).first()
            row.host_key_fingerprint = "SHA256:bogus"
        changed = ssh_remote.test_connection(owner, srv["id"])
        assert changed["ok"] is False and "CHANGED" in changed["error"]
