"""Installing the managed public key on a machine (ssh-copy-id, server-side).

The Machines area has always *shown* an `ssh-copy-id` line; `install_public_key`
runs it. Three layers, because the feature can be wrong in three ways:

* `copy_id_hint` — the copy-ready command must name the real target and port (it
  used to end in a literal ``user@host`` placeholder);
* ``INSTALL_PUBKEY_COMMAND`` — the remote script is executed **for real** here,
  locally, with ``HOME`` in a temp dir, so it is verified as a shell script:
  idempotent, byte-exact for an arbitrary key comment, and leaving sshd's 0700 /
  0600 permissions behind;
* `install_public_key` end-to-end against the in-process paramiko sshd — the
  password-only machine that motivated the feature: install with the saved
  password, then connect with a key-only row on the same host.
"""

import os
import stat
import subprocess
from contextlib import contextmanager

import pytest

from src import ssh_remote
from tests.helpers.paramiko_sshd import authorized_blob_for, paramiko_sshd  # noqa: F401


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


def _machine(owner, endpoint, **over):
    fields = dict(label="box", host=endpoint.host, port=endpoint.port,
                  username=endpoint.username, auth_type="password",
                  password=endpoint.password)
    fields.update(over)
    return ssh_remote.create_server(owner, **fields)


class TestCopyIdHint:
    def test_names_the_real_target_and_omits_the_default_port(self):
        srv = {"username": "dean", "host": "pluto3", "port": 22}
        assert ssh_remote.copy_id_hint(srv, "/data/ssh/dean_ed25519.pub") == \
            "ssh-copy-id -i /data/ssh/dean_ed25519.pub dean@pluto3"

    def test_carries_a_non_default_port(self):
        srv = {"username": "dean", "host": "pluto3", "port": 2222}
        assert ssh_remote.copy_id_hint(srv, "k.pub") == \
            "ssh-copy-id -i k.pub -p 2222 dean@pluto3"

    def test_without_a_username_it_is_just_the_host(self):
        assert ssh_remote.copy_id_hint({"host": "box", "port": 22}, "k.pub") == \
            "ssh-copy-id -i k.pub box"

    def test_a_placeholder_is_never_emitted(self):
        """The old literal `user@host` was copied into a shell and could only fail."""
        for srv in ({"username": "dean", "host": "pluto3", "port": 22},
                    {"host": "pluto3", "port": 22}):
            assert "user@host" not in ssh_remote.copy_id_hint(srv, "k.pub")


class TestInstallScript:
    """The remote script, executed locally with HOME in a temp dir."""

    def _run(self, home, stdin_text):
        return subprocess.run(
            ssh_remote.INSTALL_PUBKEY_COMMAND, shell=True, input=stdin_text,
            capture_output=True, text=True, timeout=30,
            env=dict(os.environ, HOME=str(home)))

    def test_adds_the_key_once_then_reports_already_present(self, tmp_path):
        home = tmp_path / "remote"
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIblob== bob@laptop"
        first = self._run(home, key + "\n")
        assert first.returncode == 0 and first.stdout.strip() == "added"
        second = self._run(home, key + "\n")
        assert second.returncode == 0 and second.stdout.strip() == "already-present"

        authorized = home / ".ssh" / "authorized_keys"
        assert authorized.read_text(encoding="utf-8") == key + "\n"

    def test_leaves_the_permissions_sshd_requires(self, tmp_path):
        home = tmp_path / "remote"
        assert self._run(home, "ssh-ed25519 AAAA== x\n").returncode == 0
        assert stat.S_IMODE((home / ".ssh").stat().st_mode) == 0o700
        assert stat.S_IMODE((home / ".ssh" / "authorized_keys").stat().st_mode) == 0o600

    def test_a_comment_with_shell_metacharacters_is_stored_byte_exact(self, tmp_path):
        home = tmp_path / "remote"
        key = "ssh-ed25519 AAAA== dean@pluto3 '); rm -rf $HOME; echo '"
        assert self._run(home, key + "\n").returncode == 0
        assert (home / ".ssh" / "authorized_keys").read_text(encoding="utf-8") == key + "\n"

    def test_empty_stdin_writes_nothing_and_fails(self, tmp_path):
        home = tmp_path / "remote"
        r = self._run(home, "\n")
        assert r.returncode != 0 and "no public key" in r.stderr
        assert not (home / ".ssh" / "authorized_keys").exists()


class TestInstallWithoutCredentials:
    def test_no_password_and_no_private_key_is_refused(self, ssh_db):
        # A public key with no private half: `generate_user_key` reuses it, so
        # this is the one way to reach the "nothing to sign in with" branch.
        paths = ssh_remote.user_key_paths("alice")
        paths["public"].write_text("ssh-ed25519 AAAA== alice@laptop\n", encoding="utf-8")
        srv = ssh_remote.create_server("alice", label="box", host="box",
                                       auth_type="key", username="alice")
        res = ssh_remote.install_public_key("alice", srv["id"])
        assert res["ok"] is False
        assert "no stored password and no SSH key" in res["error"]


@pytest.mark.ssh_integration
class TestInstallAgainstAPasswordMachine:
    """The whole point: a machine whose only working credential is a password."""

    def test_password_install_then_key_only_login_works(self, ssh_db, paramiko_sshd):
        endpoint = paramiko_sshd(password="hunter2")
        pw_row = _machine("alice", endpoint)

        res = ssh_remote.install_public_key("alice", pw_row["id"])
        assert res["ok"] is True, res
        assert res["installed"] is True and res["pinned"] is True

        pub = ssh_remote.user_key_paths("alice")["public"].read_text(encoding="utf-8")
        assert authorized_blob_for(pub) in endpoint.authorized_keys()
        assert stat.S_IMODE(endpoint.authorized_keys_path.stat().st_mode) == 0o600

        # A second row for the same machine that offers the key and nothing else:
        # before the install this could only fail, which is exactly the state
        # users describe as "SSH won't connect without a key".
        key_row = _machine("alice", endpoint, label="box-key", auth_type="key",
                           password="")
        test = ssh_remote.test_connection("alice", key_row["id"])
        assert test["ok"] is True, test
        out = ssh_remote.exec_one_shot("alice", key_row["id"], "echo key-login-ok")
        assert out["exit_code"] == 0 and "key-login-ok" in out["output"], out

    def test_installing_twice_reports_the_key_was_already_there(self, ssh_db, paramiko_sshd):
        endpoint = paramiko_sshd(password="hunter2")
        srv = _machine("alice", endpoint)
        assert ssh_remote.install_public_key("alice", srv["id"])["installed"] is True
        again = ssh_remote.install_public_key("alice", srv["id"])
        assert again["ok"] is True and again["installed"] is False
        assert endpoint.authorized_keys().count("ssh-ed25519") == 1

    def test_a_wrong_password_installs_nothing(self, ssh_db, paramiko_sshd):
        endpoint = paramiko_sshd(password="hunter2")
        srv = _machine("alice", endpoint, password="not-the-password")
        res = ssh_remote.install_public_key("alice", srv["id"])
        assert res["ok"] is False and res["exit_code"] != 0
        assert "hint" in res
        assert endpoint.authorized_keys() == ""
        assert not endpoint.authorized_keys_path.exists()

    def test_the_pin_is_recorded_so_later_exec_is_not_blocked(self, ssh_db, paramiko_sshd):
        """Exec refuses an unpinned machine; install must leave it usable."""
        endpoint = paramiko_sshd(password="hunter2")
        srv = _machine("alice", endpoint)
        blocked = ssh_remote.exec_one_shot("alice", srv["id"], "echo too-early")
        assert blocked["exit_code"] == 1 and "run Test first" in blocked["error"]

        assert ssh_remote.install_public_key("alice", srv["id"])["pinned"] is True
        after = ssh_remote.exec_one_shot("alice", srv["id"], "echo now-ok")
        assert after["exit_code"] == 0 and "now-ok" in after["output"], after

    def test_the_audit_row_records_the_install(self, ssh_db, paramiko_sshd):
        endpoint = paramiko_sshd(password="hunter2")
        srv = _machine("alice", endpoint)
        ssh_remote.install_public_key("alice", srv["id"])
        events = [r["event"] for r in ssh_remote.list_audit("alice")]
        assert "key_install" in events
