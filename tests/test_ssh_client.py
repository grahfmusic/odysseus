"""Unit tests for src/ssh_client.py — the paramiko transport, with no network.

Covers the security-critical parts: the host-key pin is enforced *before* any
credential is offered, the fingerprint format matches OpenSSH's, secrets never
reach a command line or the environment, and the terminal session cap/idle
bookkeeping behaves.
"""

import base64
import socket
import subprocess
import sys
import types
from pathlib import Path

import pytest

from src import ssh_client, ssh_remote


class _FakeKey:
    def __init__(self, blob=b"k" * 32, name="ssh-ed25519"):
        self._blob, self._name = blob, name

    def asbytes(self):
        return self._blob

    def get_name(self):
        return self._name


class _FakeChannel:
    def __init__(self, chunks=(), exit_status=0):
        self._chunks = list(chunks)
        self._exit_status = exit_status
        self.sent = []
        self.resized = []
        self.closed = False

    def recv_ready(self):
        return bool(self._chunks)

    def recv(self, n):
        return self._chunks.pop(0) if self._chunks else b""

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return self._exit_status

    def send(self, data):
        self.sent.append(data)

    def resize_pty(self, width=None, height=None):
        self.resized.append((width, height))

    def close(self):
        self.closed = True

    def settimeout(self, _t):
        pass


class _FakeSSHClient:
    """Stands in for paramiko.SSHClient; records policy, args, and lifecycle."""

    instances = []
    # Class-level hooks so a test can arm a failure for the *next* connection
    # (instance attributes would shadow them).
    connect_raises = None
    exec_raises = None
    shell_raises = None

    def __init__(self):
        _FakeSSHClient.instances.append(self)
        self.policy = None
        self.loaded = []
        self.connect_kwargs = None
        self.closed = False
        self.present = _FakeKey()
        self.channel = _FakeChannel([b"hello\n", b""])

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def load_host_keys(self, path):
        self.loaded.append(path)
        # Mirror paramiko: a file that is not known_hosts-shaped raises, and the
        # caller is expected to fail closed.
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3:
                raise ValueError("not a known_hosts file")
            try:
                base64.b64decode(parts[2])
            except Exception as exc:
                raise ValueError("not a known_hosts file") from exc

    def connect(self, host, **kwargs):
        if self.connect_raises:
            raise self.connect_raises
        self.connect_kwargs = {"host": host, **kwargs}
        if isinstance(self.policy, ssh_client._CaptureHostKeyPolicy):
            self.policy.missing_host_key(self, host, self.present)

    def get_transport(self):
        return types.SimpleNamespace(get_remote_server_key=lambda: self.present)

    def exec_command(self, cmd, timeout=None):
        if self.exec_raises:
            raise self.exec_raises
        self.exec_cmd = (cmd, timeout)
        stdin = types.SimpleNamespace(
            write=lambda d: None, flush=lambda: None,
            channel=types.SimpleNamespace(shutdown_write=lambda: None))
        stdout = types.SimpleNamespace(
            read=lambda: b"ok\n",
            channel=types.SimpleNamespace(recv_exit_status=lambda: 0))
        stderr = types.SimpleNamespace(read=lambda: b"")
        return stdin, stdout, stderr

    def invoke_shell(self, term=None, width=None, height=None):
        if self.shell_raises:
            raise self.shell_raises
        self.shell = (term, width, height)
        return self.channel

    def close(self):
        self.closed = True


@pytest.fixture
def fake_paramiko(monkeypatch, tmp_path):
    """Install a fake paramiko and an isolated DATA_DIR for pin files."""
    import src.constants as consts
    monkeypatch.setattr(consts, "DATA_DIR", str(tmp_path))
    fake = types.SimpleNamespace(SSHClient=_FakeSSHClient, RejectPolicy=lambda: "REJECT")
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    _FakeSSHClient.instances = []
    monkeypatch.setattr(_FakeSSHClient, "connect_raises", None)
    monkeypatch.setattr(_FakeSSHClient, "exec_raises", None)
    monkeypatch.setattr(_FakeSSHClient, "shell_raises", None)
    ssh_client._reset_sessions_for_tests()
    yield fake
    _FakeSSHClient.instances = []
    ssh_client._reset_sessions_for_tests()


def _pin_file(server_id):
    return ssh_remote._pinned_known_hosts_path(server_id)


class TestFingerprint:
    def test_matches_openssh_ssh_keygen(self, tmp_path):
        """Our SHA256 fingerprint must equal what `ssh-keygen -lf` reports."""
        import shutil
        if not shutil.which("ssh-keygen"):
            pytest.skip("ssh-keygen not available")
        key = tmp_path / "k"
        r = subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key)],
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        pub = key.with_suffix(".pub").read_text(encoding="utf-8").split()
        blob = base64.b64decode(pub[1])
        expected = subprocess.run(["ssh-keygen", "-lf", str(key.with_suffix(".pub"))],
                                  capture_output=True, text=True, timeout=30).stdout.split()[1]
        assert ssh_client.key_fingerprint(_FakeKey(blob, pub[0])) == expected

    def test_key_line_shape_is_known_hosts_compatible(self):
        line = ssh_client.key_line("box", _FakeKey(b"x" * 8))
        host, keytype, b64 = line.split()
        assert host == "box" and keytype == "ssh-ed25519"
        assert base64.b64decode(b64) == b"x" * 8


class TestPinFile:
    def test_pins_from_pin_file_reads_fingerprints(self, fake_paramiko):
        blob = b"z" * 32
        _pin_file("srv1").parent.mkdir(parents=True, exist_ok=True)
        _pin_file("srv1").write_text(
            f"box ssh-ed25519 {base64.b64encode(blob).decode()}\n", encoding="utf-8")
        assert ssh_client.pins_from_pin_file("srv1") == {
            ssh_client.key_fingerprint(_FakeKey(blob))}

    def test_missing_pin_file_is_empty(self, fake_paramiko):
        assert ssh_client.pins_from_pin_file("nope") == set()
        assert ssh_client.pins_from_pin_file("") == set()


class TestPinEnforcement:
    def test_first_connection_uses_capture_policy(self, fake_paramiko):
        ssh_client.connect("box", 22, "alice", password="pw")
        (client,) = _FakeSSHClient.instances
        assert isinstance(client.policy, ssh_client._CaptureHostKeyPolicy)

    def test_on_disk_pin_installs_reject_policy_before_auth(self, fake_paramiko):
        """A pin file must tighten things even when the caller passes no pins."""
        blob = b"z" * 32
        _pin_file("srv1").parent.mkdir(parents=True, exist_ok=True)
        _pin_file("srv1").write_text(
            f"box ssh-ed25519 {base64.b64encode(blob).decode()}\n", encoding="utf-8")
        with pytest.raises(ssh_client.HostKeyChangedError):
            ssh_client.connect("box", 22, "alice", password="pw", server_id="srv1")
        (client,) = _FakeSSHClient.instances
        assert client.policy == "REJECT"
        assert client.loaded and client.loaded[0].endswith("srv1")
        assert client.closed is True

    def test_matching_pin_connects(self, fake_paramiko):
        presented = _FakeKey(b"k" * 32)  # the key _FakeSSHClient presents
        client, fp, line = ssh_client._open(
            "box", 22, "alice", password="pw",
            expected_fingerprints=[ssh_client.key_fingerprint(presented)])
        assert fp == ssh_client.key_fingerprint(presented)
        assert line.startswith("box ssh-ed25519 ")
        assert client.connect_kwargs["password"] == "pw"
        client.close()

    def test_corrupt_pin_file_fails_closed(self, fake_paramiko):
        _pin_file("srv9").parent.mkdir(parents=True, exist_ok=True)
        _pin_file("srv9").write_bytes(b"\x00\x01not a known_hosts file\n")
        with pytest.raises(ssh_client.SshClientError):
            ssh_client.connect("box", 22, "alice", password="pw", server_id="srv9")

    def test_connect_failure_is_wrapped_and_client_closed(self, fake_paramiko, monkeypatch):
        def boom(self, host, **kw):
            raise OSError("connection refused")
        monkeypatch.setattr(_FakeSSHClient, "connect", boom)
        with pytest.raises(ssh_client.SshClientError, match="refused"):
            ssh_client.connect("box", 22, "alice", password="pw")
        assert _FakeSSHClient.instances[-1].closed is True

    def test_missing_credentials_is_a_clear_error(self, fake_paramiko):
        with pytest.raises(ssh_client.SshClientError, match="no password and no key"):
            ssh_client.connect("box", 22, "alice")
        with pytest.raises(ssh_client.SshClientError, match="username is required"):
            ssh_client.connect("box", 22, "", password="pw")


class TestSecretsNeverHitACommandLine:
    """The whole point of the paramiko path: no argv/environ secret surface."""

    def test_module_has_no_process_or_environment_surface(self):
        src = (ssh_remote.__file__.rsplit("/", 2)[0] + "/src/ssh_client.py")
        text = open(src, encoding="utf-8").read()
        # No way to spawn a process and no way to hand a secret to the
        # environment: the password can only travel as a paramiko argument.
        assert "import subprocess" not in text
        assert "os.environ" not in text
        assert "Popen(" not in text
        assert "from subprocess" not in text

    def test_password_is_passed_as_a_connect_kwarg(self, fake_paramiko):
        ssh_client.connect("box", 22, "alice", password="hunter2")
        (client,) = _FakeSSHClient.instances
        assert client.connect_kwargs["password"] == "hunter2"
        assert client.connect_kwargs["allow_agent"] is False
        assert client.connect_kwargs["look_for_keys"] is False


class TestRunCommand:
    def test_returns_output_and_exit_code(self, fake_paramiko):
        out = ssh_client.run_command("box", 22, "alice", "id", password="pw")
        assert out["exit_code"] == 0 and out["stdout"] == "ok\n"

    def test_socket_timeout_becomes_ssh_timeout(self, fake_paramiko, monkeypatch):
        monkeypatch.setattr(_FakeSSHClient, "exec_raises", socket.timeout("timed out"))
        with pytest.raises(ssh_client.SshTimeoutError):
            ssh_client.run_command("box", 22, "alice", "sleep 99", password="pw", timeout=3)

    def test_sudo_password_goes_to_stdin_only(self, fake_paramiko):
        cmd, stdin = ssh_client.apply_sudo("sudo rm -rf /tmp/x", "s3cret")
        assert cmd == "sudo -S -p '' rm -rf /tmp/x"
        assert stdin == "s3cret\n"
        assert "s3cret" not in cmd

    @pytest.mark.parametrize("cmd,expected", [
        ("ls", "ls"),
        ("echo sudo", "echo sudo"),
        ("sudo -S whoami", "sudo -S whoami"),
        ("sudo -A whoami", "sudo -A whoami"),
        ("", ""),
    ])
    def test_apply_sudo_leaves_other_commands_alone(self, cmd, expected):
        assert ssh_client.apply_sudo(cmd, "pw")[0] == expected

    def test_apply_sudo_without_a_password_is_a_noop(self):
        assert ssh_client.apply_sudo("sudo whoami", "") == ("sudo whoami", "")


class TestTestLogin:
    def test_returns_fingerprint_line_and_latency(self, fake_paramiko):
        res = ssh_client.test_login("box", 22, "alice", password="pw")
        assert res["ok"] is True and res["latency_ms"] >= 0
        assert res["fingerprint"].startswith("SHA256:")
        assert res["key_line"].startswith("box ssh-ed25519 ")


class TestTerminal:
    def _patch_connect(self, monkeypatch):
        def _connect(host, port, username, **kw):
            client = _FakeSSHClient()
            client.connect(host, username=username, port=port, **kw)
            return client
        monkeypatch.setattr(ssh_client, "connect", _connect)

    def test_session_cap_and_close(self, fake_paramiko, monkeypatch):
        self._patch_connect(monkeypatch)
        sessions = [ssh_client.open_terminal("alice", "box", 22, "a", password="pw")
                    for _ in range(ssh_client.MAX_TERMINAL_SESSIONS_PER_USER)]
        assert ssh_client.session_count("alice") == 3
        with pytest.raises(ssh_client.SshClientError, match="too many open terminals"):
            ssh_client.open_terminal("alice", "box", 22, "a", password="pw")
        # A different owner has their own budget.
        ssh_client.open_terminal("bob", "box", 22, "b", password="pw")
        ssh_client.close_terminal("alice", sessions[0].id)
        assert ssh_client.session_count("alice") == 2
        again = ssh_client.open_terminal("alice", "box", 22, "a", password="pw")
        assert again.id not in [s.id for s in sessions]

    def test_get_terminal_is_owner_scoped(self, fake_paramiko, monkeypatch):
        self._patch_connect(monkeypatch)
        session = ssh_client.open_terminal("alice", "box", 22, "a", password="pw")
        assert ssh_client.get_terminal("alice", session.id) is session
        with pytest.raises(LookupError):
            ssh_client.get_terminal("bob", session.id)
        with pytest.raises(LookupError):
            ssh_client.close_terminal("bob", session.id)

    def test_write_and_resize_reach_the_channel(self, fake_paramiko, monkeypatch):
        self._patch_connect(monkeypatch)
        session = ssh_client.open_terminal("alice", "box", 22, "a", password="pw",
                                           cols=111, rows=22)
        channel = session._channel
        assert channel is not None and session.write("ls\n") is None
        session.resize(120, 40)
        assert channel.sent == ["ls\n"]
        assert channel.resized == [(120, 40)]

    def test_idle_sessions_are_reaped(self, fake_paramiko, monkeypatch):
        self._patch_connect(monkeypatch)
        session = ssh_client.open_terminal("alice", "box", 22, "a", password="pw")
        session.last_activity -= ssh_client.TERMINAL_IDLE_KILL_S + 1
        assert ssh_client._reap_idle() == [session.id]
        assert ssh_client.session_count("alice") == 0

    def test_read_returns_none_at_eof_and_text_when_ready(self):
        session = ssh_client.TerminalSession(
            "alice", "s1", types.SimpleNamespace(close=lambda: None),
            _FakeChannel([b"hi\n", b""]))
        assert session.read(wait=0) == "hi\n"
        assert session.read(wait=0) is None

    def test_read_returns_none_when_closed_process_has_no_output(self):
        session = ssh_client.TerminalSession(
            "alice", "s1", types.SimpleNamespace(close=lambda: None), _FakeChannel([]))
        assert session.read(wait=0) is None

    def test_close_is_idempotent(self):
        client = types.SimpleNamespace(close=lambda: None)
        channel = _FakeChannel([])
        session = ssh_client.TerminalSession("alice", "s1", client, channel)
        session.close()
        session.close()
        assert channel.closed is True and session.closed is True
