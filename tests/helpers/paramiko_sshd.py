"""A throwaway in-process SSH server for the password-auth paths.

`tests/helpers/ssh_fixture.py` runs a real OpenSSH sshd, but it has to set
`PasswordAuthentication no`: a non-root sshd cannot read `/etc/shadow`, so no
password can ever verify. That leaves the half of Phase 2 that exists *because*
of passwords (`src/ssh_client.py`) with no end-to-end coverage at all — and it
is exactly the half a user hits when they save a machine with a password.

This fixture speaks SSH with paramiko's own server side (already a runtime
dependency), accepting a fixed password and/or a fixed public key, and runs
`exec` requests through the local shell with **HOME pointed at a temporary
directory**. That last part matters twice over:

* `~/.ssh/authorized_keys` on the "remote" resolves inside `tmp_path`, so a
  test can install a key against a throwaway home and never touch the real one;
* the command the app sends is executed for real, so the install script is
  verified as a shell script and not merely compared to a string.

Only what the SSH paths under test need is implemented: password/publickey
auth, `exec`, and a piped `shell`. There is no SFTP subsystem and no PTY — the
real-sshd fixture covers those.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import paramiko
import pytest


class PasswordAuthSshd(paramiko.ServerInterface):
    """Password and/or publickey auth over a paramiko transport.

    An empty ``password`` disables password auth, an empty ``authorized`` list
    disables publickey auth; `get_allowed_auths` reports exactly what is on
    offer so a test can assert which method a client actually used.
    """

    def __init__(self, username: str, password: str, authorized: List[str],
                 home: Path, commands: List[str]) -> None:
        self.username = username
        self.password = password
        self.authorized = list(authorized)
        self.home = home
        self.commands = commands
        self.used_auth: Optional[str] = None
        self.exec_requests: List[str] = []

    # ── authentication ─────────────────────────────────────────────────────

    def check_auth_password(self, username: str, password: str) -> int:
        if (self.password and username == self.username
                and password == self.password):
            self.used_auth = "password"
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        # Read the real authorized_keys out of the temp home on every attempt,
        # exactly as sshd does: a key the app installs is then accepted by the
        # very next connection, so "install, then switch Auth to key" is a test
        # of the whole loop and not of a monkeypatched list.
        if username == self.username and key.get_base64() in self._authorized_blobs():
            self.used_auth = "publickey"
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def _authorized_blobs(self) -> set:
        blobs = {line.split()[1] for line in self.authorized if len(line.split()) >= 2}
        path = self.home / ".ssh" / "authorized_keys"
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    blobs.add(parts[1])
        return blobs

    def get_allowed_auths(self, username: str) -> str:
        # Both, always: which of them *works* is decided by check_auth_*.
        return "publickey,password"

    # ── channels ───────────────────────────────────────────────────────────

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        text = command.decode("utf-8", "replace")
        self.exec_requests.append(text)
        self.commands.append(text)
        threading.Thread(target=self._run, args=(channel, text), daemon=True).start()
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        # A piped `sh` rather than a PTY: enough for `invoke_shell` to open and
        # exchange bytes, which is all the client-side terminal smoke test needs.
        threading.Thread(target=self._run, args=(channel, "sh"), daemon=True).start()
        return True

    def check_channel_pty_request(self, *args, **kwargs) -> bool:
        return True

    def check_channel_window_change_request(self, *args, **kwargs) -> bool:
        return True

    # ── exec ───────────────────────────────────────────────────────────────

    def _run(self, channel: paramiko.Channel, command: str) -> None:
        """Run ``command`` locally, swallowing a client that hung up mid-write.

        A client that disconnects (a test's terminal session closing, a channel
        torn down at teardown) makes every later channel write raise EOFError
        inside paramiko. That is normal in a fixture whose whole job is to be
        hung up on, and it must not surface as an unhandled thread exception.
        """
        try:
            self._execute(channel, command)
        except Exception:
            pass
        finally:
            try:
                channel.close()
            except Exception:
                pass

    def _execute(self, channel: paramiko.Channel, command: str) -> None:
        """Run ``command`` locally with HOME in the temp dir, streaming I/O."""
        env = dict(os.environ)
        env["HOME"] = str(self.home)
        env["PWD"] = str(self.home)
        env.pop("SSH_AUTH_SOCK", None)
        try:
            proc = subprocess.Popen(
                command, shell=True, cwd=str(self.home), env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except Exception as exc:  # pragma: no cover - a failure of the fixture
            channel.sendall(f"fixture failed to run command: {exc}\n".encode())
            channel.send_exit_status(127)
            return

        def _feed() -> None:
            try:
                while True:
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    if proc.stdin is not None:
                        proc.stdin.write(chunk)
                        proc.stdin.flush()
            except Exception:
                pass
            finally:
                if proc.stdin is not None:
                    try:
                        proc.stdin.close()
                    except Exception:
                        pass

        feeder = threading.Thread(target=_feed, daemon=True)
        feeder.start()
        try:
            assert proc.stdout is not None
            for chunk in iter(lambda: proc.stdout.read(4096), b""):
                channel.sendall(chunk)
            code = proc.wait()
        except Exception:  # pragma: no cover - channel closed under us
            code = 255
        try:
            feeder.join(timeout=2)
        except Exception:
            pass
        try:
            channel.send_exit_status(int(code))
        except Exception:
            pass


@dataclass
class ParamikoEndpoint:
    """A live in-process SSH server plus the state a test asserts against."""

    host: str
    port: int
    username: str
    password: str
    home: Path
    commands: List[str] = field(default_factory=list)

    @property
    def ssh_dir(self) -> Path:
        return self.home / ".ssh"

    @property
    def authorized_keys_path(self) -> Path:
        return self.ssh_dir / "authorized_keys"

    def authorized_keys(self) -> str:
        p = self.authorized_keys_path
        return p.read_text(encoding="utf-8") if p.exists() else ""

    def last_command(self) -> str:
        return self.commands[-1] if self.commands else ""


def _host_keys(home: Path) -> List[paramiko.PKey]:
    """One host key per type `ssh-keyscan -t rsa,ecdsa,ed25519` asks for.

    All three, not just one: the app pins with ``capture_host_key``, which runs
    `ssh-keyscan -t rsa,ecdsa,ed25519`, and ssh-keyscan opens one connection per
    requested type announcing *only* that type. A single-key server therefore
    answers two of the three probes with "no acceptable host key", which
    paramiko prints as an unhandled thread exception — noise in the suite, and
    a server shape no real host has. paramiko's Ed25519Key/ECDSAKey have no
    generator and only read OpenSSH-format files, so ssh-keygen writes them (the
    SSH tests already require the OpenSSH client binaries).
    """
    keygen = shutil.which("ssh-keygen")
    if not keygen:
        pytest.skip("ssh-keygen is required to build the fixture's host keys")
    specs = (("ed25519", paramiko.Ed25519Key, []),
             ("ecdsa", paramiko.ECDSAKey, ["-b", "256"]),
             ("rsa", paramiko.RSAKey, ["-b", "2048"]))
    keys: List[paramiko.PKey] = []
    for name, cls, extra in specs:
        path = home.parent / f"paramiko-sshd-hostkey-{name}"
        if not path.exists():
            r = subprocess.run(
                [keygen, "-q", "-t", name, "-N", "", "-f", str(path)] + extra,
                capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                raise RuntimeError(
                    f"ssh-keygen failed to make the {name} host key: {r.stderr[:200]}")
        keys.append(cls.from_private_key_file(str(path)))
    return keys


class _ServerThread(threading.Thread):
    def __init__(self, sock: socket.socket, host_keys: List[paramiko.PKey],
                 interface: PasswordAuthSshd) -> None:
        super().__init__(daemon=True)
        self._sock = sock
        self._host_keys = host_keys
        self._interface = interface
        self._stop = threading.Event()

    def run(self) -> None:  # pragma: no cover - exercised via the fixture
        while not self._stop.is_set():
            try:
                client_sock, _ = self._sock.accept()
            except OSError:
                return
            try:
                transport = paramiko.Transport(client_sock)
                for key in self._host_keys:
                    transport.add_server_key(key)
                transport.start_server(server=self._interface)
                while transport.is_active() and not self._stop.is_set():
                    transport.join(1)
            except Exception:
                continue


def start_sshd(home: Path, *, username: str, password: str = "",
               authorized: Optional[List[str]] = None) -> tuple:
    """Start the server. Returns ``(endpoint, stop_callable)``."""
    home.mkdir(parents=True, exist_ok=True)
    host_keys = _host_keys(home)
    interface = PasswordAuthSshd(username, password, authorized or [], home, [])
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    port = sock.getsockname()[1]
    thread = _ServerThread(sock, host_keys, interface)
    thread.start()

    def _stop() -> None:
        thread._stop.set()
        try:
            sock.close()
        except OSError:
            pass

    endpoint = ParamikoEndpoint(
        host="127.0.0.1", port=port, username=username, password=password,
        home=home, commands=interface.commands)
    return endpoint, _stop


@pytest.fixture
def paramiko_sshd(tmp_path):
    """A factory for password-auth SSH endpoints, each with its own temp home.

    Each call gets a fresh home directory, so a test can stand up "a machine"
    the app has to install a key onto without any state leaking between cases.
    The caller stops nothing: teardown does.
    """
    endpoints: List[callable] = []
    started = 0

    def _factory(password: str = "hunter2", username: str = "",
                 authorized: Optional[List[str]] = None) -> ParamikoEndpoint:
        nonlocal started
        started += 1
        e, stop = start_sshd(
            tmp_path / f"remote-home-{started}",
            username=username or os.environ.get("USER") or "root",
            password=password, authorized=authorized)
        endpoints.append(stop)
        return e

    try:
        yield _factory
    finally:
        for stop in endpoints:
            stop()


def authorized_blob_for(public_key_text: str) -> str:
    """The base64 blob of an OpenSSH public key line (what a server compares)."""
    parts = str(public_key_text or "").split()
    if len(parts) < 2:
        raise ValueError(f"not an OpenSSH public key line: {public_key_text!r}")
    return parts[1]
