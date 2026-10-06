"""ssh_client.py — paramiko transport for password auth, SFTP, and the terminal.

Phase 2 (ssh-rsh-spec.md §6.2, §6.3, §6.4). OpenSSH argv stays the path for
key-only one-shot/transfer (`src/ssh_remote.py`); this module exists for the
three things argv cannot do safely:

* **password login** — the secret is passed as a ``connect(password=...)`` API
  argument, never on a command line and never in the environment (``sshpass`` is
  rejected: ``-p`` leaks through ``ps`` and ``-e`` through ``/proc/<pid>/environ``).
* **SFTP transfer** — ``put``/``get`` with the password in-process.
* **interactive terminal** — ``invoke_shell`` + ``get_pty``.

Host keys are still pinned, and the pin is enforced **before** any credential is
sent: the per-server known_hosts file is loaded, its fingerprints are added to
the expected set, and ``RejectPolicy`` is installed whenever that set is
non-empty. Only a first, entirely unpinned connection uses the capture policy,
and the key it captured is checked against the stored pin immediately after.

Everything here is blocking. Callers must run it via ``asyncio.to_thread`` so the
FastAPI event loop stays free (same rule the Cookbook/CalDAV paths follow).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 5
BANNER_TIMEOUT = 10
AUTH_TIMEOUT = 15

# Terminal session limits (spec §6.4/§6.3).
MAX_TERMINAL_SESSIONS_PER_USER = 3
TERMINAL_IDLE_KILL_S = 600
TERMINAL_DEFAULT_COLS = 100
TERMINAL_DEFAULT_ROWS = 30


class SshClientError(Exception):
    """Transport-level failure (auth, network, protocol)."""


class HostKeyChangedError(SshClientError):
    """The presented host key does not match the pinned fingerprint."""


class SshTimeoutError(SshClientError):
    """The remote operation exceeded its deadline."""


def key_fingerprint(key: Any) -> str:
    """OpenSSH-style ``SHA256:<b64>`` fingerprint for a paramiko PKey."""
    raw = key.asbytes() if hasattr(key, "asbytes") else bytes(key)
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _fingerprint_from_b64(key_b64: str) -> str:
    raw = base64.b64decode(str(key_b64).encode("ascii"))
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def key_line(host: str, key: Any, port: int = 22) -> str:
    """known_hosts line(s) for a paramiko PKey.

    Emits every host form for the port (see ``ssh_remote._host_forms``): paramiko
    looks a non-default port up as ``[host]:port``, so a bare-host line alone
    would leave the pin unenforceable.
    """
    from src.ssh_remote import _host_forms
    b64 = base64.b64encode(key.asbytes()).decode("ascii")
    return "\n".join(f"{form} {key.get_name()} {b64}"
                      for form in _host_forms(host, port))


def pins_from_pin_file(server_id: str) -> set:
    """Fingerprints already pinned on disk for this server."""
    if not server_id:
        return set()
    pin = _pin_file(server_id)
    if not pin.exists():
        return set()
    out = set()
    try:
        for line in pin.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and not parts[0].startswith("#"):
                try:
                    out.add(_fingerprint_from_b64(parts[2]))
                except Exception:
                    continue
    except OSError:
        return set()
    return out


class _CaptureHostKeyPolicy:
    """Accept an unpinned key so the caller can verify it (never silently trust).

    Used only for the first connection to a server: once a fingerprint is stored
    the pinned known_hosts file is loaded and ``RejectPolicy`` applies, so a
    password is never offered to a host that fails the pin.
    """

    def __init__(self) -> None:
        self.key = None

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        self.key = key


def _pin_file(server_id: str) -> Path:
    from src.ssh_remote import _pinned_known_hosts_path
    return _pinned_known_hosts_path(server_id)


def _open(host: str, port: int, username: str, *,
          password: str = "", key_path: Optional[Path] = None,
          server_id: str = "", expected_fingerprints: Optional[Iterable[str]] = None,
          timeout: int = CONNECT_TIMEOUT) -> Tuple[Any, Optional[str], Optional[str]]:
    """Open an authenticated SSHClient.

    Returns ``(client, fingerprint, known_hosts_line)``. Raises
    ``HostKeyChangedError`` on a pin mismatch — before authenticating whenever a
    pin is known, so credentials never reach a mismatched host.
    """
    import paramiko

    if not username:
        raise SshClientError("username is required for password/SFTP auth")
    if not password and key_path is None:
        raise SshClientError("no password and no key available for this server")

    # The stored pin (passed by the caller) is authoritative. The pin file is a
    # *fallback* for callers that only know a server id — never an additional
    # vote, or a stale file could outvote a re-pinned row and keep a host the
    # user just un-trusted reachable.
    expected = {f for f in (expected_fingerprints or ()) if f}
    if not expected:
        expected = pins_from_pin_file(server_id)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    capture = _CaptureHostKeyPolicy()
    if server_id:
        pin = _pin_file(server_id)
        if pin.exists():
            try:
                client.load_host_keys(str(pin))
            except Exception as exc:  # unreadable/corrupt pin file: fail closed
                client.close()
                raise SshClientError(f"could not read pinned host key: {exc}")
    if not expected:
        client.set_missing_host_key_policy(capture)

    kwargs: Dict[str, Any] = {
        "port": int(port),
        "username": username,
        "timeout": timeout,
        "banner_timeout": BANNER_TIMEOUT,
        "auth_timeout": AUTH_TIMEOUT,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if password:
        kwargs["password"] = password
    if key_path is not None:
        kwargs["key_filename"] = str(key_path)

    try:
        client.connect(host, **kwargs)
    except Exception as exc:
        client.close()
        raise SshClientError(f"{type(exc).__name__}: {exc}"[:300]) from exc

    presented = capture.key
    if presented is None and client.get_transport() is not None:
        presented = client.get_transport().get_remote_server_key()
    fingerprint = None
    line = None
    if presented is not None:
        fingerprint = key_fingerprint(presented)
        line = key_line(host, presented, port)
        if expected and fingerprint not in expected:
            client.close()
            raise HostKeyChangedError(
                "HOST KEY CHANGED — refusing to connect. Verify the server, "
                "then re-run Test to re-pin."
            )
    return client, fingerprint, line


def connect(host: str, port: int, username: str, *,
            password: str = "", key_path: Optional[Path] = None,
            server_id: str = "", expected_fingerprints: Optional[Iterable[str]] = None,
            timeout: int = CONNECT_TIMEOUT) -> Any:
    """Open an SSHClient. The caller owns it and must ``close()`` it."""
    client, _, _ = _open(host, port, username, password=password, key_path=key_path,
                         server_id=server_id,
                         expected_fingerprints=expected_fingerprints, timeout=timeout)
    return client


def test_login(host: str, port: int, username: str, *,
               password: str = "", key_path: Optional[Path] = None,
               server_id: str = "", expected_fingerprints: Optional[Iterable[str]] = None,
               timeout: int = CONNECT_TIMEOUT) -> Dict[str, Any]:
    """Connect and run ``true``. Returns ok/latency/fingerprint/known_hosts line."""
    started = time.monotonic()
    client, fingerprint, line = _open(
        host, port, username, password=password, key_path=key_path,
        server_id=server_id, expected_fingerprints=expected_fingerprints,
        timeout=timeout,
    )
    try:
        try:
            stdin, stdout, stderr = client.exec_command("true", timeout=30)
            code = stdout.channel.recv_exit_status()
            err = stderr.read().decode("utf-8", "replace").strip()
        except (TimeoutError, socket.timeout) as exc:
            raise SshTimeoutError("connection timed out") from exc
    finally:
        client.close()
    return {
        "ok": code == 0,
        "exit_code": code,
        "stderr": err[:300],
        "fingerprint": fingerprint,
        "key_line": line,
        "latency_ms": int((time.monotonic() - started) * 1000),
    }


def apply_sudo(cmd: str, sudo_password: str) -> Tuple[str, str]:
    """Rewrite a leading ``sudo`` into ``sudo -S`` and return (cmd, stdin).

    The password goes to the remote process over stdin only — never through the
    environment or a command line, and never logged. No password stored, or a
    command that already passes ``-S``/``-A``, is left exactly as the user wrote
    it so the remote host decides.
    """
    text = (cmd or "").strip()
    if not sudo_password or not text:
        return text, ""
    if not (text == "sudo" or text.startswith("sudo ")):
        return text, ""
    rest = text[4:].lstrip()
    if rest.startswith("-S") or rest.startswith("-A"):
        return text, ""
    return f"sudo -S -p '' {rest}", f"{sudo_password}\n"


def run_command(host: str, port: int, username: str, cmd: str, *,
                password: str = "", key_path: Optional[Path] = None,
                server_id: str = "", expected_fingerprints: Optional[Iterable[str]] = None,
                timeout: int = 30, stdin_text: str = "",
                sudo_password: str = "") -> Dict[str, Any]:
    """One-shot command over paramiko. Returns stdout/stderr/exit_code."""
    command, sudo_stdin = apply_sudo(cmd, sudo_password)
    if sudo_stdin and not stdin_text:
        stdin_text = sudo_stdin
    client = connect(host, port, username, password=password, key_path=key_path,
                     server_id=server_id, expected_fingerprints=expected_fingerprints)
    try:
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        except (TimeoutError, socket.timeout) as exc:
            raise SshTimeoutError(f"command timed out after {timeout}s") from exc
        if stdin_text:
            try:
                stdin.write(stdin_text)
                stdin.flush()
            except Exception:
                pass  # remote may close stdin immediately (e.g. no read)
        try:
            stdin.channel.shutdown_write()
        except Exception:
            pass
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
    finally:
        client.close()
    return {"stdout": out, "stderr": err, "exit_code": code}


def sftp_transfer(host: str, port: int, username: str, direction: str, *,
                  local_path: str, remote_path: str,
                  password: str = "", key_path: Optional[Path] = None,
                  server_id: str = "", expected_fingerprints: Optional[Iterable[str]] = None,
                  timeout: int = 120) -> Dict[str, Any]:
    """SFTP put/get. The local side is already workspace-resolved by the caller."""
    client = connect(host, port, username, password=password, key_path=key_path,
                     server_id=server_id, expected_fingerprints=expected_fingerprints)
    try:
        sftp = client.open_sftp()
        sftp.get_channel().settimeout(timeout)
        try:
            if direction == "upload":
                sftp.put(local_path, remote_path)
            else:
                sftp.get(remote_path, local_path)
        finally:
            sftp.close()
    finally:
        client.close()
    return {"ok": True, "direction": direction, "remote_path": remote_path}


class TerminalSession:
    """One interactive remote shell (paramiko ``invoke_shell`` + PTY).

    Output is buffered by the transport channel and drained by ``read()``; the
    SSE route drives that loop. Sessions live in memory only, so a restart drops
    them (documented and acceptable per spec §6.3).
    """

    def __init__(self, owner: str, server_id: str, client: Any, channel: Any) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.owner = owner
        self.server_id = server_id
        self._client = client
        self._channel = channel
        self._lock = threading.Lock()
        self.last_activity = time.monotonic()
        self.closed = False

    def write(self, data: str) -> None:
        with self._lock:
            if self.closed:
                return
            self._channel.send(data)
            self.last_activity = time.monotonic()

    def resize(self, cols: int, rows: int) -> None:
        with self._lock:
            if self.closed:
                return
            self._channel.resize_pty(width=int(cols), height=int(rows))
            self.last_activity = time.monotonic()

    def read(self, wait: float = 0.25) -> Optional[str]:
        """Return available output, ``''`` when idle, or ``None`` at EOF."""
        if self._channel.recv_ready():
            data = self._channel.recv(65536)
            if not data:
                return None
            self.last_activity = time.monotonic()
            return data.decode("utf-8", "replace")
        if self._channel.exit_status_ready() and not self._channel.recv_ready():
            return None
        time.sleep(wait)
        if self._channel.recv_ready():
            data = self._channel.recv(65536)
            if not data:
                return None
            self.last_activity = time.monotonic()
            return data.decode("utf-8", "replace")
        if self._channel.exit_status_ready():
            return None
        return ""

    def exit_status(self) -> int:
        try:
            if self._channel.exit_status_ready():
                return int(self._channel.recv_exit_status())
        except Exception:
            pass
        return 0

    def idle_seconds(self) -> float:
        return time.monotonic() - self.last_activity

    def close(self) -> None:
        with self._lock:
            if self.closed:
                return
            self.closed = True
        try:
            self._channel.close()
        except Exception:
            pass
        try:
            self._client.close()
        except Exception:
            pass


_sessions: Dict[str, TerminalSession] = {}
_sessions_lock = threading.Lock()


def open_terminal(owner: str, host: str, port: int, username: str, *,
                  server_id: str = "", password: str = "",
                  key_path: Optional[Path] = None,
                  expected_fingerprints: Optional[Iterable[str]] = None,
                  cols: int = TERMINAL_DEFAULT_COLS,
                  rows: int = TERMINAL_DEFAULT_ROWS,
                  term: str = "xterm-256color") -> TerminalSession:
    """Open a PTY-backed shell. Enforces the per-user session cap."""
    _reap_idle()
    with _sessions_lock:
        live = [s for s in _sessions.values() if s.owner == owner and not s.closed]
        if len(live) >= MAX_TERMINAL_SESSIONS_PER_USER:
            raise SshClientError(
                f"too many open terminals (max {MAX_TERMINAL_SESSIONS_PER_USER})")
    client = connect(host, port, username, password=password, key_path=key_path,
                     server_id=server_id, expected_fingerprints=expected_fingerprints)
    try:
        channel = client.invoke_shell(term=term, width=int(cols), height=int(rows))
        channel.settimeout(0.0)
    except Exception as exc:
        client.close()
        raise SshClientError(f"{type(exc).__name__}: {exc}"[:300]) from exc
    session = TerminalSession(owner, server_id, client, channel)
    with _sessions_lock:
        _sessions[session.id] = session
    return session


def get_terminal(owner: str, session_id: str) -> TerminalSession:
    with _sessions_lock:
        session = _sessions.get(session_id)
    if session is None or session.owner != owner or session.closed:
        raise LookupError("terminal session not found")
    return session


def close_terminal(owner: str, session_id: str) -> None:
    session = get_terminal(owner, session_id)
    session.close()
    with _sessions_lock:
        _sessions.pop(session_id, None)


def close_terminal_by_id(session_id: str) -> None:
    with _sessions_lock:
        session = _sessions.pop(session_id, None)
    if session is not None:
        session.close()


def _reap_idle() -> List[str]:
    """Close sessions idle past the kill window. Returns the ids reaped."""
    reaped: List[str] = []
    with _sessions_lock:
        for sid, session in list(_sessions.items()):
            if session.closed or session.idle_seconds() > TERMINAL_IDLE_KILL_S:
                reaped.append(sid)
    for sid in reaped:
        try:
            close_terminal_by_id(sid)
        except Exception:
            pass
    return reaped


def session_count(owner: str) -> int:
    with _sessions_lock:
        return len([s for s in _sessions.values() if s.owner == owner and not s.closed])


def _reset_sessions_for_tests() -> None:
    """Test hook: drop every session (mirrors a process restart)."""
    with _sessions_lock:
        sessions = list(_sessions.values())
        _sessions.clear()
    for s in sessions:
        s.close()
