"""SSH integration-test fixture (plan Phase 0.1).

Resolution chain for a usable SSH endpoint:
  1. ``SSHD_TEST_HOST`` env var (CI-provided ``user@host``; optional
     ``SSHD_TEST_PORT``, ``SSHD_TEST_KEY``).
  2. A temporary local ``sshd`` on 127.0.0.1 with a generated host key and
     ``authorized_keys`` under ``tmp_path`` — only when the ``ssh`` and
     ``sshd`` binaries exist.
  3. Otherwise the test is skipped.

Pure-logic SSH tests must not depend on this fixture; it is only for the
end-to-end cases marked ``ssh_integration``.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

has_sshd = bool(shutil.which("sshd"))
has_ssh = bool(shutil.which("ssh"))


@dataclass
class SshEndpoint:
    host: str
    user: str
    port: int
    private_key: Path

    @property
    def remote(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_local_sshd(tmp_path: Path) -> Optional[tuple]:
    """Best-effort local sshd. Returns (proc, SshEndpoint) or None.

    Notes: sshd must be invoked by absolute path (it refuses bare `sshd`),
    and auth uses the current login user — a non-root sshd cannot log in
    as anyone else.
    """
    import getpass
    sshd_bin = shutil.which("sshd")
    keygen_bin = shutil.which("ssh-keygen")
    if not sshd_bin or not keygen_bin:
        return None
    try:
        login_user = getpass.getuser()
    except Exception:
        return None
    host_key = tmp_path / "ssh_host_ed25519_key"
    client_key = tmp_path / "client_ed25519"
    authorized = tmp_path / "authorized_keys"
    for args in (
        [keygen_bin, "-t", "ed25519", "-N", "", "-f", str(host_key)],
        [keygen_bin, "-t", "ed25519", "-N", "", "-f", str(client_key)],
    ):
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return None
    authorized.write_text(client_key.with_suffix(".pub").read_text(), encoding="utf-8")
    authorized.chmod(0o600)
    port = _free_port()
    cfg = tmp_path / "sshd_config"
    cfg.write_text(
        "\n".join([
            f"Port {port}",
            "ListenAddress 127.0.0.1",
            f"HostKey {host_key}",
            f"AuthorizedKeysFile {authorized}",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "ChallengeResponseAuthentication no",
            "StrictModes no",
            "UsePAM no",
            "PidFile " + str(tmp_path / "sshd.pid"),
            "LogLevel ERROR",
        ]) + "\n",
        encoding="utf-8",
    )
    try:
        proc = subprocess.Popen(
            [sshd_bin, "-D", "-f", str(cfg)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    # Wait for the listener to accept (sshd can take a moment to bind).
    import time
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return proc, SshEndpoint("127.0.0.1", login_user, port, client_key)
        except OSError:
            if proc.poll() is not None:
                return None
            time.sleep(0.1)
    proc.terminate()
    return None


@pytest.fixture(scope="session")
def ssh_endpoint(tmp_path_factory):
    env_host = (os.environ.get("SSHD_TEST_HOST") or "").strip()
    if env_host:
        user, _, host = env_host.partition("@")
        if not host:
            user, host = "", env_host
        key = os.environ.get("SSHD_TEST_KEY") or os.path.expanduser("~/.ssh/id_ed25519")
        yield SshEndpoint(host, user, int(os.environ.get("SSHD_TEST_PORT") or 22), Path(key))
        return

    if not (has_sshd and has_ssh):
        pytest.skip("no sshd/ssh binaries and no SSHD_TEST_HOST — skipping SSH integration test")

    tmp = tmp_path_factory.mktemp("sshd")
    started = _start_local_sshd(tmp)
    if not started:
        pytest.skip("could not start a local sshd — skipping SSH integration test")
    proc, endpoint = started
    try:
        yield endpoint
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
