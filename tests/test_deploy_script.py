"""Focused tests for ``deploy.sh``.

``deploy.sh`` is the single entrypoint for both deployment paths, so a bad edit
can silently deploy the wrong thing. These tests pin the four parts where that
would happen:

* mode resolution — auto picks Docker only when the daemon really answers, and
  an explicit ``--docker`` / ``--native`` / ``ODYSSEUS_MODE`` always wins;
* flag validation — a typo or a missing value fails loudly instead of falling
  through to a default deploy;
* systemd unit generation — the unit matches the resolved bind and port, and
  ``--dry-run`` prints it without writing anything to disk;
* the Docker health probe — a status code is read from the app, so a container
  that is merely listening (or answering 5xx) is never reported as healthy.

Nothing here touches the Docker daemon or a real Python environment: a fake
``docker`` executable on ``PATH`` stands in for the daemon, native-mode deploys
run against a throwaway project whose interpreter is a stub, and the HTTP
servers the health-probe tests dial are throwaway loopback servers. The suite
therefore runs anywhere, including machines without Docker.
"""
from __future__ import annotations

import contextlib
import hashlib
import http.server
import os
import shutil
import socket
import subprocess
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy.sh"

# Minimal stand-in for the docker CLI. `docker info` is what deploy.sh checks
# before choosing the Docker path, so making just that one call fail is enough
# to exercise the daemon-down fallback.
FAKE_DOCKER = """#!/bin/sh
if [ "$1" = "info" ] && [ "${FAKE_DOCKER_DAEMON_DOWN:-}" = "1" ]; then
    exit 1
fi
exit 0
"""

STUB_VENV_PYTHON = """#!/bin/sh
if [ "$1" = "--version" ]; then
    echo "Python 3.11.0"
fi
exit 0
"""


def run_deploy(args, *, script=DEPLOY, env=None, cwd=None):
    """Run ``deploy.sh`` with ``args`` and capture its output."""
    return subprocess.run(
        ["bash", str(script), *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        cwd=str(cwd) if cwd is not None else None,
        timeout=120,
    )


def env_with_path(path_prepend: Path | None = None, **extra: str) -> dict[str, str]:
    env = dict(os.environ)
    if path_prepend is not None:
        env["PATH"] = f"{path_prepend}{os.pathsep}{env.get('PATH', '')}"
    env.update(extra)
    return env


def resolved_mode(proc: subprocess.CompletedProcess) -> str:
    """Pull the ``mode: <m>`` line that the ``status`` verb prints."""
    for line in proc.stdout.splitlines():
        if line.startswith("mode: "):
            return line.split()[1]
    raise AssertionError(
        f"no mode line in output:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def listening(port: int):
    """Hold ``port`` open so the deploy's health probe succeeds instantly."""
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    try:
        yield
    finally:
        sock.close()


@contextlib.contextmanager
def http_server(status: int = 200):
    """A throwaway HTTP server that answers every request with ``status``.

    The probe speaks HTTP/1.0 and closes the connection after each request while
    the wait loop redials, so the server has to serve several sequential
    requests: ThreadingHTTPServer keeps a retry from queueing behind the socket
    the previous one left open.
    """

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - the name is fixed by the base class
            self.send_response(status)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):  # a chatty server would litter pytest output
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def make_native_project(tmp_path: Path) -> Path:
    """A throwaway project holding only what a native deploy reads.

    The venv interpreter, uvicorn and setup.py are stubs so a deploy here cannot
    touch a real Python environment, and requirements.txt is matched by a
    precomputed hash so the pip step is skipped entirely.
    """
    project = tmp_path / "project"
    (project / "venv" / "bin").mkdir(parents=True)
    (project / "data").mkdir()

    shutil.copy2(DEPLOY, project / "deploy.sh")

    requirements = project / "requirements.txt"
    requirements.write_text("# stub\n", encoding="utf-8")
    digest = hashlib.md5(requirements.read_bytes()).hexdigest()
    (project / "venv" / ".requirements_hash").write_text(digest, encoding="utf-8")

    for name in ("python", "uvicorn"):
        stub = project / "venv" / "bin" / name
        stub.write_text(STUB_VENV_PYTHON, encoding="utf-8")
        stub.chmod(0o755)

    (project / "setup.py").write_text("# stub\n", encoding="utf-8")
    return project


def make_docker_project(tmp_path: Path) -> Path:
    """A throwaway project for Docker-mode runs.

    ``deploy.sh`` resolves its repo dir from its own location, so running a copy
    keeps ``docker_ensure_env`` from ever creating a ``.env`` in the real
    checkout. There is no ``.env.example`` or ``docker-compose.yml`` here, so
    nothing is written beside it either, and the fake ``docker`` on ``PATH``
    stands in for the daemon.
    """
    project = tmp_path / "docker-project"
    project.mkdir()
    shutil.copy2(DEPLOY, project / "deploy.sh")
    return project


@pytest.fixture
def fake_docker(tmp_path: Path) -> Path:
    """A directory containing a fake ``docker`` executable, for ``PATH``."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8")
    docker.chmod(0o755)
    return bin_dir


# -------------------------------------------------------------- mode resolution --


def test_auto_mode_uses_docker_when_the_daemon_answers(fake_docker):
    proc = run_deploy(["status", "--dry-run"], env=env_with_path(fake_docker))

    assert proc.returncode == 0
    assert resolved_mode(proc) == "docker"


def test_auto_mode_falls_back_to_native_when_the_daemon_is_down(fake_docker):
    proc = run_deploy(
        ["status", "--dry-run"],
        env=env_with_path(fake_docker, FAKE_DOCKER_DAEMON_DOWN="1"),
    )

    assert proc.returncode == 0
    assert resolved_mode(proc) == "native"
    assert "daemon is not reachable" in proc.stderr


def test_explicit_native_overrides_a_usable_docker(fake_docker):
    proc = run_deploy(["--native", "status", "--dry-run"], env=env_with_path(fake_docker))

    assert proc.returncode == 0
    assert resolved_mode(proc) == "native"


def test_explicit_docker_overrides_the_daemon_fallback(fake_docker):
    proc = run_deploy(
        ["--docker", "status", "--dry-run"],
        env=env_with_path(fake_docker, FAKE_DOCKER_DAEMON_DOWN="1"),
    )

    assert proc.returncode == 0
    assert resolved_mode(proc) == "docker"


def test_odysseus_mode_env_selects_the_mode(fake_docker):
    proc = run_deploy(
        ["status", "--dry-run"],
        env=env_with_path(fake_docker, ODYSSEUS_MODE="native"),
    )

    assert proc.returncode == 0
    assert resolved_mode(proc) == "native"


# ------------------------------------------------------------- flag validation --


@pytest.mark.parametrize("flag", ["--image", "--host", "--port"])
def test_value_flags_reject_a_missing_value(flag):
    proc = run_deploy([flag])

    assert proc.returncode == 1
    assert f"{flag} needs a value" in proc.stderr


def test_unknown_flag_fails_loudly():
    proc = run_deploy(["--definitely-not-a-flag"])

    assert proc.returncode == 1
    assert "unknown argument: --definitely-not-a-flag" in proc.stderr


def test_unknown_verb_fails_loudly():
    proc = run_deploy(["frobnicate"])

    assert proc.returncode == 1
    assert "unknown verb: frobnicate" in proc.stderr


def test_image_and_optional_are_refused_together(fake_docker):
    # --optional needs a local build, so combining it with a prebuilt image
    # reference cannot be honoured; it must be rejected rather than silently
    # dropping one of the two.
    proc = run_deploy(
        ["--docker", "--image", "ghcr.io/example/app:1.0.2-abcdef0", "--optional", "deploy"],
        env=env_with_path(fake_docker),
    )

    assert proc.returncode == 1
    assert "cannot be combined" in proc.stderr


def test_help_exits_zero_and_lists_the_interface():
    proc = run_deploy(["--help"])

    assert proc.returncode == 0
    assert "one-command deploy" in proc.stdout
    for token in ("--docker", "--native", "--dry-run", "--systemd", "--port"):
        assert token in proc.stdout
    for verb in ("deploy", "stop", "restart", "status", "logs", "update"):
        assert verb in proc.stdout


def test_shell_syntax_is_valid():
    subprocess.run(["bash", "-n", str(DEPLOY)], check=True)


# ------------------------------------------------------- systemd unit generation --


def test_dry_run_prints_the_unit_without_writing_it(tmp_path):
    project = make_native_project(tmp_path)

    proc = run_deploy(
        ["--native", "--no-chromadb", "--systemd", "--dry-run", "deploy"],
        script=project / "deploy.sh",
    )

    assert proc.returncode == 0
    # The whole point of --dry-run: a preview must not touch the filesystem.
    assert not (project / "data" / "systemd").exists()
    assert "[dry-run] mkdir -p" in proc.stdout
    assert "ExecStart=" in proc.stdout
    assert "WantedBy=multi-user.target" in proc.stdout
    assert "sudo systemctl enable --now odysseus" in proc.stdout


def test_systemd_writes_a_unit_for_the_resolved_bind_and_port(tmp_path):
    project = make_native_project(tmp_path)
    port = free_port()

    with listening(port):
        proc = run_deploy(
            [
                "--native", "--no-chromadb", "--systemd",
                "--host", "127.0.0.1", "--port", str(port), "deploy",
            ],
            script=project / "deploy.sh",
        )

    assert proc.returncode == 0
    unit = project / "data" / "systemd" / "odysseus.service"
    assert unit.is_file()

    text = unit.read_text(encoding="utf-8")
    assert f"WorkingDirectory={project}" in text
    assert f"ExecStart={project}/venv/bin/uvicorn app:app --host 127.0.0.1 --port {port}" in text
    assert "User=" in text
    assert "WantedBy=multi-user.target" in text
    # Installing needs root, so the script prints the commands instead of running them.
    assert "sudo install -m 0644" in proc.stdout
    assert "sudo systemctl enable --now odysseus" in proc.stdout


def test_systemd_flag_is_inert_outside_a_native_deploy(tmp_path):
    project = make_native_project(tmp_path)

    proc = run_deploy(
        ["--native", "--systemd", "status", "--dry-run"],
        script=project / "deploy.sh",
    )

    assert proc.returncode == 0
    assert not (project / "data" / "systemd").exists()


@pytest.mark.skipif(
    shutil.which("systemd-analyze") is None, reason="systemd-analyze not available"
)
def test_generated_unit_passes_systemd_analyze(tmp_path):
    project = make_native_project(tmp_path)
    port = free_port()

    with listening(port):
        proc = run_deploy(
            ["--native", "--no-chromadb", "--systemd", "--port", str(port), "deploy"],
            script=project / "deploy.sh",
        )
    assert proc.returncode == 0

    unit = project / "data" / "systemd" / "odysseus.service"
    verify = subprocess.run(
        ["systemd-analyze", "verify", str(unit)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert verify.returncode == 0, verify.stderr


# ---------------------------------------------------------------- dry-run safety --
# Two code paths used to run for real even under --dry-run, because a command
# that never returns cannot be wrapped in the print-it-instead `run` helper.
# Both are easy to reintroduce, so they get their own tests.


def test_foreground_dry_run_does_not_start_a_server(tmp_path):
    # `--foreground` execs uvicorn; under --dry-run it must only describe it.
    project = make_native_project(tmp_path)

    proc = run_deploy(
        ["--native", "--foreground", "--dry-run", "deploy"],
        script=project / "deploy.sh",
    )

    assert proc.returncode == 0
    assert "[dry-run] exec" in proc.stdout
    assert "uvicorn app:app" in proc.stdout


def test_native_logs_dry_run_does_not_follow_the_log(tmp_path):
    # `logs` runs `tail -f`, which never returns; --dry-run must not enter it.
    project = make_native_project(tmp_path)
    (project / "logs").mkdir()
    (project / "logs" / "odysseus.log").write_text("seeded\n", encoding="utf-8")

    proc = run_deploy(["--native", "--dry-run", "logs"], script=project / "deploy.sh")

    assert proc.returncode == 0
    assert "[dry-run] tail -n 120 -f" in proc.stdout


# --------------------------------------------------------- docker health probe --
# The Docker health check used to be a TCP connect, which cannot tell a working
# UI from a container that is up and failing every request. These pin the HTTP
# contract: a status code is read back from the app, and only 2xx/3xx counts.
# 302 is the case worth stating — with auth on, `/` redirects to /login, and that
# is a healthy answer, not a failure.


@pytest.mark.parametrize("code", [200, 302])
def test_docker_status_accepts_a_served_response(fake_docker, tmp_path, code):
    project = make_docker_project(tmp_path)

    with http_server(code) as port:
        proc = run_deploy(
            ["--docker", "status", "--port", str(port)],
            script=project / "deploy.sh",
            env=env_with_path(fake_docker),
        )

    assert proc.returncode == 0
    assert "✓ web UI answers on" in proc.stdout
    assert f"HTTP {code}" in proc.stdout


@pytest.mark.parametrize("code", [404, 500, 503])
def test_docker_status_rejects_an_error_response(fake_docker, tmp_path, code):
    project = make_docker_project(tmp_path)

    with http_server(code) as port:
        proc = run_deploy(
            ["--docker", "status", "--port", str(port)],
            script=project / "deploy.sh",
            env=env_with_path(fake_docker),
        )

    assert proc.returncode == 0
    assert "✓ web UI answers on" not in proc.stdout
    assert f"HTTP {code}" in proc.stdout  # it names what it actually got


def test_docker_status_rejects_a_listener_that_never_answers_http(fake_docker, tmp_path):
    # The old check's blind spot: a socket that accepts the connection but never
    # speaks HTTP is exactly what a port check called healthy.
    project = make_docker_project(tmp_path)
    port = free_port()

    with listening(port):
        proc = run_deploy(
            ["--docker", "status", "--port", str(port)],
            script=project / "deploy.sh",
            env=env_with_path(fake_docker),
        )

    assert proc.returncode == 0
    assert "✗ nothing answering on" in proc.stdout


def test_docker_deploy_reports_the_status_code_of_a_healthy_app(fake_docker, tmp_path):
    project = make_docker_project(tmp_path)

    with http_server(200) as port:
        proc = run_deploy(
            ["--docker", "--port", str(port), "deploy"],
            script=project / "deploy.sh",
            env=env_with_path(fake_docker),
        )

    assert proc.returncode == 0
    assert "✓ the app is answering (HTTP 200)" in proc.stdout


def test_docker_deploy_does_not_report_success_for_a_server_error(fake_docker, tmp_path):
    # The regression that motivated the change: `deploy` announced
    # "✓ the app is answering" for anything that was merely listening. The
    # timeout is shortened so the deploy gives up in a second rather than two
    # minutes; the answer it saw is what makes the failure honest.
    project = make_docker_project(tmp_path)

    with http_server(500) as port:
        proc = run_deploy(
            ["--docker", "--port", str(port), "deploy"],
            script=project / "deploy.sh",
            env=env_with_path(fake_docker, ODYSSEUS_HEALTH_TIMEOUT="1"),
        )

    assert proc.returncode == 0
    assert "✓ the app is answering" not in proc.stdout
    assert "HTTP 500" in proc.stderr


def test_health_timeout_must_be_a_whole_number(fake_docker, tmp_path):
    # Bash reads a non-numeric value as an unset variable, so a typo would wait
    # zero seconds and report a working app as broken. Fail loudly instead.
    project = make_docker_project(tmp_path)

    proc = run_deploy(
        ["--docker", "status"],
        script=project / "deploy.sh",
        env=env_with_path(fake_docker, ODYSSEUS_HEALTH_TIMEOUT="soon"),
    )

    assert proc.returncode == 1
    assert "ODYSSEUS_HEALTH_TIMEOUT must be a whole number" in proc.stderr
