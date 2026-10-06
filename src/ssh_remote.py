"""ssh_remote.py — owner-scoped saved SSH servers: store, exec, audit, keys.

Phase 1: key-only auth via OpenSSH argv (no new dependencies).
Phase 2: password auth, SFTP transfer, and the interactive terminal go
through ``src/ssh_client.py`` (paramiko) instead; key-only one-shot and
transfer keep the argv path so their behaviour is unchanged.
Implements ssh-rsh-spec.md §§6.1–6.4, 7, 10 (backend half).

All public functions take an explicit ``owner`` (username) and scope every
query to it — there is no cross-owner access path by construction.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

logger = logging.getLogger(__name__)

# Same shape as routes/_validators.py (which raises HTTPException and so is
# unsuitable for the agent path). Kept in sync by test_ssh_servers.py.
_REMOTE_HOST_RE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*@)?[A-Za-z0-9][A-Za-z0-9._-]*$")
_SSH_PORT_RE = re.compile(r"^\d{1,5}$")

EXEC_DEFAULT_TIMEOUT = 30
EXEC_MAX_TIMEOUT = 120
CONNECT_TIMEOUT = 5


def _data_ssh_dir() -> Path:
    from src.constants import DATA_DIR
    return Path(DATA_DIR) / "ssh"


def _known_hosts_dir() -> Path:
    return _data_ssh_dir() / "known_hosts.d"


# ---------------------------------------------------------------------------
# Key plumbing (Phase 0.2)
# ---------------------------------------------------------------------------

def ensure_managed_ssh_dir() -> Path:
    """Create data/ssh (0700) if missing. Idempotent, safe at startup."""
    d = _data_ssh_dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    _known_hosts_dir().mkdir(parents=True, exist_ok=True)
    return d


def user_key_paths(owner: str) -> Dict[str, Path]:
    """Per-user keypair paths. Stable filename => rotation needs no DB change."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", owner or "default")
    d = ensure_managed_ssh_dir()
    return {"private": d / f"{safe}_ed25519", "public": d / f"{safe}_ed25519.pub"}


def generate_user_key(owner: str, force: bool = False) -> Dict[str, str]:
    """Generate the user's ed25519 keypair if missing. Returns paths + pubkey."""
    paths = user_key_paths(owner)
    if paths["private"].exists() and not force:
        pub = paths["public"].read_text(encoding="utf-8").strip() if paths["public"].exists() else ""
        return {"private": str(paths["private"]), "public_path": str(paths["public"]), "public_key": pub, "generated": False}
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh_keygen:
        raise RuntimeError("ssh-keygen not found — install openssh-client")
    if paths["private"].exists():
        bak = paths["private"].with_name(paths["private"].name + ".bak")
        paths["private"].replace(bak)
        if paths["public"].exists():
            paths["public"].replace(paths["public"].with_suffix(".pub.bak"))
    r = subprocess.run(
        [ssh_keygen, "-t", "ed25519", "-N", "", "-f", str(paths["private"])],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        raise RuntimeError(f"ssh-keygen failed: {(r.stderr or '').strip()[:200]}")
    try:
        os.chmod(paths["private"], 0o600)
    except OSError:
        pass
    pub = paths["public"].read_text(encoding="utf-8").strip()
    return {"private": str(paths["private"]), "public_path": str(paths["public"]), "public_key": pub, "generated": True}


# ---------------------------------------------------------------------------
# Validation (mirrors routes/_validators.py, raises ValueError for tool use)
# ---------------------------------------------------------------------------

def validate_host(host: str) -> str:
    v = (host or "").strip()
    if not v or not _REMOTE_HOST_RE.match(v):
        raise ValueError("Invalid remote_host — must be host or user@host, no SSH option syntax")
    return v


def validate_port(port: Any) -> int:
    if port in (None, ""):
        return 22
    s = str(port).strip()
    if not _SSH_PORT_RE.fullmatch(s) or not (1 <= int(s) <= 65535):
        raise ValueError("Invalid ssh_port")
    return int(s)


def _split_user_host(host: str, username: str = "") -> tuple[str, str]:
    """Split an optional user@ prefix out of the host field.

    The Host field accepts a bare host or user@host (the UI/API also has a
    separate Username field). Returns (bare_host, effective_username). A
    conflicting explicit Username is rejected instead of silently preferred:
    storing "alice@a" + Username "bob" would build "bob@alice@a", which can
    never connect and poisons the pinned known_hosts line.
    """
    remote = validate_host(host)
    username = str(username or "")
    user, sep, bare = remote.rpartition("@")
    if not sep:
        return remote, username.strip()
    explicit = username.strip()
    if explicit and explicit != user:
        raise ValueError("specify the login user in Host or Username, not both")
    return bare, user


def _host_allowed(remote: str, port: int) -> bool:
    """Admin CIDR/glob gate. Default [] = allow any saved host (spec L4)."""
    try:
        from src.settings import get_setting
        patterns = get_setting("ssh_allowed_host_patterns", []) or []
    except Exception:
        patterns = []
    if not patterns:
        return True
    target = f"{remote}:{port}"
    host_only = remote.rsplit("@", 1)[-1]
    for pat in patterns:
        p = str(pat).strip()
        if not p:
            continue
        if "/" in p and "@" not in p:
            try:
                if ipaddress.ip_address(host_only) in ipaddress.ip_network(p, strict=False):
                    return True
                continue
            except ValueError:
                pass
        if fnmatch.fnmatch(target, p) or fnmatch.fnmatch(remote, p) or fnmatch.fnmatch(host_only, p):
            return True
    return False


def _require_allowed(remote: str, port: int) -> None:
    if not _host_allowed(remote, port):
        raise ValueError("host not permitted by admin policy")


# ---------------------------------------------------------------------------
# DB sessions
# ---------------------------------------------------------------------------

@contextmanager
def _session() -> Iterator[Any]:
    from core.database import SessionLocal
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _row_to_dict(row: Any, *, with_secrets: bool = False) -> Dict[str, Any]:
    d = {
        "id": row.id, "owner": row.owner, "label": row.label,
        "host": row.host, "port": row.port, "username": row.username,
        "auth_type": row.auth_type, "ssh_key_ref": row.ssh_key_ref,
        "host_key_fingerprint": row.host_key_fingerprint,
        "has_password": bool(row.password),
        "has_sudo_password": bool(row.sudo_password),
        "last_tested_at": row.last_tested_at.isoformat() if row.last_tested_at else None,
        "last_test_result": row.last_test_result,
    }
    if with_secrets:
        d["password"] = row.password or ""
        d["sudo_password"] = row.sudo_password or ""
    return d


# ---------------------------------------------------------------------------
# CRUD (all owner-scoped)
# ---------------------------------------------------------------------------

def list_servers(owner: str) -> List[Dict[str, Any]]:
    from core.database import SshServer
    with _session() as db:
        rows = db.query(SshServer).filter(SshServer.owner == owner).order_by(SshServer.label).all()
        return [_row_to_dict(r) for r in rows]


def _get_row(db: Any, owner: str, server_id: str) -> Any:
    from core.database import SshServer
    row = db.query(SshServer).filter(SshServer.id == server_id, SshServer.owner == owner).first()
    if row is None:
        raise LookupError("server not found")
    return row


def resolve_server(owner: str, ref: str) -> Dict[str, Any]:
    """Resolve id (exact) or label (case-insensitive, then substring).

    Mirrors _resolve_cookbook_host semantics. Never crosses owners.
    """
    from core.database import SshServer
    val = (ref or "").strip()
    if not val:
        raise ValueError("server is required")
    with _session() as db:
        row = db.query(SshServer).filter(SshServer.id == val, SshServer.owner == owner).first()
        if row is not None:
            return _row_to_dict(row)
        rows = db.query(SshServer).filter(SshServer.owner == owner).all()
        low = val.lower()
        for r in rows:
            if (r.label or "").lower() == low:
                return _row_to_dict(r)
        for r in rows:
            if low and low in (r.label or "").lower():
                return _row_to_dict(r)
    raise LookupError(f"no server matches {val!r}")


def create_server(owner: str, *, label: str, host: str, port: Any = 22,
                  username: str = "", auth_type: str = "key",
                  password: str = "", sudo_password: str = "") -> Dict[str, Any]:
    from core.database import SshServer
    label = (label or "").strip()
    if not label:
        raise ValueError("label is required")
    bare_host, eff_user = _split_user_host(host, username)
    port_n = validate_port(port)
    _require_allowed(f"{eff_user}@{bare_host}" if eff_user else bare_host, port_n)
    if auth_type not in ("key", "password", "both"):
        raise ValueError("auth_type must be key, password, or both")
    with _session() as db:
        row = SshServer(
            id=uuid.uuid4().hex[:12], owner=owner, label=label,
            host=bare_host, port=port_n, username=eff_user,
            auth_type=auth_type,
            password=password or None, sudo_password=sudo_password or None,
            ssh_key_ref=user_key_paths(owner)["private"].name,
        )
        db.add(row)
        db.flush()
        out = _row_to_dict(row)
    audit(owner, out["id"], "server_created", "", 0)
    return out


def update_server(owner: str, server_id: str, **fields: Any) -> Dict[str, Any]:
    with _session() as db:
        row = _get_row(db, owner, server_id)
        if "label" in fields and fields["label"] is not None:
            label = str(fields["label"]).strip()
            if not label:
                raise ValueError("label is required")
            row.label = label
        prior_target = (row.host, int(row.port))
        if "port" in fields and fields["port"] is not None:
            row.port = validate_port(fields["port"])
        host_given = "host" in fields and fields["host"] is not None
        user_given = "username" in fields and fields["username"] is not None
        if host_given or user_given:
            raw_host = fields["host"] if host_given else row.host
            raw_user = fields["username"] if user_given else (row.username or "")
            row.host, row.username = _split_user_host(raw_host, raw_user)
        gate = f"{row.username}@{row.host}" if row.username else row.host
        _require_allowed(gate, int(row.port))
        if (row.host, int(row.port)) != prior_target:
            # A pin belongs to one host:port. Re-pointing the row must not carry
            # the old server's trust over, and must not leave a stale pin failing
            # closed against a host that was never verified.
            row.host_key_fingerprint = None
            row.last_test_result = None
            row.last_tested_at = None
            _drop_pin_file(server_id)
        if "auth_type" in fields and fields["auth_type"] is not None:
            if fields["auth_type"] not in ("key", "password", "both"):
                raise ValueError("auth_type must be key, password, or both")
            row.auth_type = fields["auth_type"]
        # Empty string and None both leave a secret unchanged (PATCH sends every
        # field, so None must NOT wipe); only a non-empty value replaces.
        if "password" in fields and fields["password"]:
            row.password = fields["password"]
        if "sudo_password" in fields and fields["sudo_password"]:
            row.sudo_password = fields["sudo_password"]
        db.flush()
        return _row_to_dict(row)


def delete_server(owner: str, server_id: str) -> None:
    with _session() as db:
        row = _get_row(db, owner, server_id)
        db.delete(row)
    try:
        kh = _known_hosts_dir() / server_id
        if kh.exists():
            kh.unlink()
    except OSError:
        pass
    audit(owner, server_id, "server_deleted", "", 0)


# ---------------------------------------------------------------------------
# Audit (append-only; never secret values)
# ---------------------------------------------------------------------------

def audit(owner: str, server_id: str, event: str, command: str, exit_code: int) -> None:
    from core.database import SshAuditLog
    digest = hashlib.sha256((command or "").encode("utf-8")).hexdigest() if command else None
    try:
        with _session() as db:
            db.add(SshAuditLog(
                id=uuid.uuid4().hex[:12], owner=owner, server_id=server_id,
                event=event, command_hash=digest, exit_code=exit_code,
            ))
    except Exception as exc:
        logger.warning("ssh audit write failed: %s", exc)


def server_meta(server_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """Display metadata for server ids: ``{id: {"label", "port"}}``.

    Best-effort by design — audit rows outlive their server (``server_id`` has no
    FK), so a deleted machine simply has no entry. Never returns secrets.
    """
    from core.database import SshServer
    ids = [str(i) for i in (server_ids or []) if i]
    if not ids:
        return {}
    with _session() as db:
        rows = db.query(SshServer).filter(SshServer.id.in_(ids)).all()
        # Materialise INSIDE the session: after the block the instances are
        # detached and expired, so touching r.label raises DetachedInstanceError.
        return {r.id: {"label": r.label or "", "port": r.port} for r in rows}


def list_audit(owner: str, limit: int = 50, event: Optional[str] = None,
               server_id: Optional[str] = None, scope: str = "self") -> List[Dict[str, Any]]:
    """Read the audit trail (machines-area-spec.md §8), newest first.

    Owner-scoped unless ``scope="all"``, which returns every owner's rows and is
    only reachable when the caller has already proven admin at the route layer.
    Returns the command *hash* only: never command text, secrets or key material.
    """
    from core.database import SshAuditLog
    try:
        n = int(limit)
    except (TypeError, ValueError):
        n = 50
    n = max(1, min(n, 200))
    with _session() as db:
        q = db.query(SshAuditLog)
        if scope != "all":
            q = q.filter(SshAuditLog.owner == owner)
        if server_id:
            q = q.filter(SshAuditLog.server_id == server_id)
        if event:
            q = q.filter(SshAuditLog.event == event)
        rows = q.order_by(SshAuditLog.created_at.desc(), SshAuditLog.id).limit(n).all()
        out = [{
            "id": r.id,
            "server_id": r.server_id,
            "event": r.event,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "exit_code": r.exit_code,
            "command_hash": r.command_hash,
        } for r in rows]
    labels = server_meta([r["server_id"] for r in out])
    for r in out:
        r["server_label"] = labels.get(r["server_id"] or "", {}).get("label", "")
    return out


# ---------------------------------------------------------------------------
# TOFU host keys
# ---------------------------------------------------------------------------

def _fingerprint_sha256(key_b64: str) -> str:
    raw = base64.b64decode(key_b64.encode("ascii"))
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _host_forms(host: str, port: int) -> List[str]:
    """known_hosts host forms for a host:port pair.

    A non-default port is keyed as ``[host]:port`` by both OpenSSH and paramiko,
    while a plain ``host`` entry is what ssh-keyscan prints. Writing both forms
    means neither client can miss the pin regardless of which name it looks up,
    and the DB pin (fingerprints) stays the single source of truth.
    """
    bare = host.rsplit("@", 1)[-1]
    if int(port) == 22:
        return [bare]
    return [bare, f"[{bare}]:{int(port)}"]


def capture_host_key(host: str, port: int) -> Dict[str, Any]:
    """Run ssh-keyscan; return every host key it reports for this host.

    A server offers several key types (ed25519, rsa, ecdsa…) and ssh/paramiko
    negotiate one of them, so pinning only the first would fail closed on a
    reconnect that negotiates a different type. Returns ``lines`` (known_hosts
    shape), ``keys``, and ``fingerprints`` — plus ``fingerprint`` (the first) for
    the UI. Raises when nothing is reported.
    """
    keyscan = shutil.which("ssh-keyscan")
    if not keyscan:
        raise RuntimeError("ssh-keyscan not found — install openssh-client")
    bare = host.rsplit("@", 1)[-1]
    # Probe an explicit, classic key-type list. ssh-keyscan's default set now
    # includes exotic types (sk-*, hybrid ML-DSA) that a normal server host key
    # never matches, and ssh-keyscan opens one connection *per* type, so the
    # defaults mean a burst of connections that negotiate nothing. OpenSSH ≥9.8
    # counts exactly those against `PerSourcePenalties` and will start dropping
    # connections from this host — a real hazard for a user's own server, not
    # just a test-harness one.
    argv = [keyscan, "-T", str(CONNECT_TIMEOUT), "-t", "rsa,ecdsa,ed25519"]
    if port != 22:
        argv += ["-p", str(port)]
    argv.append(bare)
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    lines: List[str] = []
    keys: List[Dict[str, str]] = []
    for line in (r.stdout or "").splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and not parts[0].startswith("#"):
            keytype, key = parts[1], parts[2]
            try:
                fp = _fingerprint_sha256(key)
            except Exception:
                continue  # not a key we can fingerprint: skip, don't pin blindly
            for form in _host_forms(bare, port):
                lines.append(f"{form} {keytype} {key}")
            keys.append({"keytype": keytype, "key": key, "fingerprint": fp})
    if not keys:
        raise RuntimeError(f"ssh-keyscan found no host key for {bare}: {(r.stderr or '').strip()[:200]}")
    return {"lines": lines, "keys": keys,
            "fingerprints": [k["fingerprint"] for k in keys],
            "fingerprint": keys[0]["fingerprint"]}


def _pins(srv: Dict[str, Any]) -> List[str]:
    """Fingerprints pinned for a server (comma-joined in the DB column)."""
    return [p for p in str(srv.get("host_key_fingerprint") or "").split(",") if p]


def _write_pin_file(server_id: str, lines: List[str]) -> None:
    """Rewrite the per-server known_hosts file (0600)."""
    if not lines:
        return
    _known_hosts_dir().mkdir(parents=True, exist_ok=True)
    kh = _pinned_known_hosts_path(server_id)
    kh.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(kh, 0o600)
    except OSError:
        pass


def _drop_pin_file(server_id: str) -> None:
    try:
        kh = _pinned_known_hosts_path(server_id)
        if kh.exists():
            kh.unlink()
    except OSError:
        pass


def _collect_pins(host: str, port: int, *, fallback_fingerprint: str = "",
                  fallback_line: str = "") -> tuple:
    """All pin material for a host, preferring ssh-keyscan's complete key set.

    paramiko only ever sees the one key type it negotiates, which is not enough
    for the argv path's known_hosts file. Returns (fingerprints, lines, primary).
    Falls back to the negotiated key when ssh-keyscan is unavailable.
    """
    try:
        scanned = capture_host_key(host, port)
        fprints = list(scanned["fingerprints"])
        lines = list(scanned["lines"])
        if fallback_fingerprint and fallback_fingerprint not in fprints:
            fprints.insert(0, fallback_fingerprint)
            if fallback_line:
                lines.insert(0, fallback_line)
        return fprints, lines, fprints[0]
    except Exception:
        if not fallback_fingerprint:
            raise
        return [fallback_fingerprint], ([fallback_line] if fallback_line else []), fallback_fingerprint


def _mark_tested(owner: str, server_id: str, fingerprints: str) -> None:
    from datetime import datetime, timezone
    with _session() as db:
        row = _get_row(db, owner, server_id)
        row.host_key_fingerprint = fingerprints or None
        row.last_tested_at = datetime.now(timezone.utc).replace(tzinfo=None)
        row.last_test_result = "ok"


def _server_secrets(owner: str, server_id: str) -> Dict[str, str]:
    """Decrypt this server's stored secrets. Owner-scoped; never logged."""
    with _session() as db:
        row = _get_row(db, owner, server_id)
        return {"password": row.password or "", "sudo_password": row.sudo_password or ""}


def _resolve_auth(owner: str, srv: Dict[str, Any], secrets: Dict[str, str],
                  *, force_paramiko: bool = False):
    """Pick a transport for this server. Returns ``(plan, error)``.

    ``paramiko`` plans carry the password/SFTP/terminal path; ``key-only`` plans
    keep the OpenSSH argv path (unchanged Phase 1 behaviour). ``force_paramiko``
    asks for the library transport even for a key-only server — the interactive
    terminal has no argv equivalent. A requested transport with no credential is
    a clear error, never a silent downgrade.
    """
    auth = srv.get("auth_type") or "key"
    key = user_key_paths(owner)["private"]
    password = secrets.get("password") or ""
    if auth == "password":
        if not password:
            return None, "no password stored — edit this server and add one"
        if not srv.get("username"):
            return None, "a username is required for password auth"
        return {"paramiko": True, "password": password, "key_path": None}, ""
    if auth == "both":
        if password:
            if not srv.get("username"):
                return None, "a username is required for password auth"
            return {"paramiko": True, "password": password,
                    "key_path": key if key.exists() else None}, ""
        if key.exists():
            if force_paramiko and not srv.get("username"):
                return None, "a username is required for this server"
            return {"paramiko": bool(force_paramiko), "password": "", "key_path": key}, ""
        return None, "no password stored and no SSH key for this user — add one"
    if not key.exists():
        return None, "no SSH key for this user — generate one first"
    if force_paramiko and not srv.get("username"):
        return None, "a username is required for this server"
    return {"paramiko": bool(force_paramiko), "password": "", "key_path": key}, ""


def _pinned_known_hosts_path(server_id: str) -> Path:
    return _known_hosts_dir() / server_id


def _ssh_argv(remote: str, port: int, server_id: str) -> List[str]:
    from core.platform_compat import _ssh_exec_argv
    argv = _ssh_exec_argv(
        remote, str(port),
        connect_timeout=CONNECT_TIMEOUT, strict_host_key_checking=True,
    )
    # Replace the default known_hosts with the per-server pinned file.
    argv[1:1] = ["-o", f"UserKnownHostsFile={_pinned_known_hosts_path(server_id)}"]
    return argv


def test_connection(owner: str, ref: str) -> Dict[str, Any]:
    """Connect and run `true`. Pins TOFU fingerprints on first success.

    Returns ok, fingerprint, latency_ms. A pinned-but-changed key fails closed
    before any credential is sent. Audited.
    """
    import time
    srv = resolve_server(owner, ref)
    remote = f"{srv['username']}@{srv['host']}" if srv["username"] else srv["host"]
    _require_allowed(remote, int(srv["port"]))
    secrets = _server_secrets(owner, srv["id"])
    plan, auth_err = _resolve_auth(owner, srv, secrets)
    if plan is None:
        audit(owner, srv["id"], "test", "", 1)
        return {"ok": False, "error": auth_err, "exit_code": 1}
    pins = _pins(srv)

    if plan["paramiko"]:
        from src import ssh_client
        try:
            res = ssh_client.test_login(
                srv["host"], int(srv["port"]), srv["username"],
                password=plan["password"], key_path=plan["key_path"],
                server_id=srv["id"], expected_fingerprints=pins,
            )
        except ssh_client.HostKeyChangedError:
            audit(owner, srv["id"], "test", "", 1)
            return {"ok": False, "exit_code": 1, "error": (
                "HOST KEY CHANGED — refusing to connect. Verify the server, "
                "then re-run Test to re-pin.")}
        except ssh_client.SshClientError as exc:
            audit(owner, srv["id"], "test", "", 1)
            return {"ok": False, "error": str(exc)[:300], "exit_code": 1}
        except Exception as exc:
            audit(owner, srv["id"], "test", "", 1)
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300], "exit_code": 1}
        if not res["ok"]:
            audit(owner, srv["id"], "test", "", int(res.get("exit_code") or 1))
            return {"ok": False, "exit_code": int(res.get("exit_code") or 1),
                    "error": (res.get("stderr") or "connection failed")[:300]}
        fingerprints, lines, primary = _collect_pins(
            srv["host"], int(srv["port"]),
            fallback_fingerprint=res.get("fingerprint") or "",
            fallback_line=res.get("key_line") or "",
        )
        _write_pin_file(srv["id"], lines)
        _mark_tested(owner, srv["id"], ",".join(fingerprints))
        audit(owner, srv["id"], "test", "", 0)
        return {"ok": True, "fingerprint": primary, "latency_ms": res["latency_ms"],
                "exit_code": 0, "pinned": not bool(pins)}

    # Key-only: the OpenSSH argv transport (unchanged Phase 1 path).
    try:
        scanned = capture_host_key(srv["host"], int(srv["port"]))
    except Exception as exc:
        audit(owner, srv["id"], "test", "", 1)
        return {"ok": False, "error": str(exc)[:300], "exit_code": 1}
    if pins and not (set(scanned["fingerprints"]) & set(pins)):
        audit(owner, srv["id"], "test", "", 1)
        return {"ok": False, "exit_code": 1, "fingerprint": scanned["fingerprint"],
                "expected_fingerprint": srv["host_key_fingerprint"], "error": (
                    "HOST KEY CHANGED — refusing to connect. Verify the server, "
                    "then re-run Test to re-pin.")}
    t0 = time.monotonic()
    try:
        argv = _ssh_argv(remote, int(srv["port"]), srv["id"])
        argv[1:1] = ["-i", str(plan["key_path"]), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
        _write_pin_file(srv["id"], scanned["lines"])
        r = subprocess.run(argv + ["true"], capture_output=True, text=True, timeout=30)
        ms = int((time.monotonic() - t0) * 1000)
    except subprocess.TimeoutExpired:
        audit(owner, srv["id"], "test", "", 1)
        return {"ok": False, "error": "connection timed out", "exit_code": 1}
    if r.returncode != 0:
        err = ((r.stderr or "").strip() or "ssh test failed")[:300]
        audit(owner, srv["id"], "test", "", r.returncode)
        return {"ok": False, "error": err, "exit_code": r.returncode, "fingerprint": scanned["fingerprint"]}
    _mark_tested(owner, srv["id"], ",".join(scanned["fingerprints"]))
    audit(owner, srv["id"], "test", "", 0)
    return {"ok": True, "fingerprint": scanned["fingerprint"], "latency_ms": ms, "exit_code": 0,
            "pinned": not bool(pins)}


def _truncate(text: str) -> str:
    from src.constants import MAX_OUTPUT_CHARS
    if len(text) > MAX_OUTPUT_CHARS:
        return text[:MAX_OUTPUT_CHARS] + f"\n... (truncated at {MAX_OUTPUT_CHARS} chars)"
    return text


def exec_one_shot(owner: str, ref: str, cmd: str,
                  timeout: Any = EXEC_DEFAULT_TIMEOUT,
                  stdin_text: str = "") -> Dict[str, Any]:
    """Run one command on a saved server. Saved-servers-only (no ad-hoc hosts)."""
    srv = resolve_server(owner, ref)
    command = (cmd or "").strip()
    if not command:
        return {"error": "cmd is required", "exit_code": 1}
    try:
        timeout_s = int(timeout) if timeout else EXEC_DEFAULT_TIMEOUT
    except (ValueError, TypeError):
        timeout_s = EXEC_DEFAULT_TIMEOUT
    timeout_s = max(1, min(timeout_s, EXEC_MAX_TIMEOUT))
    remote = f"{srv['username']}@{srv['host']}" if srv["username"] else srv["host"]
    _require_allowed(remote, int(srv["port"]))
    if not srv["host_key_fingerprint"]:
        return {"error": "server has no pinned host key — run Test first", "exit_code": 1}
    secrets = _server_secrets(owner, srv["id"])
    plan, auth_err = _resolve_auth(owner, srv, secrets)
    if plan is None:
        return {"error": auth_err, "exit_code": 1}

    if plan["paramiko"]:
        from src import ssh_client
        try:
            r = ssh_client.run_command(
                srv["host"], int(srv["port"]), srv["username"], command,
                password=plan["password"], key_path=plan["key_path"],
                server_id=srv["id"], expected_fingerprints=_pins(srv),
                timeout=timeout_s, stdin_text=stdin_text,
                sudo_password=secrets.get("sudo_password") or "",
            )
        except ssh_client.SshTimeoutError:
            audit(owner, srv["id"], "exec", command, 124)
            return {"error": f"command timed out after {timeout_s}s", "exit_code": 124,
                    "host": srv["host"], "server_id": srv["id"]}
        except ssh_client.SshClientError as exc:
            audit(owner, srv["id"], "exec", command, 1)
            return {"error": str(exc)[:300], "exit_code": 1,
                    "host": srv["host"], "server_id": srv["id"]}
        except Exception as exc:
            audit(owner, srv["id"], "exec", command, 1)
            return {"error": f"{type(exc).__name__}: {exc}"[:300], "exit_code": 1,
                    "host": srv["host"], "server_id": srv["id"]}
        code = int(r["exit_code"])
        audit(owner, srv["id"], "exec", command, code)
        out = _truncate(r["stdout"] or "")
        err = _truncate((r["stderr"] or "").strip())
        res: Dict[str, Any] = {"output": out, "stdout": out, "exit_code": code,
                               "host": srv["host"], "server_id": srv["id"]}
        if err:
            res["stderr"] = err
        return res

    from src import ssh_client as _ssh_client
    argv_command, sudo_stdin = _ssh_client.apply_sudo(command, secrets.get("sudo_password") or "")
    if sudo_stdin and not stdin_text:
        stdin_text = sudo_stdin
    argv = _ssh_argv(remote, int(srv["port"]), srv["id"])
    argv[1:1] = ["-i", str(plan["key_path"]), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
    try:
        r = subprocess.run(argv + [argv_command], input=(stdin_text or None),
                           capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        audit(owner, srv["id"], "exec", command, 124)
        return {"error": f"command timed out after {timeout_s}s", "exit_code": 124,
                "host": srv["host"], "server_id": srv["id"]}
    audit(owner, srv["id"], "exec", command, r.returncode)
    out = _truncate(r.stdout or "")
    err = _truncate((r.stderr or "").strip())
    res = {"output": out, "stdout": out, "exit_code": r.returncode,
           "host": srv["host"], "server_id": srv["id"]}
    if err:
        res["stderr"] = err
    return res


def transfer(owner: str, ref: str, direction: str,
             local_path: str, remote_path: str) -> Dict[str, Any]:
    """Upload/download to a saved server. Local side is workspace-resolved by caller."""
    if direction not in ("upload", "download"):
        return {"error": "direction must be upload or download", "exit_code": 1}
    if not (local_path or "").strip() or not (remote_path or "").strip():
        return {"error": "local_path and remote_path are required", "exit_code": 1}
    srv = resolve_server(owner, ref)
    remote = f"{srv['username']}@{srv['host']}" if srv["username"] else srv["host"]
    _require_allowed(remote, int(srv["port"]))
    if not srv["host_key_fingerprint"]:
        return {"error": "server has no pinned host key — run Test first", "exit_code": 1}
    secrets = _server_secrets(owner, srv["id"])
    plan, auth_err = _resolve_auth(owner, srv, secrets)
    if plan is None:
        return {"error": auth_err, "exit_code": 1}

    if plan["paramiko"]:
        from src import ssh_client
        try:
            ssh_client.sftp_transfer(
                srv["host"], int(srv["port"]), srv["username"], direction,
                local_path=local_path.strip(), remote_path=remote_path.strip(),
                password=plan["password"], key_path=plan["key_path"],
                server_id=srv["id"], expected_fingerprints=_pins(srv),
            )
        except ssh_client.SshClientError as exc:
            audit(owner, srv["id"], direction, remote_path, 1)
            return {"error": str(exc)[:300], "exit_code": 1}
        except Exception as exc:
            audit(owner, srv["id"], direction, remote_path, 1)
            return {"error": f"{type(exc).__name__}: {exc}"[:300], "exit_code": 1}
        audit(owner, srv["id"], direction, remote_path, 0)
        return {"output": f"{direction} ok: {remote_path}", "exit_code": 0,
                "host": srv["host"], "server_id": srv["id"]}

    scp = shutil.which("scp")
    if not scp:
        return {"error": "scp not found — install openssh-client", "exit_code": 1}
    base = [scp, "-i", str(plan["key_path"]), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", f"UserKnownHostsFile={_pinned_known_hosts_path(srv['id'])}",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={CONNECT_TIMEOUT}"]
    if int(srv["port"]) != 22:
        base += ["-P", str(int(srv["port"]))]
    target = f"{remote}:{remote_path.strip()}"
    argv = base + ([local_path.strip(), target] if direction == "upload"
                   else [target, local_path.strip()])
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        audit(owner, srv["id"], direction, remote_path, 124)
        return {"error": "transfer timed out", "exit_code": 124}
    audit(owner, srv["id"], direction, remote_path, r.returncode)
    if r.returncode != 0:
        return {"error": ((r.stderr or "").strip() or "scp failed")[:300], "exit_code": r.returncode}
    return {"output": f"{direction} ok: {remote_path}", "exit_code": 0,
            "host": srv["host"], "server_id": srv["id"]}


# ---------------------------------------------------------------------------
# Interactive terminal (Phase 2, spec §6.3)
# ---------------------------------------------------------------------------

def open_terminal_for(owner: str, ref: str, *, cols: int = 100,
                      rows: int = 30) -> Dict[str, Any]:
    """Open a PTY-backed interactive shell on a saved server.

    Returns {session_id, server_id, target, port}. The per-user session cap and
    idle reaping live in ``src/ssh_client.py``. Audited.
    """
    from src import ssh_client
    srv = resolve_server(owner, ref)
    remote = f"{srv['username']}@{srv['host']}" if srv["username"] else srv["host"]
    _require_allowed(remote, int(srv["port"]))
    if not srv["host_key_fingerprint"]:
        raise ValueError("server has no pinned host key — run Test first")
    secrets = _server_secrets(owner, srv["id"])
    plan, auth_err = _resolve_auth(owner, srv, secrets, force_paramiko=True)
    if plan is None:
        raise ValueError(auth_err)
    session = ssh_client.open_terminal(
        owner, srv["host"], int(srv["port"]), srv["username"],
        server_id=srv["id"], password=plan["password"], key_path=plan["key_path"],
        expected_fingerprints=_pins(srv), cols=cols, rows=rows,
    )
    audit(owner, srv["id"], "terminal_open", "", 0)
    return {"session_id": session.id, "server_id": srv["id"],
            "target": remote, "port": srv["port"], "label": srv["label"]}


def close_terminal_for(owner: str, session_id: str) -> None:
    """Close an interactive session owned by ``owner`` and audit it."""
    from src import ssh_client
    session = ssh_client.get_terminal(owner, session_id)
    server_id = session.server_id
    ssh_client.close_terminal(owner, session_id)
    audit(owner, server_id, "terminal_closed", "", 0)


def rotate_user_key(owner: str) -> Dict[str, Any]:
    """Generate a fresh keypair, keeping one .bak. Filename stable => no DB change."""
    info = generate_user_key(owner, force=True)
    audit(owner, "", "key_rotated", "", 0)
    return info
