"""SSH routes — owner-scoped saved servers, one-shot exec, transfer.

Any authenticated user may manage and use ONLY their own servers
(no admin gate; cross-owner access is denied by construction in
src.ssh_remote). The in-process `internal-tool` marker is rejected —
it is a loopback identity, never a server owner.
"""

import logging
import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.auth_helpers import get_current_user

logger = logging.getLogger(__name__)

# Simple per-user rate limit for connection-touching endpoints (spec §6.4).
_RATE_LIMIT = 30
_RATE_WINDOW_S = 60.0
_hits: Dict[str, deque] = defaultdict(deque)


def _check_rate_limit(owner: str) -> None:
    now = time.monotonic()
    q = _hits[owner]
    while q and now - q[0] > _RATE_WINDOW_S:
        q.popleft()
    if len(q) >= _RATE_LIMIT:
        raise HTTPException(429, "Rate limit exceeded — slow down")
    q.append(now)


class ServerCreate(BaseModel):
    label: str = ""
    host: str = ""
    port: Any = 22
    username: str = ""
    auth_type: str = "key"
    password: str = ""
    sudo_password: str = ""


class ServerUpdate(BaseModel):
    label: Optional[str] = None
    host: Optional[str] = None
    port: Any = None
    username: Optional[str] = None
    auth_type: Optional[str] = None
    password: Optional[str] = None
    sudo_password: Optional[str] = None


class ExecRequest(BaseModel):
    cmd: str = ""
    timeout: Any = 30
    stdin: str = ""


class TransferRequest(BaseModel):
    direction: str = "upload"
    local_path: str = ""
    remote_path: str = ""


def _owner(request: Request) -> str:
    user = get_current_user(request)
    if not user or user in ("internal-tool", "api"):
        raise HTTPException(401, "Not authenticated")
    return user


def _to_400(exc: Exception) -> HTTPException:
    return HTTPException(400, str(exc)[:300])


def setup_ssh_routes() -> APIRouter:
    router = APIRouter(tags=["ssh"])

    @router.get("/api/ssh/servers")
    async def list_ssh_servers(request: Request):
        from src import ssh_remote as ssh
        return {"servers": ssh.list_servers(_owner(request))}

    @router.post("/api/ssh/servers")
    async def create_ssh_server(request: Request, req: ServerCreate):
        from src import ssh_remote as ssh
        owner = _owner(request)
        try:
            srv = ssh.create_server(
                owner, label=req.label, host=req.host, port=req.port,
                username=req.username, auth_type=req.auth_type,
                password=req.password, sudo_password=req.sudo_password,
            )
        except ValueError as e:
            raise _to_400(e)
        return {"ok": True, "server": srv}

    @router.patch("/api/ssh/servers/{server_id}")
    async def update_ssh_server(request: Request, server_id: str, req: ServerUpdate):
        from src import ssh_remote as ssh
        owner = _owner(request)
        try:
            srv = ssh.update_server(owner, server_id, **req.model_dump())
        except LookupError:
            raise HTTPException(404, "Server not found")
        except ValueError as e:
            raise _to_400(e)
        return {"ok": True, "server": srv}

    @router.delete("/api/ssh/servers/{server_id}")
    async def delete_ssh_server(request: Request, server_id: str):
        from src import ssh_remote as ssh
        owner = _owner(request)
        try:
            ssh.delete_server(owner, server_id)
        except LookupError:
            raise HTTPException(404, "Server not found")
        return {"ok": True}

    @router.get("/api/ssh/servers/{server_id}/pubkey")
    async def ssh_pubkey(request: Request, server_id: str):
        from src import ssh_remote as ssh
        owner = _owner(request)
        try:
            ssh.resolve_server(owner, server_id)
        except (LookupError, ValueError):
            raise HTTPException(404, "Server not found")
        info = ssh.generate_user_key(owner)
        return {"ok": True, "public_key": info["public_key"],
                "ssh_copy_hint": f"ssh-copy-id -i {info['public_path']} user@host"}

    @router.post("/api/ssh/servers/{server_id}/test")
    async def ssh_test(request: Request, server_id: str):
        from src import ssh_remote as ssh
        owner = _owner(request)
        _check_rate_limit(owner)
        try:
            res = ssh.test_connection(owner, server_id)
        except (LookupError, ValueError) as e:
            raise HTTPException(404 if isinstance(e, LookupError) else 400,
                                str(e)[:300])
        return res

    @router.post("/api/ssh/servers/{server_id}/exec")
    async def ssh_exec_route(request: Request, server_id: str, req: ExecRequest):
        from src import ssh_remote as ssh
        from src.prompt_security import wrap_untrusted_text
        owner = _owner(request)
        _check_rate_limit(owner)
        try:
            res = ssh.exec_one_shot(owner, server_id, req.cmd,
                                    timeout=req.timeout, stdin_text=req.stdin)
        except (LookupError, ValueError) as e:
            raise HTTPException(404 if isinstance(e, LookupError) else 400,
                                str(e)[:300])
        if res.get("output"):
            res["output"] = wrap_untrusted_text(f"ssh {res.get('server_id', '')}", res["output"])
        return res

    @router.post("/api/ssh/servers/{server_id}/upload")
    @router.post("/api/ssh/servers/{server_id}/transfer")
    async def ssh_transfer(request: Request, server_id: str, req: TransferRequest):
        from src import ssh_remote as ssh
        from src.tool_execution import _resolve_tool_path
        owner = _owner(request)
        _check_rate_limit(owner)
        try:
            local = _resolve_tool_path(req.local_path)
        except ValueError as e:
            raise _to_400(e)
        try:
            res = ssh.transfer(owner, server_id, req.direction, local, req.remote_path)
        except (LookupError, ValueError) as e:
            raise HTTPException(404 if isinstance(e, LookupError) else 400,
                                str(e)[:300])
        return res

    @router.post("/api/ssh/keygen")
    async def ssh_keygen(request: Request):
        from src import ssh_remote as ssh
        owner = _owner(request)
        try:
            info = ssh.generate_user_key(owner)
        except RuntimeError as e:
            raise HTTPException(500, str(e)[:300])
        info.pop("private", None)
        return {"ok": True, **info}

    return router
