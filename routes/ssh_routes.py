"""SSH routes — owner-scoped saved servers, one-shot exec, transfer, terminal.

Any authenticated user may manage and use ONLY their own servers
(no admin gate; cross-owner access is denied by construction in
src.ssh_remote). The in-process `internal-tool` marker is rejected —
it is a loopback identity, never a server owner.

The interactive terminal (spec §6.3) relays a paramiko PTY over SSE using the
same frame shape as `routes/shell_routes._generate_pty`:
``data: {"stream": "stdout", "data": ...}`` … ``data: {"exit_code": N}``. The
local shell PTY in shell_routes stays admin-only; this is a *remote* session on
a saved server, owner-scoped and capped at 3 per user.
"""

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
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


class TerminalOpen(BaseModel):
    cols: Any = 100
    rows: Any = 30


class TerminalInput(BaseModel):
    data: str = ""


class TerminalResize(BaseModel):
    cols: Any = 100
    rows: Any = 30


# One keystroke batch is small; a large paste is still bounded (spec §6.4).
MAX_TERMINAL_INPUT_CHARS = 8192


def _owner(request: Request) -> str:
    user = get_current_user(request)
    if not user or user in ("internal-tool", "api"):
        raise HTTPException(401, "Not authenticated")
    return user


def _to_400(exc: Exception) -> HTTPException:
    return HTTPException(400, str(exc)[:300])


def _terminal_session(owner: str, server_id: str, session_id: str):
    """Fetch a session, enforcing both owner and server binding. 404 otherwise."""
    from src import ssh_client
    try:
        session = ssh_client.get_terminal(owner, session_id)
    except LookupError:
        raise HTTPException(404, "Terminal session not found")
    if session.server_id != server_id:
        raise HTTPException(404, "Terminal session not found")
    return session


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

    @router.post("/api/ssh/servers/{server_id}/terminal")
    async def ssh_terminal_open(request: Request, server_id: str, req: TerminalOpen):
        from src import ssh_remote as ssh
        from src import ssh_client
        owner = _owner(request)
        _check_rate_limit(owner)
        # Absent/None means "default"; a present value is clamped, never silently
        # swapped for the default (a caller asking for 0 gets the floor).
        try:
            cols = int(req.cols) if req.cols is not None else 100
            rows = int(req.rows) if req.rows is not None else 30
        except (TypeError, ValueError):
            raise HTTPException(400, "cols and rows must be integers")
        cols = max(20, min(cols, 400))
        rows = max(5, min(rows, 200))
        try:
            info = await asyncio.to_thread(
                ssh.open_terminal_for, owner, server_id, cols=cols, rows=rows)
        except LookupError:
            raise HTTPException(404, "Server not found")
        except ValueError as e:
            raise _to_400(e)
        except ssh_client.SshClientError as e:
            raise _to_400(e)
        return {"ok": True, **info}

    @router.get("/api/ssh/servers/{server_id}/terminal/{session_id}/stream")
    async def ssh_terminal_stream(request: Request, server_id: str, session_id: str):
        from src import ssh_client
        owner = _owner(request)
        session = _terminal_session(owner, server_id, session_id)

        async def generate():
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    chunk = await asyncio.to_thread(session.read, 0.25)
                    if chunk is None:
                        yield f"data: {json.dumps({'exit_code': session.exit_status()})}\n\n"
                        return
                    if chunk:
                        yield f"data: {json.dumps({'stream': 'stdout', 'data': chunk})}\n\n"
            except Exception as exc:  # transport died mid-stream
                logger.debug("ssh terminal stream ended: %s", exc)
            finally:
                # A dropped browser must free the remote PTY; the idle reaper
                # covers a client that hangs without disconnecting.
                try:
                    ssh_client.close_terminal_by_id(session_id)
                except Exception:
                    pass

        return StreamingResponse(generate(), media_type="text/event-stream")

    @router.post("/api/ssh/servers/{server_id}/terminal/{session_id}/input")
    async def ssh_terminal_input(request: Request, server_id: str,
                                 session_id: str, req: TerminalInput):
        owner = _owner(request)
        session = _terminal_session(owner, server_id, session_id)
        data = req.data or ""
        if len(data) > MAX_TERMINAL_INPUT_CHARS:
            raise HTTPException(400, "terminal input too large")
        if data:
            try:
                await asyncio.to_thread(session.write, data)
            except Exception as e:
                raise HTTPException(400, f"terminal write failed: {e}"[:300])
        return {"ok": True, "bytes": len(data)}

    @router.post("/api/ssh/servers/{server_id}/terminal/{session_id}/resize")
    async def ssh_terminal_resize(request: Request, server_id: str,
                                  session_id: str, req: TerminalResize):
        owner = _owner(request)
        session = _terminal_session(owner, server_id, session_id)
        try:
            cols = int(req.cols) if req.cols is not None else 100
            rows = int(req.rows) if req.rows is not None else 30
        except (TypeError, ValueError):
            raise HTTPException(400, "cols and rows must be integers")
        cols = max(20, min(cols, 400))
        rows = max(5, min(rows, 200))
        try:
            await asyncio.to_thread(session.resize, cols, rows)
        except Exception as e:
            raise HTTPException(400, f"terminal resize failed: {e}"[:300])
        return {"ok": True, "cols": cols, "rows": rows}

    @router.delete("/api/ssh/servers/{server_id}/terminal/{session_id}")
    async def ssh_terminal_close(request: Request, server_id: str, session_id: str):
        from src import ssh_remote as ssh
        owner = _owner(request)
        _terminal_session(owner, server_id, session_id)
        try:
            await asyncio.to_thread(ssh.close_terminal_for, owner, session_id)
        except LookupError:
            raise HTTPException(404, "Terminal session not found")
        return {"ok": True}

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
