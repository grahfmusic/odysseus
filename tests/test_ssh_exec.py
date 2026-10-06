"""Dispatch, gating, and app_api guard tests for ssh_exec / list_ssh_servers."""

import json

import pytest

from src.tool_security import (
    NON_ADMIN_BLOCKED_TOOLS,
    PLAN_MODE_READONLY_TOOLS,
    plan_mode_disabled_tools,
)
from src.tool_execution import _ADMIN_TOOLS
from src.tool_implementations import _ssh_app_api_blocked, do_app_api


class TestGates:
    def test_ssh_exec_usable_by_non_admin(self):
        assert "ssh_exec" not in NON_ADMIN_BLOCKED_TOOLS
        assert "ssh_exec" not in _ADMIN_TOOLS
        assert "list_ssh_servers" not in NON_ADMIN_BLOCKED_TOOLS
        assert "list_ssh_servers" not in _ADMIN_TOOLS

    def test_plan_mode_blocks_exec_allows_list(self):
        assert "ssh_exec" in plan_mode_disabled_tools()
        assert "list_ssh_servers" in PLAN_MODE_READONLY_TOOLS

    def test_schemas_registered(self):
        from src.tool_schemas import FUNCTION_TOOL_SCHEMAS
        names = {(t.get("function") or {}).get("name") for t in FUNCTION_TOOL_SCHEMAS}
        assert "ssh_exec" in names and "list_ssh_servers" in names

    def test_native_names_allowed(self):
        import src.agent_tools as at
        # The allowed-names set lives at module top; find the frozenset/set
        # containing cookbook tools and assert ours are alongside.
        found = False
        for value in vars(at).values():
            if isinstance(value, (set, frozenset)) and "list_cookbook_servers" in value:
                assert "ssh_exec" in value and "list_ssh_servers" in value
                found = True
        assert found


def _block(tool, content):
    from src.agent_tools import ToolBlock
    return ToolBlock(tool, content)


@pytest.mark.asyncio
async def test_ssh_exec_non_admin_allowed_own_server(monkeypatch):
    from src.tool_execution import NO_TOOL_SECURITY_CONTEXT, execute_tool_block
    from src import ssh_remote

    async def _no_admin(owner):
        return False

    monkeypatch.setattr("src.tool_execution._owner_is_admin", _no_admin)
    monkeypatch.setattr("src.tool_security.owner_is_admin_or_single_user", _no_admin)

    def _fake_exec(owner, ref, cmd, timeout=30, stdin_text=""):
        assert owner == "bob" and ref == "home" and cmd == "uptime"
        return {"output": "up", "stdout": "up", "exit_code": 0,
                "host": "h", "server_id": "abc123"}

    monkeypatch.setattr(ssh_remote, "exec_one_shot", _fake_exec)
    desc, result = await execute_tool_block(
        _block("ssh_exec", json.dumps({"server": "home", "cmd": "uptime"})),
        owner="bob",
        security_context=NO_TOOL_SECURITY_CONTEXT,
    )
    assert desc == "ssh_exec"
    assert result["exit_code"] == 0
    # Remote output must be wrapped as untrusted data.
    assert "UNTRUSTED" in result["output"]
    assert "up" in result["output"]


@pytest.mark.asyncio
async def test_ssh_exec_unknown_server_errors(monkeypatch):
    from src.tool_execution import NO_TOOL_SECURITY_CONTEXT, execute_tool_block
    from src import ssh_remote

    async def _no_admin(owner):
        return False

    monkeypatch.setattr("src.tool_execution._owner_is_admin", _no_admin)
    monkeypatch.setattr("src.tool_security.owner_is_admin_or_single_user", _no_admin)

    def _missing(owner, ref, cmd, timeout=30, stdin_text=""):
        raise LookupError("no server matches 'nope'")

    monkeypatch.setattr(ssh_remote, "exec_one_shot", _missing)
    _, result = await execute_tool_block(
        _block("ssh_exec", json.dumps({"server": "nope", "cmd": "uptime"})),
        owner="bob",
        security_context=NO_TOOL_SECURITY_CONTEXT,
    )
    assert result["exit_code"] == 1
    assert "nope" in result["error"]


@pytest.mark.asyncio
async def test_list_ssh_servers_dispatch(monkeypatch):
    from src.tool_execution import NO_TOOL_SECURITY_CONTEXT, execute_tool_block
    from src import ssh_remote

    async def _no_admin(owner):
        return False

    monkeypatch.setattr("src.tool_execution._owner_is_admin", _no_admin)
    monkeypatch.setattr("src.tool_security.owner_is_admin_or_single_user", _no_admin)
    monkeypatch.setattr(ssh_remote, "list_servers", lambda owner: [])
    _, result = await execute_tool_block(_block("list_ssh_servers", ""), owner="bob",
        security_context=NO_TOOL_SECURITY_CONTEXT)
    assert result["exit_code"] == 0


class TestAppApiGuard:
    def test_helper_blocks_exec_allows_reads(self):
        assert _ssh_app_api_blocked("POST", "/api/ssh/servers/abc/exec") is True
        assert _ssh_app_api_blocked("POST", "/api/ssh/servers/abc/upload") is True
        assert _ssh_app_api_blocked("POST", "/api/ssh/servers/abc/terminal") is True
        assert _ssh_app_api_blocked("DELETE", "/api/ssh/servers/abc") is True
        assert _ssh_app_api_blocked("GET", "/api/ssh/servers") is False
        assert _ssh_app_api_blocked("GET", "/api/ssh/servers/abc/pubkey") is False
        assert _ssh_app_api_blocked("POST", "/api/ssh/servers/abc/test") is False
        assert _ssh_app_api_blocked("GET", "/api/cookbook/gpus") is False

    @pytest.mark.asyncio
    async def test_app_api_refuses_exec_before_loopback(self, monkeypatch):
        import httpx

        class UnexpectedAsyncClient:
            def __init__(self, *a, **k):
                raise AssertionError("must block before loopback")

        monkeypatch.setattr(httpx, "AsyncClient", UnexpectedAsyncClient)
        result = await do_app_api(json.dumps({
            "action": "call", "method": "POST",
            "path": "/api/ssh/servers/abc/exec", "body": {"cmd": "id"},
        }), owner="admin")
        assert result["exit_code"] == 1
        assert "ssh_exec" in result["error"]
