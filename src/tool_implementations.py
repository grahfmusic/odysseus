"""
tool_implementations.py

Compatibility facade over the src/tools/* domain modules (and the admin
tools in src/agent_tools/admin_tools). Everything is re-exported so existing
``from src.tool_implementations import X`` imports keep resolving; the
contract is pinned by tests/test_tool_implementations_shim.py.

Implemented here (not in a domain module): the active-email UI helpers and
the SSH remote-execution tools (do_ssh_exec, do_list_ssh_servers).
"""

import logging
from typing import Dict, Optional

from src.tool_utils import get_mcp_manager  # re-exported: tests patch src.tool_implementations.get_mcp_manager

# System-domain tools were extracted to src/tools/system.py (slice 1,
# #4082/#4071); the admin manage_* tools live in src/agent_tools/admin_tools
# after the upstream registry migration (#3629). Re-imported here so this
# module stays a working facade.
from src.tools.system import (  # noqa: F401
    do_manage_skills, _skill_dump, do_manage_tasks,
    do_api_call, do_app_api,
    _APP_API_BLOCKLIST_PREFIXES, _APP_API_BLOCKLIST_METHOD_PATH,
    _ssh_app_api_blocked,
)
# Admin manage_* tools (endpoints/mcp/webhooks/tokens/settings) live in
# src/agent_tools/admin_tools after the upstream registry migration (#3629).
# Re-exported lazily via __getattr__: src.agent_tools.__init__ imports this
# facade at top level, so a eager `from src.agent_tools.admin_tools import`
# here would re-enter the partially-initialized agent_tools package (circular).
_ADMIN_TOOL_SYMBOLS = (
    "do_manage_endpoints", "do_manage_mcp", "do_manage_webhooks",
    "do_manage_tokens", "do_manage_settings",
    "_MCP_DENIED_COMMANDS", "_validate_mcp_command", "_mcp_allowed_commands",
)


def __getattr__(name):
    if name in _ADMIN_TOOL_SYMBOLS:
        from src.agent_tools import admin_tools
        return getattr(admin_tools, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# Cookbook (model serving) domain extracted to src/tools/cookbook.py
# (slice 1, #4082/#4071). Re-imported here so this module stays a working
# facade. cookbook.py pulls `_internal_headers` / `_INTERNAL_BASE` back
# function-locally from this facade (which re-exports them from _common).
from src.tools.cookbook import (  # noqa: F401
    do_download_model, do_serve_model, do_list_served_models,
    do_stop_served_model, do_tail_serve_output, do_list_downloads,
    do_cancel_download, do_search_hf_models, do_adopt_served_model,
    do_list_cookbook_servers, do_list_serve_presets, do_serve_preset,
    do_list_cached_models,
    _cookbook_servers, _resolve_cookbook_host, _cookbook_env_for_host,
    _infer_serve_port, _infer_serve_host, _ensure_served_endpoint,
    _cookbook_register_task, _cookbook_apply_retry_suggestion,
    _scan_running_model_processes, _cookbook_kill_session,
    _MODEL_PROCESS_PATTERNS,
    _string_arg, _validate_cookbook_ssh_target,
)
# Search domain extracted to src/tools/search.py (slice 1, #4082/#4071).
# Re-imported here so this module stays a working facade.
from src.tools.search import do_search_chats  # noqa: F401
# Notes domain extracted to src/tools/notes.py (slice 1, #4082/#4071).
from src.tools.notes import do_manage_notes  # noqa: F401
# Calendar domain extracted to src/tools/calendar.py (slice 1, #4082/#4071).
from src.tools.calendar import do_manage_calendar  # noqa: F401
# Image domain extracted to src/tools/image.py (slice 1, #4082/#4071).
from src.tools.image import do_edit_image  # noqa: F401
# Research domain extracted to src/tools/research.py (slice 1, #4082/#4071).
from src.tools.research import do_manage_research, do_trigger_research  # noqa: F401
# Contacts domain extracted to src/tools/contacts.py (slice 1, #4082/#4071).
from src.tools.contacts import do_resolve_contact, do_manage_contact  # noqa: F401
# Vault domain extracted to src/tools/vault.py (slice 1, #4082/#4071).
from src.tools.vault import (  # noqa: F401
    _load_vault_config, _run_bw,
    do_vault_search, do_vault_get, do_vault_unlock,
)
# Shared helpers live in src/tools/_common.py. Re-exported here so the
# function-local `from src.tool_implementations import _INTERNAL_BASE` (and
# friends) used by domain files still resolve through this facade.
from src.tools._common import _parse_tool_args, _INTERNAL_BASE, _internal_headers  # noqa: F401

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Active email state
# ---------------------------------------------------------------------------

# When the user has an email reader window open, the frontend tells the
# backend about it on each chat submit. Email tools can resolve "this email"
# without guessing a UID. Cleared between requests by chat_routes.
_active_email_ref: Optional[Dict[str, str]] = None


def set_active_email(uid: Optional[str], folder: Optional[str] = None, account: Optional[str] = None,
                     subject: Optional[str] = None, sender: Optional[str] = None) -> None:
    """Stash the email currently open in the UI. None clears it."""
    global _active_email_ref
    if not uid:
        _active_email_ref = None
        return
    _active_email_ref = {
        "uid": str(uid),
        "folder": str(folder or "INBOX"),
        "account": str(account or ""),
        "subject": str(subject or ""),
        "from": str(sender or ""),
    }


def get_active_email() -> Optional[Dict[str, str]]:
    return _active_email_ref


def clear_active_email() -> None:
    global _active_email_ref
    _active_email_ref = None


# ---------------------------------------------------------------------------
# SSH remote execution (owner-scoped saved servers). Implemented here;
# the app_api guard lives in src/tools/system.py next to the blocklists.
# ---------------------------------------------------------------------------


async def do_ssh_exec(content: str, owner: Optional[str] = None) -> Dict:
    """Run one command on one of the caller's saved SSH servers.

    Saved-servers-only: `server` is a server id or label (see list_ssh_servers).
    Raw hosts are never accepted — this bounds SSRF/pivot by construction.
    Remote output is untrusted: wrapped per prompt-security before return.
    """
    from src import ssh_remote as _ssh
    from src.prompt_security import wrap_untrusted_text
    try:
        args = _parse_tool_args(content)
    except ValueError:
        return {"error": "Invalid JSON arguments", "exit_code": 1}
    server = (args.get("server") or "").strip()
    cmd = args.get("cmd") or ""
    if not server:
        return {"error": "server is required (id or label from list_ssh_servers)", "exit_code": 1}
    if not owner:
        return {"error": "owner is required", "exit_code": 1}
    try:
        res = _ssh.exec_one_shot(owner, server, cmd,
                                 timeout=args.get("timeout"),
                                 stdin_text=args.get("stdin") or "")
    except LookupError as e:
        return {"error": str(e), "exit_code": 1}
    except ValueError as e:
        return {"error": str(e), "exit_code": 1}
    if "error" in res:
        return res
    label = f"ssh {res.get('server_id', '')}"
    res["output"] = wrap_untrusted_text(label, res.get("output", ""))
    res["stdout"] = res["output"]
    if res.get("stderr"):
        res["stderr"] = wrap_untrusted_text(label, res["stderr"])
    return res


async def do_list_ssh_servers(content: str, owner: Optional[str] = None) -> Dict:
    """List the caller's saved SSH servers (no secrets). Read-only."""
    from src import ssh_remote as _ssh
    if not owner:
        return {"error": "owner is required", "exit_code": 1}
    servers = _ssh.list_servers(owner)
    if not servers:
        return {"output": "No SSH servers saved. Add one in Machines.",
                "servers": [], "exit_code": 0}
    lines = [f"{len(servers)} saved SSH server(s):"]
    for s in servers:
        user = f"{s['username']}@" if s.get("username") else ""
        auth = f" [{s.get('auth_type')}]" if s.get("auth_type") else ""
        tested = " (tested ok)" if s.get("last_test_result") == "ok" else ""
        lines.append(f"- {s['label']} → {user}{s['host']}:{s.get('port')}{auth}{tested}")
    lines.append("\nRefer to a server by its label (or id) in ssh_exec.")
    return {"output": "\n".join(lines), "servers": servers, "exit_code": 0}

