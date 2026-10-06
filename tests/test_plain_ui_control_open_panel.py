import asyncio
from pathlib import Path

import pytest

import src.agent_tools  # noqa: F401  (break agent_tools<->tool_parsing import cycle)
from src.ai_interaction import do_ui_control
from src.tool_parsing import parse_tool_blocks, strip_tool_blocks


def test_plain_ui_control_open_panel_is_rescued_even_when_fences_skipped():
    blocks = parse_tool_blocks("ui_control open_panel notes", skip_fenced=True)

    assert len(blocks) == 1
    assert blocks[0].tool_type == "ui_control"
    assert blocks[0].content == "open_panel notes"


def test_plain_ui_control_open_panel_rescues_backticked_line():
    blocks = parse_tool_blocks("``ui_control open_panel cookbook```", skip_fenced=True)

    assert len(blocks) == 1
    assert blocks[0].tool_type == "ui_control"
    assert blocks[0].content == "open_panel cookbook"


def test_plain_ui_control_open_panel_strips_executed_line_only():
    text = "I'll open it now.\nui_control open_panel notes"

    assert strip_tool_blocks(text, skip_fenced=True) == "I'll open it now."


def test_plain_ui_control_rescue_does_not_run_other_commands():
    assert parse_tool_blocks("ui_control switch_model gemma4:31b", skip_fenced=True) == []
    assert parse_tool_blocks("bash ls", skip_fenced=True) == []


_ROOT = Path(__file__).resolve().parents[1]

# The three backend lists that decide which panels `ui_control open_panel <name>`
# may open: the tool schema (tool description + `name` parameter description), the
# tool index entry, and the agent-loop guidance. The frontend handler in
# static/js/chatStream.js keeps its own branch, but a panel name missing from any
# of these is one the agent would be told to open and still could not.
_BACKEND_PANEL_LISTS = (
    "src/tool_schemas.py",
    "src/tool_index.py",
    "src/agent_loop.py",
)


def _lists_machines_beside_cookbook(src: str) -> bool:
    """`machines` enumerated in the same panel list as `cookbook`.

    Deliberately phrasing-agnostic: the three lists word the entry differently
    ("machines (the user's own SSH servers; aliases: servers, ssh, remotes)"), so
    this checks proximity to the reference entry rather than one exact sentence.
    """
    i = src.find("cookbook")
    while i != -1:
        if "machines" in src[i:i + 160]:
            return True
        i = src.find("cookbook", i + 1)
    return False


@pytest.mark.parametrize("rel", _BACKEND_PANEL_LISTS)
def test_ui_control_open_panel_advertises_machines(rel):
    src = (_ROOT / rel).read_text(encoding="utf-8")

    assert _lists_machines_beside_cookbook(src), (
        f"{rel} does not advertise `machines` next to the other panel names — "
        "`ui_control open_panel machines` would be a panel the backend never offers"
    )


# Advertising a panel is only half of it: the dispatcher in
# src/ai_interaction.py resolves the name through its own alias table, so a
# panel advertised in the three lists above but absent there is a capability the
# model is told to use and that always errors. Same failure shape as
# tests/test_ui_control_rag_toggle.py, so it is pinned the same way: call the
# handler, not the docs.


def test_open_panel_machines_is_accepted_by_the_handler():
    r = asyncio.run(do_ui_control("open_panel machines"))

    assert r.get("ui_event") == "open_panel"
    assert r.get("panel") == "machines"
    assert "error" not in r


@pytest.mark.parametrize("alias", ["machine", "servers", "ssh", "remotes"])
def test_open_panel_machine_aliases_resolve_to_machines(alias):
    """The aliases the agent guidance advertises must resolve to the same panel."""
    r = asyncio.run(do_ui_control(f"open_panel {alias}"))

    assert r.get("panel") == "machines", r
    assert "error" not in r


def test_unknown_panel_is_still_rejected():
    """Widening the alias table must not turn it into a catch-all."""
    r = asyncio.run(do_ui_control("open_panel bogus"))

    assert "error" in r
