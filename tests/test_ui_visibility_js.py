import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "static" / "index.html"
pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node binary not on PATH")


def _node_eval(source):
    result = subprocess.run(
        ["node", "--input-type=module", "-e", source],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def _resolve(state):
    """Run resolveVisibility(state) in node; return {selector: visible}."""
    return _node_eval(
        f"""
        const {{ resolveVisibility }} = await import('./static/js/ui_visibility.js');
        console.log(JSON.stringify(resolveVisibility({json.dumps(state)})));
        """
    )


def _map():
    return _node_eval(
        """
        const { UI_VIS_MAP } = await import('./static/js/ui_visibility.js');
        console.log(JSON.stringify(UI_VIS_MAP));
        """
    )


# Selectors (kept in one place so the tests read as plain assertions).
EMAIL = "#email-section, #rail-email"
TOOLS = "#tools-section"
CAL = "#tool-calendar-btn, #rail-calendar"
COMPARE = "#tool-compare-btn, #rail-compare"
LIB = "#tool-library-btn, #rail-archive"
RESEARCH = "#tool-research-btn, #rail-research"
MACHINES = "#tool-machines-btn, #rail-machines"
NEWCHAT = "#rail-new-session"
RAG = "#overflow-rag-btn"

# Full-sidebar tabs that have an icon-rail counterpart must pair it into their
# UI_VIS_MAP selector; otherwise minimizing the sidebar re-shows a tab the user
# turned off in the full view (#tool-library-btn's rail counterpart is #rail-archive).
EXPECTED_RAIL_PAIRS = {
    "email-section": "#rail-email",
    "tool-calendar": "#rail-calendar",
    "tool-compare": "#rail-compare",
    "tool-cookbook": "#rail-cookbook",
    "tool-machines": "#rail-machines",
    "tool-research": "#rail-research",
    "tool-gallery": "#rail-gallery",
    "tool-library": "#rail-archive",
    "tool-memory": "#rail-memory",
    "tool-notes": "#rail-notes",
    "tool-tasks": "#rail-tasks",
    "tool-theme": "#rail-theme",
}


def test_every_customizable_tab_pairs_its_rail_button():
    ui_vis_map = _map()
    missing = {
        key: rail
        for key, rail in EXPECTED_RAIL_PAIRS.items()
        if rail not in ui_vis_map.get(key, "")
    }
    assert not missing, (
        "these tabs are missing their icon-rail counterpart in UI_VIS_MAP "
        f"(minimizing the sidebar would re-show them): {missing}"
    )


def test_defaults_everything_visible_except_default_off():
    m = _resolve({})
    assert m[EMAIL] is True
    assert m[TOOLS] is True
    assert m[CAL] is True
    assert m[NEWCHAT] is True
    assert m[RAG] is False  # rag-toggle-btn is default-off


def test_email_off_hides_email_and_its_rail_only():
    m = _resolve({"email-section": False})
    assert m[EMAIL] is False
    assert m[CAL] is True
    assert m[TOOLS] is True


def test_tool_off_hides_its_rail_launcher():
    m = _resolve({"tool-calendar": False})
    assert m[CAL] is False
    assert m[COMPARE] is True


def test_library_off_hides_archive_rail():
    # tool-library's rail counterpart is #rail-archive (mirrors _railToolMap).
    m = _resolve({"tool-library": False})
    assert m[LIB] is False


def test_tools_off_hides_every_tool_rail_but_not_email():
    m = _resolve({"tools-section": False})
    assert m[TOOLS] is False
    for sel in (CAL, COMPARE, LIB, RESEARCH, MACHINES):
        assert m[sel] is False, sel
    assert m[EMAIL] is True  # email is independent of the Tools section


def test_tools_off_overrides_per_tool_on():
    # A tool individually "on" must still hide when its parent Tools is off.
    m = _resolve({"tools-section": False, "tool-calendar": True})
    assert m[CAL] is False


def test_tools_on_with_tool_off_hides_only_that_tool():
    m = _resolve({"tools-section": True, "tool-research": False})
    assert m[RESEARCH] is False
    assert m[CAL] is True


def test_rail_new_chat_off_hides_new_session():
    m = _resolve({"rail-new-chat": False})
    assert m[NEWCHAT] is False


def test_explicit_false_takes_precedence_over_default_on():
    m = _resolve({"rag-toggle-btn": True})
    assert m[RAG] is True


# ── Appearance-panel wiring parity ─────────────────────────────────────────
# UI_VIS_MAP (JS) and the Settings → Appearance checkboxes (HTML) are two
# hand-maintained lists that must stay in step, and the icon rail is a third.
# Nothing guarded that before: adding a tool to the map without its row or its
# rail button silently produces a tool that cannot be hidden, or a checkbox that
# toggles nothing — which is exactly how the new `tool-machines` entry was
# almost missed. These two tests pin all three lists together.

_DATA_UI_KEY = re.compile(r'data-ui-key="([^"]+)"')

# Pre-existing gaps this guard found when it was introduced, both unrelated to
# the Machines change and both living in static/index.html, which this test does
# not own: the RAG toggle and the rail-only "New Chat" toggle are switchable in
# UI_VIS_MAP but have no row in the Appearance panel. The set must only ever
# SHRINK — test_appearance_row_exceptions_are_not_stale() fails the moment one of
# them gains a row, so a new key can never be parked here quietly.
_APPEARANCE_ROW_EXCEPTIONS = {"rag-toggle-btn", "rail-new-chat"}


def test_every_ui_vis_key_has_an_appearance_row_and_tool_rail_backing():
    ui_vis_map = _map()
    html = INDEX.read_text(encoding="utf-8")
    rows = set(_DATA_UI_KEY.findall(html))

    missing_rows = {
        key for key in ui_vis_map
        if key not in rows and key not in _APPEARANCE_ROW_EXCEPTIONS
    }
    assert not missing_rows, (
        "these UI_VIS_MAP keys have no matching data-ui-key=\"<key>\" checkbox "
        f"in the Appearance panel of static/index.html: {sorted(missing_rows)}"
    )

    # Every tool pairs its sidebar button with a rail launcher, and each selector
    # must match a real element: a selector that matches nothing is a tool that
    # cannot be hidden from the rail (or a rail button that does nothing).
    all_ids = set(re.findall(r'id="([a-z0-9-]+)"', html))
    unbacked: dict = {}
    for key, selector in ui_vis_map.items():
        if not key.startswith("tool-"):
            continue
        wanted = [s.strip()[1:] for s in selector.split(",") if s.strip().startswith("#")]
        if not any(w.startswith("rail-") for w in wanted):
            unbacked[key] = "UI_VIS_MAP selector names no #rail-* launcher"
            continue
        absent = [wid for wid in wanted if wid not in all_ids]
        if absent:
            unbacked[key] = f"no element with id=\"{absent[0]}\" in static/index.html"
    assert not unbacked, (
        f"these tools are missing a sidebar button or an icon-rail button: {unbacked}"
    )


def test_appearance_row_exception_list_is_pinned():
    """The set may only ever SHRINK — pin its contents.

    `test_appearance_row_exceptions_are_not_stale` enforces the shrink direction
    (an excepted key that gains a row fails). This enforces the other one, so the
    comment above the set — "a new key can never be parked here quietly" — is
    true rather than aspirational.
    """
    assert _APPEARANCE_ROW_EXCEPTIONS == {"rag-toggle-btn", "rail-new-chat"}


def test_appearance_row_exceptions_are_not_stale():
    rows = set(_DATA_UI_KEY.findall(INDEX.read_text(encoding="utf-8")))
    stale = sorted(key for key in _APPEARANCE_ROW_EXCEPTIONS if key in rows)
    assert not stale, (
        f"{stale} now have a data-ui-key row — delete them from "
        "_APPEARANCE_ROW_EXCEPTIONS so the parity guard covers them again"
    )