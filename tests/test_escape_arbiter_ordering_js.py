"""Escape-ordering contract for module-owned Escape handlers.

`static/js/ui.js` installs one global Escape arbiter — a **document-capture**
listener whose first act is to close the *hovered* window, then
`stopImmediatePropagation()`. Any handler that has to run on Escape while its own
window is up is therefore invisible unless it binds **earlier than document
capture**, i.e. on `window` in the capture phase.

This is not theoretical, it is a bug that shipped twice:

* `static/js/machines.js` — the add/edit dialog. Escape with the pointer over the
  Machines window closed the whole window and left the form open behind it,
  discarding a half-typed host and password.
* `static/js/cookbook.js` — an expanded Serve card. Escape closed the Cookbook
  window and left the card expanded. Its comment claimed document capture was
  enough to "run before the modal manager's global ESC-to-close handler"; the
  arbiter lives a phase earlier, so it never got a turn.

Both were reproduced in a real browser (Playwright): with the document-level
binding the modal was `hidden` after Escape and the card was still expanded; with
the window-level binding the card collapsed and the modal stayed open.

The sibling handlers are pinned here rather than next to each module so that the
arbiter's own shape and the handlers that must beat it stay readable as one
contract.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "static" / "js" / "ui.js"
COOKBOOK = ROOT / "static" / "js" / "cookbook.js"
MACHINES = ROOT / "static" / "js" / "machines.js"
APP = ROOT / "static" / "app.js"
KEYBOARD_SHORTCUTS = ROOT / "static" / "js" / "keyboard-shortcuts.js"

# (module, bind-once flag belonging to a handler that must win over the arbiter)
_WINDOW_CAPTURE_HANDLERS = (
    (COOKBOOK, "_cookbookServeEscBound"),
    (MACHINES, "_machinesFormEscBound"),
)

# The same race, in handlers that have no bind-once flag of their own.
_WINDOW_CAPTURE_ANCHORS = (
    (APP, "// Esc exits rearrange mode"),
    (KEYBOARD_SHORTCUTS, "// \u2500\u2500 Esc cancels select mode"),
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _registration(src: str, anchor: str) -> str:
    """One capture-phase keydown registration: from `anchor` through `}, true);`.

    Deliberately structural — comments and handler bodies grow, so a fixed
    character window would rot into a test that passes for the wrong reason.
    """
    start = src.index(anchor)
    reg = src.index("addEventListener(", start)
    return src[start:src.index("}, true);", reg) + len("}, true);")]


def test_the_arbiter_is_document_capture_and_closes_the_hovered_window_first():
    """If this changes, the binding choice pinned below may need to change too."""
    arbiter = _registration(_read(UI), "// ── Global Escape arbiter")
    assert "document.addEventListener('keydown'" in arbiter
    # The hovered-window close is the branch that shadows document-level handlers.
    assert arbiter.index("_closeHoveredWindow()") < arbiter.index("dismissTopMenu()")


@pytest.mark.parametrize("path,flag", _WINDOW_CAPTURE_HANDLERS,
                         ids=[p.name for p, _ in _WINDOW_CAPTURE_HANDLERS])
def test_module_escape_handlers_that_must_win_bind_on_window_capture(path, flag):
    binding = _registration(_read(path), flag)
    assert "window.addEventListener('keydown'" in binding, (
        f"{path.name}: {flag} binds at or below document capture, so ui.js's "
        "arbiter closes the hovered window before this handler runs"
    )
    assert "document.addEventListener('keydown'" not in binding, (
        f"{path.name}: a document-level Escape listener loses to the arbiter"
    )
    assert "stopImmediatePropagation" in binding, (
        f"{path.name}: must stop the arbiter's window close, not just handle the key"
    )


@pytest.mark.parametrize("path,anchor", _WINDOW_CAPTURE_ANCHORS,
                         ids=[p.name for p, _ in _WINDOW_CAPTURE_ANCHORS])
def test_the_app_level_escape_handlers_also_bind_on_window_capture(path, anchor):
    """Rearrange mode and bulk-select cancel have the same race as the two
    modal handlers above, and the same symptom: the hovered window closes
    instead of the mode/selection being cancelled."""
    binding = _registration(_read(path), anchor)
    assert "window.addEventListener('keydown'" in binding, (
        f"{path.name}: document capture loses to ui.js's arbiter"
    )
    assert "document.addEventListener('keydown'" not in binding
    assert "stopPropagation" in binding, "must swallow the key it handled"


@pytest.mark.parametrize("path,flag", _WINDOW_CAPTURE_HANDLERS,
                         ids=[p.name for p, _ in _WINDOW_CAPTURE_HANDLERS])
def test_the_handler_ignores_escape_while_its_window_is_closed(path, flag):
    """Otherwise a closed window swallows the Escape meant for whatever is in
    front of it (the arbiter's text-input guard lets the key through)."""
    binding = _registration(_read(path), flag)
    assert "classList.contains('hidden')" in binding, (
        f"{path.name}: no visibility guard — a closed window captures Escape"
    )
