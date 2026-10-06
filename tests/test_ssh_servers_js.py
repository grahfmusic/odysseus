"""Machines area — `static/js/machines.js` shell + `static/js/sshServers.js` body.

The owner-scoped SSH servers feature is no longer a card in the Cookbook modal: it
is a first-class top-level *Machines* area (spec: machines-area-spec.md). The
window shell (`static/js/machines.js`) owns the modal, the master–detail layout,
the form dialog, transfer and activity; `static/js/sshServers.js` stays the
data / row / terminal body layer.

Pure helpers are executed under `node --input-type=module` (same approach as
test_compare_js.py) against the real module source, with a stub ui.js so the
browser-only import resolves. Source assertions pin the new placement, the
terminal-lifecycle rule (minimize/close must NOT end a session) and the security
property that every user-controlled field is escaped and no secret is printed.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "static" / "js" / "sshServers.js"
SHELL = ROOT / "static" / "js" / "machines.js"
COOKBOOK = ROOT / "static" / "js" / "cookbook.js"
INDEX = ROOT / "static" / "index.html"

_HAS_NODE = shutil.which("node") is not None

# Minimal stand-in for ui.js: only `esc` (a faithful HTML escaper) and the
# toast channel are used by this module.
_UI_STUB = """
const _MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export default {
  esc: (v) => String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, (c) => _MAP[c]),
  showToast: () => {},
};
"""


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _func_body(src: str, name: str) -> str:
    """Slice one top-level function body: `function NAME(` … first line-start `}`.

    Deliberately not a parser — just enough to assert *inside* one function
    rather than anywhere in the file (which is how the old teardown pin went
    wrong: it counted call sites across the whole module).
    """
    start = src.find(f"function {name}(")
    assert start != -1, f"function {name} not found"
    end = src.find("\n}", start)
    assert end != -1, f"unterminated function {name}"
    return src[start:end]


def _run_node(body: str) -> dict:
    """Copy the module + ui stub into a temp dir and import it under node."""
    import tempfile

    script = f"""
import {{ sshServerPayload, sshTestMessage, sshErrorText, sshServerRowHtml,
        sshServersListHtml, parseSshSse, sshMachineDetailHostHtml,
        sshMachineInfoHtml, sshAuditRowHtml, sshTransferRequest,
        sshStatusDot, sshInstallMessage, sshCopyIdHint }} from './sshServers.js';
{body}
"""
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "ui.js").write_text(_UI_STUB, encoding="utf-8")
        (d / "sshServers.js").write_text(
            MODULE.read_text(encoding="utf-8"), encoding="utf-8")
        (d / "run.mjs").write_text(script, encoding="utf-8")
        proc = subprocess.run(["node", str(d / "run.mjs")],
                              capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"node failed:\nSTDERR:\n{proc.stderr}\nSTDOUT:\n{proc.stdout}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(not _HAS_NODE, reason="node binary not on PATH")
class TestPayload:
    def test_defaults_and_trim(self):
        out = _run_node("""
console.log(JSON.stringify(sshServerPayload({ label: '  Home  ', host: ' user@box ' })));
""")
        assert out == {"label": "Home", "host": "user@box", "username": "",
                       "auth_type": "key", "port": 22}

    def test_blank_secrets_are_omitted(self):
        """A blank password box must not clear the stored one on PATCH."""
        out = _run_node("""
console.log(JSON.stringify(sshServerPayload({ label: 'a', host: 'h', password: '', sudo_password: '' })));
""")
        assert "password" not in out and "sudo_password" not in out

    def test_present_secrets_are_forwarded(self):
        out = _run_node("""
console.log(JSON.stringify(sshServerPayload({ label: 'a', host: 'h', password: 'p', sudo_password: 's' })));
""")
        assert out["password"] == "p" and out["sudo_password"] == "s"

    def test_explicit_port_wins_and_blank_is_22(self):
        out = _run_node("""
console.log(JSON.stringify([sshServerPayload({ port: '2222' }).port,
                            sshServerPayload({ port: '' }).port,
                            sshServerPayload({}).port]));
""")
        assert out == ["2222", 22, 22]


@pytest.mark.skipif(not _HAS_NODE, reason="node binary not on PATH")
class TestMessages:
    def test_ok_message_reports_latency_and_fingerprint(self):
        out = _run_node("""
console.log(JSON.stringify(sshTestMessage({ ok: true, latency_ms: 12, fingerprint: 'SHA256:abc' })));
""")
        assert out == "OK (12 ms) \u00b7 SHA256:abc"

    def test_error_message_is_surfaced_and_bounded(self):
        out = _run_node("""
console.log(JSON.stringify([sshTestMessage({ ok: false, error: 'connection timed out' }),
                            sshTestMessage({ ok: false, error: 'x'.repeat(500) }).length,
                            sshTestMessage(null), sshTestMessage('nonsense')]));
""")
        assert out[0] == "connection timed out"
        assert out[1] <= 200
        assert out[2] == "No response" and out[3] == "No response"

    def test_the_servers_hint_rides_along_with_the_error(self):
        """The reason and the fix are read together: the server owns the hint."""
        out = _run_node("""
console.log(JSON.stringify(sshTestMessage({ ok: false, error: 'Permission denied (publickey)',
                                            hint: 'Install key adds it with that password' })));
""")
        assert out == ("Permission denied (publickey) — "
                       "Install key adds it with that password")

    def test_error_text_prefers_fastapi_detail(self):
        out = _run_node("""
console.log(JSON.stringify([sshErrorText({ detail: 'label is required' }, 400),
                            sshErrorText({ error: 'nope' }, 500),
                            sshErrorText('<html>', 502),
                            sshErrorText('   ', 502)]));
""")
        assert out == ["label is required", "nope", "<html>", "HTTP 502"]


@pytest.mark.skipif(not _HAS_NODE, reason="node binary not on PATH")
class TestKeyInstallUi:
    """The Install button's copy, and the ssh-copy-id line it replaces."""

    def test_install_message_says_what_happened(self):
        out = _run_node("""
console.log(JSON.stringify([
  sshInstallMessage({ ok: true, installed: true, pinned: true }),
  sshInstallMessage({ ok: true, installed: false, pinned: false }),
  sshInstallMessage({ ok: false, error: 'Authentication failed', hint: 'check the password' }),
  sshInstallMessage(null),
]));
""")
        assert "key added" in out[0] and "host key pinned" in out[0]
        assert "already" in out[1].lower()
        assert out[2] == "Authentication failed (check the password)"
        assert out[3] == "No response"

    def test_copy_id_hint_prefers_the_server_command(self):
        out = _run_node("""
console.log(JSON.stringify([
  sshCopyIdHint({ username: 'dean', host: 'pluto3', port: 22 },
                 { ssh_copy_hint: 'ssh-copy-id -i /data/ssh/dean_ed25519.pub dean@pluto3' }),
  sshCopyIdHint({ username: 'dean', host: 'pluto3', port: 2222 }, {}),
  sshCopyIdHint({ host: 'box', port: 22 }, {}),
]));
""")
        assert out[0] == "ssh-copy-id -i /data/ssh/dean_ed25519.pub dean@pluto3"
        assert out[1] == "ssh-copy-id -i data/ssh/<user>_ed25519 -p 2222 dean@pluto3"
        assert out[2] == "ssh-copy-id -i data/ssh/<user>_ed25519 box"
        assert not any("user@host" in s for s in out)

    def test_the_key_pane_offers_install_and_wires_it(self):
        src = _read(MODULE)
        key = _func_body(src, "_onKey")
        assert "ssh-k-install" in key
        assert "_onInstallKey(" in key
        install = _func_body(src, "_onInstallKey")
        # Busy-guard: the call opens an SSH connection and writes a remote file,
        # so a double-click must not race itself into two appends.
        assert "btn.disabled = true" in install and "finally" in install
        assert "installSshKey(" in install
        assert "refreshSshServers()" in install

    def test_the_api_call_posts_to_the_install_route(self):
        src = _read(MODULE)
        body = _func_body(src, "installSshKey")
        assert "/install-key" in body and "POST" in body

    def test_the_machines_form_offers_install_and_requires_a_saved_machine(self):
        shell = _read(SHELL)
        assert 'id="machines-f-installkey"' in shell
        assert "_el('machines-f-installkey')?.addEventListener('click', _installKey)" in shell
        body = _func_body(shell, "_installKey")
        assert "Save the machine first" in body
        assert "installSshKey(_formState.id)" in body


class TestRowHtml:
    def test_hostile_fields_are_escaped(self):
        """A stored label/host must never inject markup into the panel."""
        out = _run_node("""
const hostile = '<img src=x onerror=alert(1)>';
console.log(JSON.stringify(sshServerRowHtml({
  id: 'abc123', label: hostile, host: hostile, port: 22, username: hostile,
})));
""")
        # No live tag survives; the hostile text is only present inert.
        assert "<img" not in out
        assert "&lt;img src=x onerror=alert(1)&gt;" in out

    def test_row_exposes_every_action(self):
        out = _run_node("""
console.log(JSON.stringify(sshServerRowHtml({ id: 's1', label: 'H', host: 'h', port: 22 })));
""")
        for action in ("test", "connect", "run", "key", "edit", "delete"):
            assert f'data-ssh-action="{action}"' in out
        assert 'data-id="s1"' in out
        assert "not pinned" in out

    def test_pinned_server_is_labelled(self):
        out = _run_node("""
console.log(JSON.stringify(sshServerRowHtml({ id: 's1', host_key_fingerprint: 'SHA256:zzz' })));
""")
        assert "host key: pinned" in out

    def test_empty_list_shows_empty_state(self):
        out = _run_node("""
console.log(JSON.stringify([sshServersListHtml([]),
                            sshServersListHtml(null).includes('No machines yet'),
                            sshServersListHtml([{ id: 'a' }, { id: 'b' }]).split('data-ssh-row=').length - 1]));
""")
        assert out[0].count("data-ssh-row=") == 0
        assert out[1] is True
        assert out[2] == 2


@pytest.mark.skipif(not _HAS_NODE, reason="node binary not on PATH")
class TestStatusDot:
    """The per-row status dot promised by ssh-rsh-spec.md §8."""

    def test_the_three_states_are_distinguishable(self):
        out = _run_node("""
console.log(JSON.stringify({
  untested: sshStatusDot({}),
  nulled: sshStatusDot({ last_test_result: null }),
  blank: sshStatusDot({ last_test_result: '   ' }),
  ok: sshStatusDot({ last_test_result: 'ok' }),
  failed: sshStatusDot({ last_test_result: 'connection timed out' }),
}));
""")
        assert 'data-ssh-status="untested"' in out["untested"]
        # NULL / blank / whitespace all mean "not tested yet", never "failed".
        assert 'data-ssh-status="untested"' in out["nulled"]
        assert 'data-ssh-status="untested"' in out["blank"]
        assert 'data-ssh-status="ok"' in out["ok"]
        assert 'data-ssh-status="failed"' in out["failed"]
        assert "Never tested" in out["untested"]
        assert "Last test succeeded" in out["ok"]
        # A failed test carries its reason, which is what makes the dot useful.
        assert "connection timed out" in out["failed"]

    def test_the_reason_is_escaped_and_bounded_to_a_tooltip(self):
        """`last_test_result` is server-side display text: it must not inject markup."""
        out = _run_node("""
console.log(JSON.stringify(sshStatusDot({
  last_test_result: '"><img src=x onerror=alert(1)>',
})));
""")
        assert "<img" not in out
        assert "&lt;img src=x onerror=alert(1)&gt;" in out

    def test_a_never_tested_dot_is_not_a_success(self):
        """Guards the old bug this replaced: a bare tick that only ever said 'ok'."""
        out = _run_node("""
console.log(JSON.stringify([sshServerRowHtml({ id: 's1', label: 'H', host: 'h' }),
                            sshServerRowHtml({ id: 's2', last_test_result: 'ok' })]));
""")
        assert out[0].count('class="ssh-status-dot"') == 1
        assert 'data-ssh-status="untested"' in out[0]
        assert out[1].count('class="ssh-status-dot"') == 1
        assert 'data-ssh-status="ok"' in out[1]
        assert "\u2713" not in out[0] and "\u2713" not in out[1]


@pytest.mark.skipif(not _HAS_NODE, reason="node binary not on PATH")
class TestMachinesHelpers:
    """Pure helpers added by the Machines restructure (spec §6.3 / §7.2 / §8)."""

    def test_detail_host_is_a_per_machine_slot_with_both_hosts(self):
        """One stable DOM node per machine — that is what keeps a live terminal."""
        out = _run_node("""
console.log(JSON.stringify(sshMachineDetailHostHtml('abc')));
""")
        assert 'data-machine-slot="abc"' in out
        # The action host the body module writes into, and the shell's own panes.
        assert 'data-ssh-detail="abc"' in out
        assert 'data-machine-info="abc"' in out
        assert 'data-machine-extra="abc"' in out
        assert out.count('data-machine-slot="abc"') == 1

    def test_detail_host_escapes_a_hostile_id(self):
        out = _run_node("""
console.log(JSON.stringify(sshMachineDetailHostHtml('a" onmouseover="x')));
""")
        assert 'onmouseover="x"' not in out
        assert "&quot;" in out

    def test_info_pane_reports_target_auth_and_pin_state(self):
        out = _run_node("""
console.log(JSON.stringify(sshMachineInfoHtml({
  id: 's1', label: 'pi', host: 'pi.lan', port: 2222, username: 'me',
  auth_type: 'both', host_key_fingerprint: 'SHA256:zzz', last_test_result: 'ok',
})));
""")
        assert "me@pi.lan:2222" in out          # target
        assert "key + password" in out          # auth label, never a secret
        assert "SHA256:zzz" in out              # pinned fingerprint
        assert "never tested" not in out        # last test recorded

    def test_info_pane_says_a_server_is_unpinned_and_untested(self):
        out = _run_node("""
console.log(JSON.stringify(sshMachineInfoHtml({ id: 's1', host: 'h' })));
""")
        assert "not pinned" in out and "never tested" in out

    def test_info_pane_escapes_hostile_fields(self):
        out = _run_node("""
console.log(JSON.stringify(sshMachineInfoHtml({ host: '<img src=x>' })));
""")
        assert "<img" not in out
        assert "&lt;img src=x&gt;" in out

    def test_audit_row_shows_a_hash_prefix_and_never_a_command(self):
        out = _run_node("""
console.log(JSON.stringify(sshAuditRowHtml({
  id: 1, server_id: 's1', server_label: 'pi', event: 'exec',
  created_at: '2026-10-07T12:34:56.789Z', exit_code: 0,
  command_hash: 'a'.repeat(64),
})));
""")
        assert "2026-10-07 12:34:56" in out
        assert "exec" in out and "pi" in out
        assert "aaaaaaaaaaaa" in out            # 12-char hash prefix
        assert "a" * 13 not in out              # …not the whole digest
        assert " · exit 0" in out

    def test_audit_row_survives_an_empty_or_null_payload(self):
        """An empty/partial/null row must render, not throw.

        The log outlives its server (`server_id` has no FK), so a row can arrive
        with no label at all. `null` is pinned explicitly: a JS default parameter
        only covers `undefined`, so `sshAuditRowHtml(null)` threw until the body
        module started guarding with `r = r || {}`.
        """
        out = _run_node("""
console.log(JSON.stringify([sshAuditRowHtml({}), sshAuditRowHtml(undefined),
                            sshAuditRowHtml(null), sshAuditRowHtml({ event: 'test' })]));
""")
        assert len(out) == 4
        assert "—" in out[0] and "—" in out[1] and "—" in out[2]

    def test_audit_row_escapes_a_hostile_label(self):
        out = _run_node("""
console.log(JSON.stringify(sshAuditRowHtml({ server_label: '<img src=x>', event: 'test' })));
""")
        assert "<img" not in out
        assert "&lt;img src=x&gt;" in out

    def test_transfer_request_mirrors_the_server_model(self):
        out = _run_node("""
console.log(JSON.stringify([
  sshTransferRequest({ direction: 'upload', local_path: ' a/b ', remote_path: ' /tmp/c ' }),
  sshTransferRequest({ direction: 'download' }),
  sshTransferRequest({}),
  sshTransferRequest({ direction: 'nonsense' }),
]));
""")
        assert out[0] == {"direction": "upload", "local_path": "a/b", "remote_path": "/tmp/c"}
        assert out[1]["direction"] == "download"
        assert out[2]["direction"] == "upload"          # defaults to upload
        assert out[3]["direction"] == "upload"          # anything else is upload
        assert set(out[2]) == {"direction", "local_path", "remote_path"}


@pytest.mark.skipif(not _HAS_NODE, reason="node binary not on PATH")
class TestTerminalFrames:
    """The SSE relay parser must mirror the server's frame shape exactly.

    Frames are built with ``JSON.stringify`` in the node half so the expected
    bytes are the server's own shape, not a hand-escaped approximation.
    """

    _HELPERS = """
const NL = String.fromCharCode(10);
const frame = (o) => 'data: ' + JSON.stringify(o) + NL + NL;
"""

    def test_parses_stream_frames_and_keeps_the_partial_tail(self):
        out = _run_node(self._HELPERS + """
const text = frame({ stream: 'stdout', data: 'hi' + NL }) +
             'data: ' + JSON.stringify({ stream: 'stdout', data: 'par' });
const parsed = parseSshSse(text);
console.log(JSON.stringify(parsed));
""")
        assert out["events"] == [{"stream": "stdout", "data": "hi\n"}]
        assert out["rest"] == 'data: {"stream":"stdout","data":"par"}'

    def test_parses_the_exit_frame(self):
        out = _run_node(self._HELPERS + """
const ev = parseSshSse(frame({ exit_code: 7 }));
console.log(JSON.stringify([ev.events, ev.rest]));
""")
        assert out == [[{"exit_code": 7}], ""]

    def test_multiple_frames_in_one_chunk(self):
        out = _run_node(self._HELPERS + """
const ev = parseSshSse(frame({ data: 'a' }) + frame({ data: 'b' }) + frame({ exit_code: 0 }));
console.log(JSON.stringify(ev.events));
""")
        assert out == [{"data": "a"}, {"data": "b"}, {"exit_code": 0}]

    def test_junk_frames_never_throw(self):
        out = _run_node(self._HELPERS + """
const ev = parseSshSse('data: not-json' + NL + NL + frame({ data: 'ok' }) +
                       ': not a data line' + NL + NL);
console.log(JSON.stringify(ev.events));
""")
        assert out == [{"data": "ok"}]

    def test_stream_chunks_can_split_mid_frame(self):
        """A TCP boundary inside a frame must not lose or corrupt it."""
        out = _run_node(self._HELPERS + """
const whole = frame({ stream: 'stdout', data: 'split' });
const first = parseSshSse(whole.slice(0, 12));
const second = parseSshSse(first.rest + whole.slice(12));
console.log(JSON.stringify([first.events, second.events]));
""")
        assert out == [[], [{"stream": "stdout", "data": "split"}]]

    def test_empty_and_null_input(self):
        out = _run_node("""
console.log(JSON.stringify([parseSshSse(''), parseSshSse(null), parseSshSse(undefined)]));
""")
        assert out == [{"events": [], "rest": ""}] * 3


class TestModuleContract:
    """The body must use its own endpoints and never touch Cookbook state."""

    def test_talks_only_to_ssh_api(self):
        src = _read(MODULE)
        assert "const API = '/api/ssh/servers';" in src
        assert "/api/cookbook" not in src

    def test_does_not_share_cookbook_server_state(self):
        """Disjoint by design: never merge into _envState.servers."""
        src = _read(MODULE)
        assert "_envState" not in src

    def test_toast_sink_is_text_only(self):
        """Remote-derived text reaches showToast; it must not be innerHTML."""
        ui = _read(ROOT / "static" / "js" / "ui.js")
        start = ui.index("export function showToast(")
        body = ui[start:ui.index("\n}", start)]
        assert "textSpan.textContent = msg;" in body
        assert "textSpan.innerHTML" not in body

    def test_secrets_are_never_rendered_back(self):
        src = _read(MODULE)
        # The panel may send a password, but no code path prints a stored one.
        assert "has_password" not in src
        assert "s.password" not in src


class TestTerminalContract:
    """Source-level pins for the terminal panel's request shape."""

    def test_terminal_verbs_match_the_server_routes(self):
        src = _read(MODULE)
        assert "`/${encodeURIComponent(id)}/terminal`" in src           # POST open
        assert "path + '/stream'" in src                               # GET stream
        assert "path + '/input'" in src                                # POST input
        assert "path + '/resize'" in src                               # POST resize
        assert "{ method: 'DELETE' }" in src                           # DELETE close

    def test_input_is_line_oriented_and_escaped_into_the_dom(self):
        src = _read(MODULE)
        # Output lands in a <pre> via textContent — never innerHTML.
        assert "out.textContent += text;" in src
        assert "out.innerHTML" not in src
        assert "e.key !== 'Enter'" in src

    def test_hiding_the_panel_keeps_the_live_session_running(self):
        """INVERTED pin (was test_live_session_is_closed_when_the_panel_goes_away).

        The old rule — "a live PTY must not keep running behind a new panel" —
        had `_showDetail` and `_hideDetail` both call the teardown helper, so
        switching machines or collapsing the panel silently killed the session.
        The requirement is now the opposite (spec §7.3, AC5): minimizing or
        closing the Machines window must NOT end a session, because the point of
        the dock chip is a terminal that survives behind it. Only an explicit
        Disconnect — or the server's own 3-session cap / idle reaper — may end
        one. Keeping the old assertion would actively reward the broken
        behaviour, which is why it is inverted rather than deleted.
        """
        src = _read(MODULE)
        show = _func_body(src, "_showDetail")
        hide = _func_body(src, "_hideDetail")

        # Neither the show nor the hide path may tear a session down…
        for body in (show, hide):
            assert "_closeTerminal" not in body
            assert "abort" not in body
            assert "closeSshTerminalById" not in body
        # …and hiding must not destroy the terminal's DOM either: a minimized
        # window or another selection has to be able to come back to its output.
        assert "innerHTML" not in hide
        assert "display = 'none'" in hide

    def test_the_only_in_ui_teardown_is_an_explicit_disconnect(self):
        src = _read(MODULE)
        assert ".ssh-t-disconnect" in src
        connect = _func_body(src, "_onConnect")
        disconnect = connect[connect.index(".ssh-t-disconnect"):]
        assert "closeSshTerminalById(id, sid)" in disconnect
        # Exactly one controller abort in the whole module, and it lives on the
        # explicit close path — nothing else can silently drop the stream.
        assert src.count(".controller.abort();") == 1
        assert ".controller.abort();" in _func_body(src, "closeSshTerminalById")

    def test_a_server_derived_string_is_escaped(self):
        src = _read(MODULE)
        assert "const target = esc(info.target || 'remote');" in src


class TestShellContract:
    """The Machines shell owns the window; the body is injected into it."""

    def test_shell_imports_and_initialises_the_body(self):
        src = _read(SHELL)
        assert "import { initSshServers } from './sshServers.js';" in src
        assert "initSshServers(body);" in src

    def test_shell_registers_the_window_with_its_own_triggers(self):
        src = _read(SHELL)
        assert "railBtnId: 'rail-machines'" in src
        assert "sidebarBtnId: 'tool-machines-btn'" in src
        assert "Modals.register(MODAL_ID, {" in src
        # Never toggle-close from the trigger: a minimized window is restored.
        assert "Modals.isMinimized(MODAL_ID)" in src

    def test_shell_never_tears_its_body_down_on_hide_or_close(self):
        src = _read(SHELL)
        mount = _func_body(src, "_mount")
        assert "if (_mounted) return;" in mount          # idempotent mount
        assert "body.innerHTML = _shellHtml();" in mount
        close_body = _func_body(src, "close")
        for forbidden in ("innerHTML", "remove()", "initSshServers", "_render("):
            assert forbidden not in close_body
        do_close = _func_body(src, "_doClose")
        assert "innerHTML" not in do_close               # closing only hides

    def test_shell_keeps_each_machines_detail_node_across_a_refresh(self):
        """Rebuilding the slots would destroy a live terminal (AC5)."""
        src = _read(SHELL)
        slots = _func_body(src, "_renderSlots")
        assert "host.innerHTML" not in slots
        assert "insertAdjacentHTML('beforeend'" in slots
        # Only slots for machines that no longer exist get removed.
        assert "slot.remove()" in slots

    def test_shell_supports_a_deep_link_to_one_machine(self):
        src = _read(SHELL)
        assert "export async function open(opts = {})" in src
        assert "opts.serverId" in src
        assert "_select(opts.serverId)" in src

    def test_shell_owns_the_form_dialog_and_the_area_panels(self):
        src = _read(SHELL)
        for fn in ("_openForm", "_saveForm", "_openTransfer", "_openActivity"):
            assert f"function {fn}(" in src, fn
        # Add/edit is a dialog now, not the old cramped inline row.
        for el_id in ("machines-f-label", "machines-f-host", "machines-f-user",
                      "machines-f-auth", "machines-f-save", "machines-f-cancel"):
            assert f'id="{el_id}"' in src, el_id
        # The guided empty state and the live-session surface are part of v1.
        assert "machines-empty-add" in src
        assert "machines-disconnect-all" in src

    def test_shell_routes_edit_into_its_own_dialog(self):
        src = _read(SHELL)
        assert "setSshActionHandlers({" in src
        assert "edit: (id) => _openForm(id)," in src
        # The body owns test/connect/disconnect/delete; it reports those moves
        # back so the panes the shell derives from them are not stale.
        assert "changed: (reason)" in src


class TestInteractionWiring:
    """Every visible affordance must reach a handler (found the hard way).

    Each of these rendered perfectly and did nothing in the browser: the header
    ✖ was never bound (the "toggle window" hotkey closes the area by clicking it),
    the guided empty state's CTA was bound to a node `_render()` replaces, and the
    detail pane sat outside the delegated listener's scope. None of them fails a
    render test, which is exactly why they are pinned here.
    """

    def test_header_close_button_is_bound(self):
        src = _read(SHELL)
        assert 'id="close-machines-modal"' in _read(INDEX)
        wire = _func_body(src, "_wire")
        assert "close-machines-modal" in wire, "the header ✖ has no listener"
        # It must run the module's own close (Modals-aware), not just hide.
        assert "close();" in wire

    def test_empty_state_cta_rides_the_delegated_handler(self):
        """`_wire()` runs once, then `_render()` re-creates the empty state."""
        src = _read(SHELL)
        assert 'id="machines-empty-add"' in _func_body(src, "_emptyStateHtml")
        assert 'data-machine-action="add"' in _func_body(src, "_emptyStateHtml")
        assert "action === 'add'" in _func_body(src, "_wire")
        # A per-element binding would be thrown away with the previous node.
        assert "machines-empty-add')?.addEventListener" not in src

    def test_detail_pane_actions_are_inside_the_delegation_scope(self):
        """The detail pane is outside `#ssh-servers-list`: the listener has to
        cover the whole area, and each detail button has to name its machine."""
        src = _read(MODULE)
        init = _func_body(src, "initSshServers")
        assert "scope.addEventListener('click'" in init
        assert "querySelector('#ssh-servers-list')" not in init
        for fn in ("_editFormHtml", "_runFormHtml", "_onKey"):
            assert "data-id=" in _func_body(src, fn), fn

    def test_detail_host_resolves_to_the_shell_slot(self):
        """The row still carries a hidden detail host and the list comes first in
        document order, so an unscoped lookup writes terminals into the 300px
        list pane instead of the detail pane on the right."""
        src = _read(MODULE)
        assert ".machine-detail-slot [data-ssh-detail=" in _func_body(src, "_detail")

    def test_body_reports_state_changes_to_the_shell(self):
        src = _read(MODULE)
        assert "function _notifyChanged(" in src
        for fn in ("_onTest", "_onConnect", "_onDelete"):
            assert "_notifyChanged(" in _func_body(src, fn), fn
        # Order matters on delete: the shell re-renders from the cached list, so
        # notifying before the re-fetch redraws the deleted machine's slot.
        delete = _func_body(src, "_onDelete")
        assert delete.index("await refreshSshServers();") < delete.index("_notifyChanged('deleted')")
        mount = _func_body(_read(SHELL), "_mount")
        assert "changed: (reason)" in mount
        assert "_render()" in mount

    def test_disconnect_all_follows_the_last_session(self):
        live = _func_body(_read(SHELL), "_renderLive")
        assert live.index("_toggleDisconnectAll") < live.index("if (!sessions.length)"), (
            "the early return skips the toggle, leaving a button with nothing to do"
        )

    def test_form_escape_is_bound_on_window_capture(self):
        """ui.js's global Escape arbiter is a *document*-capture listener that
        closes the hovered window first, and the pointer is over this window
        whenever the form is being typed into — so a document-level handler (the
        cookbook Serve-card pattern) loses the race and the whole window closes,
        discarding a typed password with it."""
        src = _read(SHELL)
        idx = src.index("window._machinesFormEscBound")
        bind = src[idx:idx + 200]
        assert "window.addEventListener('keydown'" in bind, bind
        esc = src[src.index("e.key !== 'Escape'"):]
        assert "modal.classList.contains('hidden')" in esc[:400], (
            "a closed window would swallow the app shell's Escape"
        )
        assert "_closeForm();" in esc[:600]


class TestBodyApiSurface:
    """Everything the shell calls must be exported by the body module."""

    def test_shell_facing_exports_exist(self):
        src = _read(MODULE)
        for name in ("setSshActionHandlers", "createSshServer", "updateSshServer",
                     "deleteSshServer", "sshServerPubkey", "transferSshFile",
                     "listSshAudit", "listSshTerminals", "closeSshTerminalById",
                     "disconnectAllTerminals", "getLiveTerminals", "getSshServers",
                     "initSshServers"):
            assert f"function {name}(" in src, name
        # The shell's `open()` must be able to re-render from the same fetch.
        assert "export function getSshServers()" in src

    def test_shell_only_calls_exports_the_body_declares(self):
        """A shell call that is not exported would throw at import time."""
        shell = _read(SHELL)
        body = _read(MODULE)
        blocks = re.findall(r"import\s*\{([^}]*)\}\s*from\s*'\./sshServers\.js';", shell)
        assert blocks, "the shell does not import the body module"
        imported = [n.strip() for block in blocks for n in block.split(",") if n.strip()]
        assert "initSshServers" in imported
        for name in imported:
            assert (f"export function {name}(" in body
                    or f"export async function {name}(" in body), name

    def test_audit_and_live_session_reads_are_read_only(self):
        src = _read(MODULE)
        assert "/api/ssh/audit" in src and "/api/ssh/terminals" in src
        audit = _func_body(src, "listSshAudit")
        assert "_fetchUrl('/api/ssh/audit'" in audit          # no method override
        for verb in ("POST", "PATCH", "DELETE", "method:"):
            assert verb not in audit
        live = _func_body(src, "listSshTerminals")
        assert "_fetchUrl('/api/ssh/terminals')" in live
        for verb in ("POST", "PATCH", "DELETE", "method:"):
            assert verb not in live

    def test_audit_scope_is_only_sent_when_asked_for(self):
        """`scope=all` is admin-gated server-side; the client must not default it."""
        src = _read(MODULE)
        audit = _func_body(src, "listSshAudit")
        assert "if (params.scope) q.set('scope', String(params.scope));" in audit


class TestNoSecretsRendered:
    """Display paths must never read a stored secret back into the DOM."""

    def test_display_helpers_never_mention_a_password(self):
        src = _read(MODULE)
        assert "has_password" not in src
        assert "s.password" not in src
        for fn in ("sshServerRowHtml", "sshServersListHtml", "sshMachineInfoHtml",
                   "sshMachineDetailHostHtml", "sshAuditRowHtml"):
            assert "password" not in _func_body(src, fn).lower(), fn

    def test_the_shell_password_input_is_write_only(self):
        src = _read(SHELL)
        assert "has_password" not in src
        reads = [ln for ln in src.splitlines() if "machines-f-pass" in ln and ".value" in ln]
        assert len(reads) == 1, reads
        # The one read is the payload builder — it is sent, never rendered.
        assert "machines-f-pass" in _func_body(src, "_saveForm")
        for fn in ("_showCommands", "_renderLive", "_loadActivity", "_openForm"):
            assert "machines-f-pass')?.value" not in _func_body(src, fn), fn

    def test_activity_copy_promises_hashes_not_commands(self):
        src = _read(SHELL)
        assert "never commands or secrets" in src


class TestMachinesWiring:
    """Placement: a top-level Machines area, and a Cookbook that lost the card."""

    def test_index_has_the_machines_modal_and_its_triggers(self):
        src = _read(INDEX)
        for anchor in ('id="machines-modal"', 'machines-body',
                       'id="tool-machines-btn"', 'id="rail-machines"',
                       'data-ui-key="tool-machines"'):
            assert anchor in src, anchor

    def test_cookbook_no_longer_imports_or_initialises_the_panel(self):
        src = _read(COOKBOOK)
        assert "sshServers" not in src
        assert "initSshServers" not in src
        for leftover in ('ssh-servers-list', 'ssh-servers-status', 'ssh-server-add',
                         'ssh-add-host', 'ssh-add-user', 'ssh-add-port', 'ssh-add-auth',
                         'ssh-servers-card'):
            assert leftover not in src, leftover

    def test_cookbook_keeps_the_shared_servers_block_only(self):
        src = _read(COOKBOOK)
        assert "// \u2500\u2500 Servers block" in src
        assert "// \u2500\u2500 My servers" not in src
        assert "My servers" not in src

    def test_settings_has_no_ssh_or_machines_panel(self):
        """AC2 — the request was that this feature is *not* configuration.

        The feature is owner-scoped machines, not a preference, so nothing about
        it may appear in the main Settings dialog: no panel, no row, no link. A
        positive assertion would not catch a panel added later, so this pins the
        absence in the surfaces that render Settings.
        """
        forbidden = ("sshServers", "initSshServers", "ssh-servers-list",
                     "data-settings-panel=\"machines\"", "data-settings-panel=\"ssh\"",
                     "machines-modal")
        for rel in ("static/js/settings.js", "static/js/settings/registry.js",
                    "static/js/settings/lifecycle.js"):
            src = _read(ROOT / rel)
            for needle in forbidden:
                assert needle not in src, f"{rel} must not carry SSH/Machines config: {needle}"
        # Panel ids are the other way Settings can grow an entry, so pin those too.
        registry = _read(ROOT / "static/js/settings/registry.js")
        panel_ids = set(re.findall(r"id:\s*'([^']+)'", registry))
        assert not (panel_ids & {"machines", "machine", "ssh", "servers"}), panel_ids
        # The Settings modal markup must not carry an SSH management surface.
        # (The Appearance panel's `data-ui-key="tool-machines"` checkbox is
        # generic per-tool chrome that every tool has — see the wiring test
        # above — so it is deliberately not included in the forbidden list.)
        settings_markup = _read(INDEX).split('id="settings-modal"', 1)[-1]
        assert "ssh-servers-list" not in settings_markup
        assert "data-settings-panel=\"machines\"" not in settings_markup


class TestAppShellWiring:
    """Every entry point that makes the area reachable, pinned where it lives.

    Spec §13 asks for these specifically. None of them fails loudly when it is
    missing: a dead rail button still renders, a hotkey whose key is absent from
    the category list simply never shows a row, and an entity hash claimed by the
    session logic navigates away instead. All of them are one careless edit from
    regressing, so each is pinned next to the file that owns it.
    """

    def test_shell_default_export_matches_the_app_shell_import(self):
        """The exact shape that took the whole app shell down once.

        `static/app.js` imports modal tools with a DEFAULT import (Cookbook's
        convention), so a module with only named exports is a link-time error for
        the entire app — not a lazy 404 at the point of use. Pin the pair.
        """
        shell = _read(SHELL)
        assert "const machinesModule = { open, close, isVisible };" in shell
        assert "export default machinesModule;" in shell
        assert "import machinesModule from './js/machines.js';" in _read(
            ROOT / "static" / "app.js"
        )

    def test_modal_manager_knows_the_window(self):
        src = _read(ROOT / "static" / "js" / "modalManager.js")
        assert re.search(r"'machines-modal':\s*\{ label: 'Machines'", src), (
            "no dock-chip label — minimize would put an unlabelled chip in the dock"
        )
        assert re.search(
            r"'machines-modal':\s*\{ rail: 'rail-machines',\s*sidebar: 'tool-machines-btn'",
            src,
        ), "auto-wire missing — the badge/restore path silently no-ops"
        assert "'machines-modal'," in src, (
            "not in the swipe-down set: a swipe would close the window instead of "
            "docking it, losing the live-session affordance"
        )

    def test_app_shell_wires_both_triggers_and_escape(self):
        src = _read(ROOT / "static" / "app.js")
        assert re.search(r"'rail-machines':\s*'tool-machines-btn'", src), (
            "missing _railToolMap entry — the rail button renders and does nothing"
        )
        assert "'/machines':" in src, "missing _routeOpen entry"
        assert "machinesModule.open()" in src, "missing sidebar click block"
        assert "'machines-modal': null," in src, (
            "absent from the Escape map: Escape would not dismiss the window the "
            "way it dismisses every sibling tool window"
        )

    def test_hotkey_touchpoints_are_complete(self):
        """Six touchpoints, all required — the category list drives the row."""
        kb = _read(ROOT / "static" / "js" / "keyboard-shortcuts.js")
        assert "open_machines: ''" in kb
        assert "'machines-modal':" in kb
        assert "open_machines: 'tool-machines-btn'" in kb
        st = _read(ROOT / "static" / "js" / "settings.js")
        assert st.count("open_machines") >= 4, (
            "expected defaults + icon + label + 'Open Tools' category entry"
        )
        assert "'Open Machines'" in st

    def test_slash_command_and_panel_link_reach_the_area(self):
        slash = _read(ROOT / "static" / "js" / "slashCommands.js")
        assert "machines: ['tool-machines-btn', 'rail-machines']" in slash, (
            "/open machines has no target — the command is advertised but inert"
        )
        assert "usage: '/machines'" in slash, "missing /machines registration"
        stream = _read(ROOT / "static" / "js" / "chatStream.js")
        assert "panel === 'machines'" in stream, "no panel-link branch"
        assert "import('./machines.js')" in stream

    def test_every_entity_hash_inventory_knows_machine(self):
        """The `#machine-<id>` prefix is hand-copied into five files.

        Missing it in one of them does not fail loudly: `chat.js` treats the hash
        as a *session* candidate (selects a session that does not exist and
        suppresses composer restore), `sessions.js` restores the last chat
        instead of landing fresh and keeps reacting on hashchange, and
        `markdown.js` stops repairing mangled anchors for machine links.
        """
        for rel in ("static/js/init.js", "static/js/chatRenderer.js",
                    "static/js/chat.js", "static/js/sessions.js",
                    "static/js/markdown.js"):
            src = _read(ROOT / rel)
            assert "research|machine)" in src, (
                f"{rel} does not list `machine` among the entity hash kinds"
            )
        assert _read(ROOT / "static" / "js" / "sessions.js").count(
            "research|machine)"
        ) == 2, "sessions.js has two inventories (boot restore + hashchange)"
