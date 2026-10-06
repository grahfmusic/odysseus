"""`My servers` panel (static/js/sshServers.js) — pure helpers + Cookbook wiring.

Pure helpers are executed under `node --input-type=module` (same approach as
test_compare_js.py) against the real module source, with a stub ui.js so the
browser-only import resolves. Source assertions pin the Cookbook wiring and the
security property that every user-controlled field is escaped.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "static" / "js" / "sshServers.js"
COOKBOOK = ROOT / "static" / "js" / "cookbook.js"

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


def _run_node(body: str) -> dict:
    """Copy the module + ui stub into a temp dir and import it under node."""
    import tempfile

    script = f"""
import {{ sshServerPayload, sshTestMessage, sshErrorText, sshServerRowHtml,
        sshServersListHtml }} from './sshServers.js';
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

    def test_error_text_prefers_fastapi_detail(self):
        out = _run_node("""
console.log(JSON.stringify([sshErrorText({ detail: 'label is required' }, 400),
                            sshErrorText({ error: 'nope' }, 500),
                            sshErrorText('<html>', 502),
                            sshErrorText('   ', 502)]));
""")
        assert out == ["label is required", "nope", "<html>", "HTTP 502"]


@pytest.mark.skipif(not _HAS_NODE, reason="node binary not on PATH")
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

    def test_row_exposes_every_phase1_action(self):
        out = _run_node("""
console.log(JSON.stringify(sshServerRowHtml({ id: 's1', label: 'H', host: 'h', port: 22 })));
""")
        for action in ("test", "run", "key", "edit", "delete"):
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
                            sshServersListHtml(null).includes('No servers yet'),
                            sshServersListHtml([{ id: 'a' }, { id: 'b' }]).split('data-ssh-row=').length - 1]));
""")
        assert out[0].count("data-ssh-row=") == 0
        assert out[1] is True
        assert out[2] == 2


class TestModuleContract:
    """The panel must use its own endpoints and never touch Cookbook state."""

    def test_talks_only_to_ssh_api(self):
        src = MODULE.read_text(encoding="utf-8")
        assert "const API = '/api/ssh/servers';" in src
        assert "/api/cookbook" not in src

    def test_does_not_share_cookbook_server_state(self):
        """Disjoint by design: never merge into _envState.servers."""
        src = MODULE.read_text(encoding="utf-8")
        assert "_envState" not in src

    def test_toast_sink_is_text_only(self):
        """Remote-derived text reaches showToast; it must not be innerHTML."""
        ui = (ROOT / "static" / "js" / "ui.js").read_text(encoding="utf-8")
        start = ui.index("export function showToast(")
        body = ui[start:ui.index("\n}", start)]
        assert "textSpan.textContent = msg;" in body
        assert "textSpan.innerHTML" not in body

    def test_secrets_are_never_rendered_back(self):
        src = MODULE.read_text(encoding="utf-8")
        # The panel may send a password, but no code path prints a stored one.
        assert "has_password" not in src
        assert "s.password" not in src


class TestCookbookWiring:
    def test_cookbook_imports_and_initialises_the_panel(self):
        src = COOKBOOK.read_text(encoding="utf-8")
        assert "import { initSshServers } from './sshServers.js';" in src
        assert "initSshServers(body);" in src

    def test_panel_markup_is_present(self):
        src = COOKBOOK.read_text(encoding="utf-8")
        for anchor in ('id="ssh-servers-list"', 'id="ssh-server-add"',
                       'id="ssh-servers-status"', 'id="ssh-add-host"',
                       'id="ssh-add-user"'):
            assert anchor in src, anchor

    def test_panel_lives_beside_the_cookbook_servers_block(self):
        src = COOKBOOK.read_text(encoding="utf-8")
        assert "// \u2500\u2500 Servers block" in src
        assert "// \u2500\u2500 My servers" in src
        assert src.index("// \u2500\u2500 Servers block") < src.index("// \u2500\u2500 My servers")
