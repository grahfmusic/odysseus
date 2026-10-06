// ============================================
// SSH SERVERS MODULE — "My servers"
// Owner-scoped saved SSH servers (ssh-rsh-spec.md §8, Phase 1 + Phase 2 terminal).
// Talks to /api/ssh/servers. Deliberately separate from the Cookbook
// Servers block above it: that list is shared GPU-infra state in
// cookbook_state.json, this one is per-user rows in ssh_servers.
// ============================================

import uiModule from './ui.js';

const esc = uiModule.esc;
const API = '/api/ssh/servers';

// ── Pure helpers (unit-tested under node; no DOM) ───────────────────────────

/**
 * Build the create/update request body from form state.
 * Secrets are omitted when blank so a PATCH never clears a stored password
 * (the server also treats empty/None as "leave unchanged").
 */
export function sshServerPayload(form = {}) {
  const body = {
    label: String(form.label || '').trim(),
    host: String(form.host || '').trim(),
    username: String(form.username || '').trim(),
    auth_type: String(form.auth_type || 'key'),
  };
  const port = String(form.port ?? '').trim();
  body.port = port === '' ? 22 : port;
  if (String(form.password || '')) body.password = String(form.password);
  if (String(form.sudo_password || '')) body.sudo_password = String(form.sudo_password);
  return body;
}

/** Human-readable one-liner for a Test result. Never throws on junk input. */
export function sshTestMessage(res) {
  if (!res || typeof res !== 'object') return 'No response';
  if (res.ok) {
    const ms = res.latency_ms != null ? ` (${res.latency_ms} ms)` : '';
    const fp = res.fingerprint ? ` · ${res.fingerprint}` : '';
    return `OK${ms}${fp}`;
  }
  return String(res.error || 'Test failed').slice(0, 200);
}

/** Pull a message out of a FastAPI error body without leaking the object. */
export function sshErrorText(payload, status) {
  if (payload && typeof payload === 'object') {
    const detail = payload.detail ?? payload.error;
    if (typeof detail === 'string' && detail.trim()) return detail.slice(0, 300);
  }
  if (typeof payload === 'string' && payload.trim()) return payload.slice(0, 300);
  return `HTTP ${status}`;
}

/**
 * Split accumulated SSE text into parsed frames, returning the trailing partial
 * chunk. Frames are the shape `routes/ssh_routes.py` emits (same as
 * `shell_routes._generate_pty`): `data: {"stream":"stdout","data":...}` up to a
 * final `data: {"exit_code":N}`. Unparsable frames are dropped, never thrown.
 */
export function parseSshSse(buf) {
  const events = [];
  let rest = String(buf == null ? '' : buf);
  let idx;
  while ((idx = rest.indexOf('\n\n')) !== -1) {
    const chunk = rest.slice(0, idx);
    rest = rest.slice(idx + 2);
    for (const line of chunk.split('\n')) {
      if (!line.startsWith('data: ')) continue;
      try { events.push(JSON.parse(line.slice(6))); } catch { /* partial frame */ }
    }
  }
  return { events, rest };
}

function _authLabel(s) {
  const a = String(s.auth_type || 'key');
  if (a === 'password') return 'password (Phase 2)';
  if (a === 'both') return 'key + password';
  return 'key';
}

function _target(s) {
  const user = s.username ? `${s.username}@` : '';
  return `${user}${s.host || ''}:${s.port || 22}`;
}

/** One server row. All user-controlled fields go through esc(). */
export function sshServerRowHtml(s = {}) {
  const id = esc(s.id || '');
  const label = esc(s.label || '(unnamed)');
  const pinned = s.host_key_fingerprint ? 'pinned' : 'not pinned — run Test';
  const btn = (action, text, title) =>
    `<button type="button" class="memory-toolbar-btn" data-ssh-action="${action}" data-id="${id}" ` +
    `title="${esc(title)}" style="height:23px;">${esc(text)}</button>`;
  let html = '';
  html += `<div class="ssh-server-row" data-ssh-row="${id}" style="display:flex;flex-direction:column;gap:4px;` +
          `padding:6px 8px;border-radius:6px;background:var(--bg-secondary,rgba(255,255,255,0.03));">`;
  html += `<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">`;
  html += `<span style="font-size:13px;font-weight:600;">${label}</span>`;
  html += `<span style="font-size:11px;opacity:0.75;font-family:var(--mono,monospace);">${esc(_target(s))}</span>`;
  html += `<span class="cookbook-dep-tag" style="font-size:8px;" title="Auth method">${esc(_authLabel(s))}</span>`;
  if (s.last_test_result === 'ok') html += `<span style="font-size:10px;color:var(--green,#50fa7b);">✓</span>`;
  html += `<span style="margin-left:auto;display:inline-flex;gap:4px;align-items:center;">`;
  html += btn('test', 'Test', 'Open a connection and pin the host key');
  html += btn('connect', 'Connect', 'Open an interactive terminal on this server');
  html += btn('run', 'Run', 'Run a one-shot command on this server');
  html += btn('key', 'Key', 'Show this user\'s public key');
  html += btn('edit', 'Edit', 'Edit server details');
  html += btn('delete', 'Delete', 'Delete this server');
  html += `</span></div>`;
  html += `<div style="font-size:10px;opacity:0.55;">host key: ${esc(pinned)}</div>`;
  html += `<div class="ssh-server-detail" data-ssh-detail="${id}" style="display:none;flex-direction:column;gap:5px;"></div>`;
  html += `</div>`;
  return html;
}

/** Empty state / list body. */
export function sshServersListHtml(list = []) {
  if (!Array.isArray(list) || !list.length) {
    return '<p class="memory-desc doclib-desc" style="margin:4px 0;">' +
           'No servers yet — add your first server below.</p>';
  }
  return list.map(sshServerRowHtml).join('');
}

// ── DOM wiring ─────────────────────────────────────────────────────────────

function _root() { return document.getElementById('ssh-servers-list'); }

function _setStatus(text) {
  const el = document.getElementById('ssh-servers-status');
  if (el) el.textContent = text || '';
}

async function _api(path, opts = {}) {
  const res = await fetch(API + path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  let payload = null;
  try { payload = await res.json(); } catch { payload = null; }
  if (!res.ok) throw new Error(sshErrorText(payload, res.status));
  return payload;
}

function _detail(id) {
  return document.querySelector(`[data-ssh-detail="${id}"]`);
}

function _showDetail(id, html) {
  const d = _detail(id);
  if (!d) return;
  _closeTerminal(d);  // a live PTY must not keep running behind a new panel
  d.innerHTML = html;
  d.style.display = 'flex';
}

function _hideDetail(id) {
  const d = _detail(id);
  if (!d) return;
  _closeTerminal(d);
  d.style.display = 'none';
  d.innerHTML = '';
}

/**
 * Close the detail panel's terminal, if any. Aborting the stream makes the
 * server's finally-block drop the remote PTY; the DELETE is the explicit path
 * (and the audit record). Both are best-effort — the idle reaper is the net.
 */
function _closeTerminal(d) {
  const t = d && d._sshTerminal;
  if (!t) return;
  d._sshTerminal = null;
  try { t.controller.abort(); } catch { /* already aborted */ }
  _api(`/${encodeURIComponent(t.serverId)}/terminal/${encodeURIComponent(t.sid)}`,
       { method: 'DELETE' }).catch(() => {});
}

export async function refreshSshServers() {
  const root = _root();
  if (!root) return;
  try {
    const data = await _api('');
    if (!document.body.contains(root)) return;  // re-rendered meanwhile
    root.innerHTML = sshServersListHtml(data && data.servers);
  } catch (err) {
    root.innerHTML = `<p class="memory-desc doclib-desc">Could not load servers: ${esc(err.message)}</p>`;
  }
}

function _editFormHtml(s) {
  const v = (x) => esc(x ?? '');
  let h = '<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">';
  h += `<input class="hwfit-sf ssh-f-label" value="${v(s.label)}" placeholder="Label" style="width:110px;" />`;
  h += `<input class="hwfit-sf ssh-f-host" value="${v(s.host)}" placeholder="host or user@host" style="width:170px;" />`;
  h += `<input class="hwfit-sf ssh-f-port" value="${v(s.port || 22)}" placeholder="22" style="width:52px;" />`;
  h += `<input class="hwfit-sf ssh-f-user" value="${v(s.username)}" placeholder="user" style="width:100px;" />`;
  const opts = ['key', 'password', 'both'].map(a =>
    `<option value="${a}"${String(s.auth_type || 'key') === a ? ' selected' : ''}>${a}</option>`).join('');
  h += `<select class="hwfit-sf ssh-f-auth">${opts}</select>`;
  h += `<input type="password" class="memory-search-input ssh-f-pass" placeholder="password (leave blank to keep)" style="width:170px;height:23px;" />`;
  h += `<input type="password" class="memory-search-input ssh-f-sudo" placeholder="sudo password (optional)" style="width:180px;height:23px;" />`;
  h += `<button type="button" class="memory-toolbar-btn ssh-f-save" data-ssh-action="save" style="height:23px;">Save</button>`;
  h += `<button type="button" class="memory-toolbar-btn ssh-f-cancel" data-ssh-action="cancel" style="height:23px;">Cancel</button>`;
  h += '</div>';
  return h;
}

function _runFormHtml() {
  let h = '<div style="display:flex;gap:4px;align-items:center;">';
  h += '<input class="memory-search-input ssh-r-cmd" placeholder="command, e.g. uptime" style="flex:1;height:23px;font-family:var(--mono,monospace);" />';
  h += '<input class="memory-search-input ssh-r-stdin" placeholder="stdin (optional)" style="width:150px;height:23px;" />';
  h += '<button type="button" class="memory-toolbar-btn ssh-r-go" style="height:23px;">Run</button>';
  h += '<button type="button" class="memory-toolbar-btn ssh-r-close" data-ssh-action="cancel" style="height:23px;">Close</button>';
  h += '</div>';
  h += '<pre class="ssh-r-out" style="display:none;margin:0;max-height:220px;overflow:auto;white-space:pre-wrap;' +
       'font-family:var(--mono,monospace);font-size:11px;line-height:1.4;"></pre>';
  return h;
}

async function _onTest(id) {
  _setStatus('Testing…');
  try {
    const res = await _api(`/${encodeURIComponent(id)}/test`, { method: 'POST' });
    _setStatus(sshTestMessage(res));
    uiModule.showToast(sshTestMessage(res));
  } catch (err) {
    _setStatus('Test failed');
    uiModule.showToast('Test failed: ' + err.message);
  }
  refreshSshServers();
}

async function _onKey(id) {
  _setStatus('Loading key…');
  try {
    const data = await _api(`/${encodeURIComponent(id)}/pubkey`);
    const key = String(data.public_key || '');
    const s = (_servers || []).find(x => x.id === id) || {};
    const hint = `ssh-copy-id -i ${data.public_path || 'data/ssh/<user>_ed25519'} ${s.username || 'user'}@${s.host || 'host'}`;
    _showDetail(id,
      '<textarea class="memory-search-input ssh-k-key" readonly rows="3" style="min-height:58px;' +
      'font-family:var(--mono,monospace);font-size:10px;line-height:1.35;">' + esc(key) + '</textarea>' +
      '<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;">' +
      '<button type="button" class="memory-toolbar-btn ssh-k-copy" style="height:23px;">Copy key</button>' +
      '<button type="button" class="memory-toolbar-btn ssh-k-cmd" style="height:23px;">Copy ssh-copy-id</button>' +
      '<button type="button" class="memory-toolbar-btn" data-ssh-action="cancel" style="height:23px;">Close</button>' +
      '</div>' +
      '<div style="font-size:10px;opacity:0.6;font-family:var(--mono,monospace);">' + esc(hint) + '</div>');
    const d = _detail(id);
    d.querySelector('.ssh-k-copy')?.addEventListener('click', () => {
      navigator.clipboard?.writeText(key);
      uiModule.showToast('Public key copied');
    });
    d.querySelector('.ssh-k-cmd')?.addEventListener('click', () => {
      navigator.clipboard?.writeText(hint);
      uiModule.showToast('ssh-copy-id command copied');
    });
    _setStatus('');
  } catch (err) {
    _setStatus('Key unavailable');
    uiModule.showToast('Key unavailable: ' + err.message);
  }
}

function _terminalHtml(info = {}) {
  const target = esc(info.target || 'remote');
  const label = info.label ? ' \u00b7 ' + esc(info.label) : '';
  let h = '<div class="ssh-t-wrap" style="display:flex;flex-direction:column;gap:4px;">';
  h += `<div style="font-size:10px;opacity:0.7;font-family:var(--mono,monospace);">` +
       `terminal: ${target}${label} \u2014 line input, Enter to send</div>`;
  h += '<pre class="ssh-t-out" style="margin:0;max-height:260px;min-height:80px;overflow:auto;white-space:pre-wrap;' +
       'word-break:break-all;font-family:var(--mono,monospace);font-size:11px;line-height:1.35;' +
       'background:var(--bg-secondary,rgba(0,0,0,0.25));padding:6px;border-radius:4px;"></pre>';
  h += '<div style="display:flex;gap:4px;align-items:center;">';
  h += '<input class="memory-search-input ssh-t-in" placeholder="command (Enter to send)" ' +
       'style="flex:1;height:23px;font-family:var(--mono,monospace);" />';
  h += '<button type="button" class="memory-toolbar-btn ssh-t-disconnect" style="height:23px;">Disconnect</button>';
  h += '</div>';
  h += '<div class="ssh-t-status" style="font-size:10px;opacity:0.6;"></div>';
  h += '</div>';
  return h;
}

async function _onConnect(id) {
  _setStatus('Connecting\u2026');
  let info;
  try {
    info = await _api(`/${encodeURIComponent(id)}/terminal`,
                      { method: 'POST', body: JSON.stringify({ cols: 100, rows: 30 }) });
  } catch (err) {
    _setStatus('');
    uiModule.showToast('Connect failed: ' + err.message);
    return;
  }
  const sid = info && info.session_id;
  if (!sid) { _setStatus(''); uiModule.showToast('Connect failed: no session'); return; }

  _showDetail(id, _terminalHtml(info));
  const d = _detail(id);
  const out = d.querySelector('.ssh-t-out');
  const statusEl = d.querySelector('.ssh-t-status');
  const input = d.querySelector('.ssh-t-in');
  const path = `/${encodeURIComponent(id)}/terminal/${encodeURIComponent(sid)}`;
  const controller = new AbortController();
  d._sshTerminal = { sid, serverId: id, controller };
  statusEl.textContent = 'connected';
  _setStatus('');
  try { input.focus(); } catch { /* not focusable in this context */ }

  const append = (text) => {
    out.textContent += text;
    out.scrollTop = out.scrollHeight;
  };

  const stream = async () => {
    let buf = '';
    try {
      const res = await fetch(API + path + '/stream',
                              { credentials: 'same-origin', signal: controller.signal });
      if (!res.ok || !res.body) { statusEl.textContent = 'stream unavailable'; return; }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parsed = parseSshSse(buf);
        buf = parsed.rest;
        for (const ev of parsed.events) {
          if (!ev || typeof ev !== 'object') continue;
          if (ev.data !== undefined && ev.data !== null) append(String(ev.data));
          if (ev.exit_code !== undefined) {
            statusEl.textContent = `session ended (exit ${ev.exit_code})`;
            input.disabled = true;
          }
        }
      }
    } catch (err) {
      if (!err || err.name !== 'AbortError') statusEl.textContent = 'stream error';
    }
  };
  stream();

  const sendInput = async (data) => {
    try {
      await _api(path + '/input', { method: 'POST', body: JSON.stringify({ data }) });
    } catch (err) {
      uiModule.showToast('Send failed: ' + err.message);
    }
  };
  const sendResize = async () => {
    const cols = Math.max(20, Math.min(400, Math.floor(out.clientWidth / 7) || 100));
    const rows = Math.max(5, Math.min(200, Math.floor(out.clientHeight / 16) || 30));
    try {
      await _api(path + '/resize', { method: 'POST', body: JSON.stringify({ cols, rows }) });
    } catch { /* resize is advisory; the PTY keeps its previous size */ }
  };

  input.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const line = input.value;
    input.value = '';
    append(line + '\n');
    sendInput(line + '\n');
  });
  d.querySelector('.ssh-t-disconnect')?.addEventListener('click', async () => {
    controller.abort();
    try { await _api(path, { method: 'DELETE' }); } catch { /* already gone */ }
    statusEl.textContent = 'disconnected';
    input.disabled = true;
    uiModule.showToast('Terminal closed');
  });
  sendResize();
}

function _onRun(id) {
  _showDetail(id, _runFormHtml());
  const d = _detail(id);
  d.querySelector('.ssh-r-go').addEventListener('click', async () => {
    const cmd = d.querySelector('.ssh-r-cmd').value;
    const stdin = d.querySelector('.ssh-r-stdin').value;
    if (!cmd.trim()) { uiModule.showToast('Enter a command'); return; }
    const out = d.querySelector('.ssh-r-out');
    out.style.display = 'block';
    out.textContent = 'Running…';
    try {
      const res = await _api(`/${encodeURIComponent(id)}/exec`, {
        method: 'POST',
        body: JSON.stringify({ cmd, stdin, timeout: 30 }),
      });
      const parts = [String(res.output || '')];
      if (res.stderr) parts.push(String(res.stderr));
      parts.push(`[exit ${res.exit_code}]`);
      out.textContent = parts.join('\n');
    } catch (err) {
      out.textContent = 'Error: ' + err.message;
    }
  });
  d.querySelector('.ssh-r-close').addEventListener('click', () => _hideDetail(id));
}

function _onEdit(id) {
  const s = (_servers || []).find(x => x.id === id) || {};
  _showDetail(id, _editFormHtml(s));
  const d = _detail(id);
  d.querySelector('.ssh-f-cancel').addEventListener('click', () => _hideDetail(id));
  d.querySelector('.ssh-f-save').addEventListener('click', async () => {
    const body = sshServerPayload({
      label: d.querySelector('.ssh-f-label').value,
      host: d.querySelector('.ssh-f-host').value,
      port: d.querySelector('.ssh-f-port').value,
      username: d.querySelector('.ssh-f-user').value,
      auth_type: d.querySelector('.ssh-f-auth').value,
      password: d.querySelector('.ssh-f-pass').value,
      sudo_password: d.querySelector('.ssh-f-sudo').value,
    });
    try {
      await _api(`/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) });
      uiModule.showToast('Server saved');
      await refreshSshServers();
    } catch (err) {
      uiModule.showToast('Save failed: ' + err.message);
    }
  });
}

async function _onDelete(id) {
  const s = (_servers || []).find(x => x.id === id) || {};
  if (!window.confirm(`Delete server "${s.label || id}"? This removes its pinned host key.`)) return;
  try {
    await _api(`/${encodeURIComponent(id)}`, { method: 'DELETE' });
    uiModule.showToast('Server deleted');
    await refreshSshServers();
  } catch (err) {
    uiModule.showToast('Delete failed: ' + err.message);
  }
}

async function _onAdd() {
  const body = sshServerPayload({
    label: document.getElementById('ssh-add-label')?.value,
    host: document.getElementById('ssh-add-host')?.value,
    port: document.getElementById('ssh-add-port')?.value,
    username: document.getElementById('ssh-add-user')?.value,
    auth_type: document.getElementById('ssh-add-auth')?.value,
    password: document.getElementById('ssh-add-pass')?.value,
    sudo_password: document.getElementById('ssh-add-sudo')?.value,
  });
  _setStatus('Adding…');
  try {
    await _api('', { method: 'POST', body: JSON.stringify(body) });
    ['ssh-add-label', 'ssh-add-host', 'ssh-add-user', 'ssh-add-pass', 'ssh-add-sudo']
      .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
    _setStatus('Added — run Test to pin the host key');
    await refreshSshServers();
  } catch (err) {
    _setStatus('');
    uiModule.showToast('Could not add server: ' + err.message);
  }
}

let _servers = [];

/** Bind once per render pass; loads and renders this user's servers. */
export function initSshServers(body) {
  const scope = body || document;
  const addBtn = scope.querySelector('#ssh-server-add');
  if (addBtn && !addBtn._sshWired) {
    addBtn._sshWired = true;
    addBtn.addEventListener('click', (e) => {
      e.preventDefault();
      _onAdd();
    });
  }
  const list = scope.querySelector('#ssh-servers-list');
  if (list && !list._sshWired) {
    list._sshWired = true;
    list.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-ssh-action]');
      if (!btn) return;
      e.preventDefault();
      const id = btn.dataset.id || btn.closest('[data-ssh-row]')?.dataset.sshRow || '';
      const action = btn.dataset.sshAction;
      if (action === 'cancel') { _hideDetail(id); return; }
      if (action === 'test') { _onTest(id); return; }
      if (action === 'key') { _onKey(id); return; }
      if (action === 'connect') { _onConnect(id); return; }
      if (action === 'run') { _onRun(id); return; }
      if (action === 'delete') { _onDelete(id); return; }
      if (action === 'edit') { _onEdit(id); return; }
    });
  }
  // Cache the row list for the row-scoped handlers, then render.
  _api('')
    .then((data) => {
      _servers = (data && data.servers) || [];
      const root = _root();
      if (root && document.body.contains(root)) {
        root.innerHTML = sshServersListHtml(_servers);
      }
    })
    .catch((err) => {
      const root = _root();
      if (root) {
        root.innerHTML = `<p class="memory-desc doclib-desc">Could not load servers: ${esc(err.message)}</p>`;
      }
    });
}
