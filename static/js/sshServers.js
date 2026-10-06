// ============================================
// MACHINES BODY — saved SSH servers (data / row / terminal layer)
// Owner-scoped saved SSH servers (ssh-rsh-spec.md §8, Phase 1 + Phase 2 terminal).
// Talks to /api/ssh/servers. This file is the *body* of the Machines area:
// static/js/machines.js owns the window shell (master–detail layout, add/edit
// form dialog, transfer panel, activity view, deep links) and imports this file.
// Deliberately separate from the Cookbook Servers block: that list is shared
// GPU-infra state in cookbook_state.json, this one is per-user rows in
// ssh_servers.
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
           'No machines yet — add your first machine.</p>';
  }
  return list.map(sshServerRowHtml).join('');
}

/**
 * Per-machine detail *slot* for the master–detail layout. Each machine keeps its
 * own DOM node for the whole session, so a live terminal inside it is never
 * destroyed by switching machines, minimizing or closing the window (spec §7.3).
 */
export function sshMachineDetailHostHtml(id) {
  return `<div class="machine-detail-slot" data-machine-slot="${esc(id)}" ` +
         `style="display:none;flex-direction:column;gap:6px;">` +
         `<div class="machine-info" data-machine-info="${esc(id)}"></div>` +
         `<div class="ssh-server-detail" data-ssh-detail="${esc(id)}" ` +
         `style="display:none;flex-direction:column;gap:5px;"></div>` +
         `<div class="machine-extra" data-machine-extra="${esc(id)}" ` +
         `style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;"></div>` +
         `</div>`;
}

/** Connection detail pane (spec §7.2) — no secrets, ever. */
export function sshMachineInfoHtml(s) {
  s = s || {};
  const row = (k, v, mono) =>
    `<div style="display:flex;gap:6px;font-size:11px;">` +
    `<span style="opacity:0.55;min-width:66px;">${esc(k)}</span>` +
    `<span style="${mono ? 'font-family:var(--mono,monospace);' : ''}word-break:break-all;">${esc(v)}</span>` +
    `</div>`;
  const fp = s.host_key_fingerprint ? s.host_key_fingerprint : 'not pinned — run Test';
  const seen = s.last_test_at || s.updated_at || '';
  const last = s.last_test_result ? `${s.last_test_result}${seen ? ' · ' + seen : ''}` : 'never tested';
  let h = '<div style="display:flex;flex-direction:column;gap:3px;">';
  h += row('target', _target(s), true);
  h += row('auth', _authLabel(s));
  h += row('host key', fp, true);
  h += row('last test', last);
  h += '</div>';
  return h;
}

/** Activity row for one audit entry (spec §8). Hashes only, never commands. */
export function sshAuditRowHtml(r) {
  // `= {}` would not cover an explicit null (JSON payloads can carry one).
  r = r || {};
  const when = String(r.created_at || '').replace('T', ' ').slice(0, 19);
  const hash = String(r.command_hash || '');
  const short = hash ? hash.slice(0, 12) : '—';
  const code = r.exit_code === null || r.exit_code === undefined ? '' : ` · exit ${r.exit_code}`;
  return '<div class="machine-audit-row" style="display:flex;gap:8px;align-items:baseline;' +
         'font-size:11px;padding:3px 0;border-bottom:1px solid var(--border,rgba(255,255,255,0.06));">' +
         `<span style="opacity:0.55;min-width:132px;font-family:var(--mono,monospace);">${esc(when)}</span>` +
         `<span style="min-width:104px;font-weight:600;">${esc(r.event || '')}</span>` +
         `<span style="opacity:0.8;">${esc(r.server_label || r.server_id || '')}</span>` +
         `<span style="margin-left:auto;opacity:0.55;font-family:var(--mono,monospace);">` +
         `${esc(short)}${esc(code)}</span>` +
         '</div>';
}

/** Payload for POST /api/ssh/servers/{id}/transfer (mirrors TransferRequest). */
export function sshTransferRequest(form = {}) {
  const direction = String(form.direction || 'upload');
  return {
    direction: direction === 'download' ? 'download' : 'upload',
    local_path: String(form.local_path || '').trim(),
    remote_path: String(form.remote_path || '').trim(),
  };
}

// ── API layer ───────────────────────────────────────────────────────────────

let _servers = [];
// serverId → { sid, controller }. One terminal per machine, several in parallel
// (the server caps concurrent PTYs per owner at 3 — spec §7.3).
const _live = new Map();
// Shell-installed overrides for actions the area owns (e.g. Edit → form dialog).
let _handlers = {};

async function _fetchUrl(url, opts = {}) {
  const res = await fetch(url, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  let payload = null;
  try { payload = await res.json(); } catch { payload = null; }
  if (!res.ok) throw new Error(sshErrorText(payload, res.status));
  return payload;
}

function _api(path, opts = {}) {
  return _fetchUrl(API + path, opts);
}

/** The last loaded server list (the shell renders from this). */
export function getSshServers() {
  return Array.isArray(_servers) ? _servers.slice() : [];
}

/** The shell installs `{edit(id, server), changed(reason)}`: Edit opens its form
 * dialog, and `changed` lets the shell re-render the panes it derives from state
 * this module owns (info pane, live-session list, slots). */
export function setSshActionHandlers(handlers) {
  _handlers = handlers || {};
}

/**
 * Tell the shell its derived panes are stale. Best-effort by design: the body
 * stays usable standalone (tests, the old inline layout), and a shell that
 * throws must not break a terminal that is already streaming.
 */
function _notifyChanged(reason) {
  try {
    if (typeof _handlers.changed === 'function') _handlers.changed(reason);
  } catch { /* no shell installed — nothing to refresh */ }
}

export function listSshServers() {
  return _api('');
}

export function createSshServer(body) {
  return _api('', { method: 'POST', body: JSON.stringify(body) });
}

export function updateSshServer(id, body) {
  return _api(`/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) });
}

export function deleteSshServer(id) {
  return _api(`/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export function testSshServer(id) {
  return _api(`/${encodeURIComponent(id)}/test`, { method: 'POST' });
}

export function sshServerPubkey(id) {
  return _api(`/${encodeURIComponent(id)}/pubkey`);
}

export function runSshCommand(id, cmd, stdin = '', timeout = 30) {
  return _api(`/${encodeURIComponent(id)}/exec`, {
    method: 'POST',
    body: JSON.stringify({ cmd, stdin, timeout }),
  });
}

export function transferSshFile(id, form) {
  return _api(`/${encodeURIComponent(id)}/transfer`, {
    method: 'POST',
    body: JSON.stringify(sshTransferRequest(form)),
  });
}

/** Activity log (spec §8). `scope: 'all'` is admin-only server-side. */
export function listSshAudit(params = {}) {
  const q = new URLSearchParams();
  if (params.limit) q.set('limit', String(params.limit));
  if (params.event) q.set('event', String(params.event));
  if (params.server_id) q.set('server_id', String(params.server_id));
  if (params.scope) q.set('scope', String(params.scope));
  const qs = q.toString();
  return _fetchUrl('/api/ssh/audit' + (qs ? '?' + qs : ''));
}

/** Live PTY sessions for this owner (spec §8.2) — read-only. */
export function listSshTerminals() {
  return _fetchUrl('/api/ssh/terminals');
}

/** Abort a session's stream AND ask the server to drop the remote PTY. */
export function closeSshTerminalById(serverId, sid) {
  const entry = _live.get(serverId);
  if (entry && entry.sid === sid) {
    _live.delete(serverId);
    try { entry.controller.abort(); } catch { /* already aborted */ }
  }
  return _api(`/${encodeURIComponent(serverId)}/terminal/${encodeURIComponent(sid)}`,
              { method: 'DELETE' }).catch(() => {});
}

/** Sessions this client is currently holding (for the live indicator/list). */
export function getLiveTerminals() {
  return [..._live.entries()].map(([serverId, v]) => ({ serverId, sid: v.sid }));
}

/** Disconnect every session this client holds (area-level "Disconnect all"). */
export async function disconnectAllTerminals() {
  const held = [..._live.entries()].map(([serverId, v]) => ({ serverId, sid: v.sid }));
  await Promise.all(held.map((s) => closeSshTerminalById(s.serverId, s.sid)));
  return held.length;
}

// ── DOM wiring ─────────────────────────────────────────────────────────────

function _root() { return document.getElementById('ssh-servers-list'); }

function _setStatus(text) {
  const el = document.getElementById('ssh-servers-status');
  if (el) el.textContent = text || '';
}

function _detail(id) {
  // The shell owns the detail pane, but `sshServerRowHtml` still carries its own
  // (hidden) detail host from the pre-restructure markup — and the list comes
  // first in document order, so an unscoped query resolves that one and renders
  // terminals inside the 300px list instead of the pane on the right.
  return document.querySelector(`.machine-detail-slot [data-ssh-detail="${id}"]`)
      || document.querySelector(`[data-ssh-detail="${id}"]`);
}

function _showDetail(id, html) {
  const d = _detail(id);
  if (!d) return;
  // NOTE: never tear a live session down here. The teardown that used to sit on
  // this path killed the remote PTY on every row switch, which the Machines area
  // forbids — showing or hiding a panel is not a disconnect. Switching machines, collapsing
  // the panel, minimizing or closing the window must all leave the remote PTY
  // running (spec §7.3 / AC5); only Disconnect (or the server's cap/idle reaper)
  // ends it.
  d.innerHTML = html;
  d.style.display = 'flex';
}

function _hideDetail(id) {
  const d = _detail(id);
  if (!d) return;
  // Hide only — the node (and any live terminal inside it) survives so a
  // minimized window or a different selection can come back to it.
  d.style.display = 'none';
}

export async function refreshSshServers() {
  const root = _root();
  if (!root) return [];
  try {
    const data = await listSshServers();
    if (!document.body.contains(root)) return [];  // re-rendered meanwhile
    _servers = (data && data.servers) || [];
    root.innerHTML = sshServersListHtml(_servers);
    return _servers;
  } catch (err) {
    _servers = [];
    root.innerHTML = `<p class="memory-desc doclib-desc">Could not load machines: ${esc(err.message)}</p>`;
    return [];
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
  // `data-id` matters: the area delegates `data-ssh-action` clicks (the detail
  // pane sits outside the row list), so a button without it resolves no machine.
  h += `<button type="button" class="memory-toolbar-btn ssh-f-cancel" data-ssh-action="cancel" data-id="${v(s.id)}" style="height:23px;">Cancel</button>`;
  h += '</div>';
  return h;
}

function _runFormHtml(id) {
  let h = '<div style="display:flex;gap:4px;align-items:center;">';
  h += '<input class="memory-search-input ssh-r-cmd" placeholder="command, e.g. uptime" style="flex:1;height:23px;font-family:var(--mono,monospace);" />';
  h += '<input class="memory-search-input ssh-r-stdin" placeholder="stdin (optional)" style="width:150px;height:23px;" />';
  h += '<button type="button" class="memory-toolbar-btn ssh-r-go" style="height:23px;">Run</button>';
  h += `<button type="button" class="memory-toolbar-btn ssh-r-close" data-ssh-action="cancel" data-id="${esc(id)}" style="height:23px;">Close</button>`;
  h += '</div>';
  h += '<pre class="ssh-r-out" style="display:none;margin:0;max-height:220px;overflow:auto;white-space:pre-wrap;' +
       'font-family:var(--mono,monospace);font-size:11px;line-height:1.4;"></pre>';
  return h;
}

async function _onTest(id) {
  _setStatus('Testing…');
  try {
    const res = await testSshServer(id);
    _setStatus(sshTestMessage(res));
    uiModule.showToast(sshTestMessage(res));
  } catch (err) {
    _setStatus('Test failed');
    uiModule.showToast('Test failed: ' + err.message);
  }
  await refreshSshServers();
  // A successful Test pins the host key — the footer text, the ✓ badge and the
  // detail pane's fingerprint all come from the list we just re-fetched.
  _notifyChanged('tested');
}

async function _onKey(id) {
  _setStatus('Loading key…');
  try {
    const data = await sshServerPubkey(id);
    const key = String(data.public_key || '');
    const s = (_servers || []).find(x => x.id === id) || {};
    const hint = `ssh-copy-id -i ${data.public_path || 'data/ssh/<user>_ed25519'} ${s.username || 'user'}@${s.host || 'host'}`;
    _showDetail(id,
      '<textarea class="memory-search-input ssh-k-key" readonly rows="3" style="min-height:58px;' +
      'font-family:var(--mono,monospace);font-size:10px;line-height:1.35;">' + esc(key) + '</textarea>' +
      '<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;">' +
      '<button type="button" class="memory-toolbar-btn ssh-k-copy" style="height:23px;">Copy key</button>' +
      '<button type="button" class="memory-toolbar-btn ssh-k-cmd" style="height:23px;">Copy ssh-copy-id</button>' +
      `<button type="button" class="memory-toolbar-btn" data-ssh-action="cancel" data-id="${esc(id)}" style="height:23px;">Close</button>` +
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
    // The server's cap error is surfaced verbatim (spec §7.3): never retried,
    // never swallowed — the area shows which machines hold the slots.
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
  _live.set(id, { sid, controller });
  _notifyChanged('connected');
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
            _live.delete(id);
            _notifyChanged('ended');
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
    // The one in-UI teardown: ends the session on purpose (spec §7.3).
    await closeSshTerminalById(id, sid);
    statusEl.textContent = 'disconnected';
    input.disabled = true;
    uiModule.showToast('Terminal closed');
    _notifyChanged('disconnected');
  });
  sendResize();
}

function _onRun(id) {
  _showDetail(id, _runFormHtml(id));
  const d = _detail(id);
  d.querySelector('.ssh-r-go').addEventListener('click', async () => {
    const cmd = d.querySelector('.ssh-r-cmd').value;
    const stdin = d.querySelector('.ssh-r-stdin').value;
    if (!cmd.trim()) { uiModule.showToast('Enter a command'); return; }
    const out = d.querySelector('.ssh-r-out');
    out.style.display = 'block';
    out.textContent = 'Running…';
    try {
      const res = await runSshCommand(id, cmd, stdin, 30);
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
  if (typeof _handlers.edit === 'function') { _handlers.edit(id, s); return; }
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
      await updateSshServer(id, body);
      uiModule.showToast('Machine saved');
      await refreshSshServers();
      _notifyChanged('saved');
    } catch (err) {
      uiModule.showToast('Save failed: ' + err.message);
    }
  });
}

async function _onDelete(id) {
  const s = (_servers || []).find(x => x.id === id) || {};
  if (!window.confirm(`Delete machine "${s.label || id}"? This removes its pinned host key.`)) return;
  try {
    // A deleted machine must not leave a live PTY behind.
    const held = _live.get(id);
    if (held) await closeSshTerminalById(id, held.sid);
    await deleteSshServer(id);
    uiModule.showToast('Machine deleted');
    // Re-fetch BEFORE notifying: the shell re-renders from the cached list, so
    // notifying first would redraw the deleted machine's slot from stale data.
    await refreshSshServers();
    // `deleted`: the shell drops the selection so the removed machine's pane
    // does not linger with stale (and now invalid) actions on it.
    _notifyChanged('deleted');
  } catch (err) {
    uiModule.showToast('Delete failed: ' + err.message);
  }
}

/**
 * Bind once per mount: click delegation for the row actions, then the initial
 * load. Returns the loaded server list so the shell can render its panes from
 * the same fetch (no second GET).
 */
export async function initSshServers(body) {
  const scope = body || document;
  // Delegate on the whole area rather than on `#ssh-servers-list`: the row
  // buttons and the detail pane's Cancel/Close live in different panes (the
  // shell owns that layout), so a list-scoped listener would leave every
  // detail-pane `data-ssh-action` button dead.
  if (!scope._sshWired) {
    scope._sshWired = true;
    scope.addEventListener('click', (e) => {
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
  return refreshSshServers();
}
