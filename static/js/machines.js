// ============================================
// MACHINES AREA — window shell
//
// "My servers" is not configuration: it is an owner-scoped remote-machine area
// (spec: machines-area-spec.md). This module owns the window shell — modal
// registration/restore, the master–detail layout, the add/edit form dialog, the
// transfer panel, the activity view and the #machine-<id> deep link — while
// `static/js/sshServers.js` stays the data / row / terminal body layer.
//
// The window is NEVER torn down on hide: a live remote terminal keeps running
// behind the dock chip, so minimize/close/reopen must not destroy its DOM
// (spec §7.3, AC5).
// ============================================

import * as Modals from './modalManager.js';
import uiModule from './ui.js';
import { makeWindowDraggable } from './windowDrag.js';

// Kept as its own import so the wiring contract is greppable in one piece.
import { initSshServers } from './sshServers.js';
import {
  refreshSshServers, getSshServers, setSshActionHandlers,
  createSshServer, updateSshServer, deleteSshServer, sshServerPubkey,
  transferSshFile, listSshAudit, listSshTerminals, closeSshTerminalById,
  disconnectAllTerminals, getLiveTerminals,
  sshServerPayload, sshMachineDetailHostHtml, sshMachineInfoHtml,
  sshAuditRowHtml, sshCopyIdHint, sshInstallMessage, installSshKey,
} from './sshServers.js';

const esc = uiModule.esc;
const MODAL_ID = 'machines-modal';
const MAX_TERMINAL_SESSIONS_PER_USER = 3;

let _mounted = false;
let _selected = '';
let _closeGen = 0;
let _dragWired = false;
let _formState = { id: '' };

function _modal() { return document.getElementById(MODAL_ID); }
function _body() { return document.querySelector('#machines-modal .machines-body'); }
function _el(id) { return document.getElementById(id); }

// ── Shell markup ────────────────────────────────────────────────────────────

function _shellHtml() {
  let h = '';
  h += '<div class="machines-toolbar" style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">';
  h += '<button class="cal-add-btn cal-add-btn-text" id="machines-add-btn" title="Add machine">' +
       '<span class="cal-add-plus">+</span><span class="cal-add-label">Add machine</span></button>';
  h += '<span id="ssh-servers-status" style="font-size:10px;opacity:0.6;"></span>';
  h += '<span style="margin-left:auto;display:inline-flex;gap:4px;align-items:center;">';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-disconnect-all" hidden ' +
       'title="End every terminal this window still holds">Disconnect all</button>';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-activity-btn" ' +
       'title="Activity for every machine">Activity</button>';
  h += '</span></div>';
  h += '<div class="machines-split" style="display:flex;gap:10px;align-items:stretch;min-height:0;flex:1;">';
  h += '<div class="machines-list-pane" style="flex:0 0 300px;min-width:240px;display:flex;' +
       'flex-direction:column;gap:6px;overflow:auto;max-height:62vh;">';
  h += '<div id="ssh-servers-list"></div>';
  h += '<div id="machines-live"></div>';
  h += '</div>';
  h += '<div class="machines-detail-pane" style="flex:1;min-width:0;display:flex;' +
       'flex-direction:column;gap:6px;overflow:auto;max-height:62vh;">';
  h += '<div id="machines-empty" class="hidden"></div>';
  h += '<div id="machines-detail-empty" class="memory-desc doclib-desc" style="margin:2px 0;">' +
       'Select a machine to see its details.</div>';
  h += '<div id="machines-slots"></div>';
  h += '<div id="machines-transfer" class="hidden"></div>';
  h += '<div id="machines-activity" class="hidden"></div>';
  h += '</div></div>';
  h += _formHtml();
  return h;
}

/** Add/edit form dialog (spec §6.3) — replaces the old inline add row. */
function _formHtml() {
  // Visibility is driven by `style.display` (not the `.hidden` class): the
  // inline `display` needed for the layout would otherwise override `.hidden`
  // and leave this overlay covering the window.
  let h = '<div id="machines-form" style="position:absolute;inset:0;z-index:5;display:none;' +
          'background:var(--bg);flex-direction:column;gap:6px;padding:10px;overflow:auto;">';
  h += '<div style="display:flex;align-items:baseline;gap:8px;">';
  h += '<h3 style="margin:0;font-size:13px;" id="machines-f-title">Add machine</h3>';
  h += '<button type="button" class="close-btn" id="machines-f-close" aria-label="Close form">✖</button>';
  h += '</div>';
  h += '<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;">';
  h += '<input class="hwfit-sf" id="machines-f-label" placeholder="Label" style="width:130px;" />';
  h += '<input class="hwfit-sf" id="machines-f-host" placeholder="host or user@host" style="width:190px;" />';
  h += '<input class="hwfit-sf" id="machines-f-port" placeholder="22" title="SSH port (default 22)" style="width:60px;" />';
  h += '<input class="hwfit-sf" id="machines-f-user" placeholder="user" style="width:110px;" />';
  h += '<select class="hwfit-sf" id="machines-f-auth" title="Auth method">' +
       '<option value="key">key</option><option value="password">password</option>' +
       '<option value="both">both</option></select>';
  h += '<input type="password" class="memory-search-input" id="machines-f-pass" ' +
       'placeholder="password (leave blank to keep)" style="width:200px;height:23px;" />';
  h += '<input type="password" class="memory-search-input" id="machines-f-sudo" ' +
       'placeholder="sudo password (optional)" style="width:200px;height:23px;" />';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-f-save" style="height:23px;">Save</button>';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-f-cancel" style="height:23px;">Cancel</button>';
  h += '</div>';
  h += '<p class="memory-desc doclib-desc" style="margin:2px 0;">The password is only sent when you type one — ' +
       'a blank field keeps the stored secret. Keys are per-user.</p>';
  h += '<div class="admin-card" style="flex:0 0 auto;display:flex;flex-direction:column;gap:4px;">';
  h += '<h2 style="margin:0;padding:0;line-height:1;font-size:12px;">Commands</h2>';
  h += '<textarea class="memory-search-input" id="machines-f-key" readonly rows="3" ' +
       'placeholder="Select or save a machine to load your public key" ' +
       'style="min-height:58px;font-family:var(--mono,monospace);font-size:10px;line-height:1.35;"></textarea>';
  h += '<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;">';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-f-keybtn" style="height:23px;">Show public key</button>';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-f-installkey" style="height:23px;" ' +
       'title="Sign in with the saved password or your key, then append the key above to the ' +
       'machine&#39;s ~/.ssh/authorized_keys">Install key on machine</button>';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-f-copykey" style="height:23px;">Copy key</button>';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-f-copyid" style="height:23px;">Copy ssh-copy-id</button>';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-f-copyrun" style="height:23px;">Copy ssh command</button>';
  h += '</div>';
  h += '<div style="font-size:10px;opacity:0.6;font-family:var(--mono,monospace);" id="machines-f-hint"></div>';
  h += '<div style="font-size:10px;opacity:0.6;">Install signs in with the saved password when ' +
       'there is one, otherwise your key, and appends the key on the machine — no copy-paste.</div>';
  h += '</div>';
  h += '</div>';
  return h;
}

function _emptyStateHtml(hasMachines) {
  if (hasMachines) return '';
  let h = '<div class="admin-card" style="flex:0 0 auto;display:flex;flex-direction:column;gap:4px;">';
  h += '<h2 style="margin:0;padding:0;line-height:1;font-size:13px;">What is a machine?</h2>';
  h += '<p class="memory-desc doclib-desc" style="margin:2px 0;">A machine is one of your own SSH hosts — ' +
       'a home lab box, a VPS, a Raspberry Pi. Odysseus stores the address, connects as your remote login ' +
       'user, and can open a terminal, run one-shot commands and move files. Only you can see and use it.</p>';
  h += '<p class="memory-desc doclib-desc" style="margin:2px 0;">Run <strong>Test</strong> once after adding it: ' +
       'that pins the host key (trust-on-first-use) and unlocks terminals and transfers. Your public key is ' +
       'shown here for <code>ssh-copy-id</code> once a machine exists.</p>';
  // The action rides on the delegated `data-machine-action` handler: this markup
  // is re-created by every _render(), so a listener bound to the element once
  // would be dropped with the previous node (a dead primary CTA).
  h += '<div><button type="button" class="cal-add-btn cal-add-btn-text" id="machines-empty-add" ' +
       'data-machine-action="add">' +
       '<span class="cal-add-plus">+</span><span class="cal-add-label">Add your first machine</span></button></div>';
  h += '</div>';
  return h;
}

// ── Rendering ───────────────────────────────────────────────────────────────

function _serverById(id) {
  return getSshServers().find((s) => s.id === id) || null;
}

/**
 * Append missing per-machine slots, drop slots for deleted machines and refresh
 * the info panes — without ever rebuilding an existing slot. That is what keeps
 * a live terminal's DOM (and its stream) alive across a refresh (AC5).
 */
function _renderSlots(servers) {
  const host = _el('machines-slots');
  if (!host) return;
  const wanted = new Set(servers.map((s) => String(s.id)));
  for (const slot of [...host.querySelectorAll('[data-machine-slot]')]) {
    if (!wanted.has(slot.dataset.machineSlot)) slot.remove();
  }
  for (const s of servers) {
    const id = String(s.id);
    let slot = host.querySelector(`[data-machine-slot="${CSS.escape(id)}"]`);
    if (!slot) {
      host.insertAdjacentHTML('beforeend', sshMachineDetailHostHtml(id));
      slot = host.querySelector(`[data-machine-slot="${CSS.escape(id)}"]`);
      if (!slot) continue;
      const extra = slot.querySelector('[data-machine-extra]');
      if (extra) {
        extra.innerHTML =
          `<button type="button" class="memory-toolbar-btn" data-machine-action="transfer" ` +
          `data-id="${esc(id)}" style="height:23px;" title="Upload or download a file">Transfer</button>` +
          `<button type="button" class="memory-toolbar-btn" data-machine-action="activity" ` +
          `data-id="${esc(id)}" style="height:23px;" title="Activity for this machine">Activity</button>`;
      }
    }
    const info = slot.querySelector('[data-machine-info]');
    if (info) info.innerHTML = sshMachineInfoHtml(s);
  }
  _applySelection();
}

function _applySelection() {
  const host = _el('machines-slots');
  if (!host) return;
  let matched = false;
  for (const slot of host.querySelectorAll('[data-machine-slot]')) {
    const on = slot.dataset.machineSlot === _selected;
    slot.style.display = on ? 'flex' : 'none';
    if (on) matched = true;
  }
  const empty = _el('machines-detail-empty');
  if (empty) empty.classList.toggle('hidden', matched);
  if (_selected && !matched) _selected = '';
}

function _select(id) {
  _selected = String(id || '');
  _hidePanel('machines-transfer');
  _hidePanel('machines-activity');
  _applySelection();
}

function _hidePanel(id) {
  const el = _el(id);
  if (el) el.classList.add('hidden');
}

function _renderEmpty(servers) {
  const el = _el('machines-empty');
  if (!el) return;
  const html = _emptyStateHtml(servers.length > 0);
  el.innerHTML = html;
  el.classList.toggle('hidden', !html);
}

async function _renderLive() {
  const el = _el('machines-live');
  if (!el) return;
  let sessions = [];
  try {
    const data = await listSshTerminals();
    sessions = (data && data.sessions) || [];
  } catch { /* the live list is advisory — never block the area on it */ }
  const mine = getLiveTerminals();
  // Keep the affordance in step with the list. This has to happen before the
  // early return below: otherwise disconnecting the last terminal leaves a
  // "Disconnect all" button behind with nothing to disconnect.
  _toggleDisconnectAll(mine.length > 0);
  if (!sessions.length) { el.innerHTML = ''; return; }
  let h = '<div style="font-size:10px;opacity:0.6;margin:2px 0;">' +
          `live terminals: ${sessions.length} of ${MAX_TERMINAL_SESSIONS_PER_USER}</div>`;
  for (const s of sessions) {
    const label = s.server_label || _serverById(s.server_id)?.label || s.server_id;
    const held = mine.some((m) => m.sid === s.session_id);
    h += '<div style="display:flex;gap:6px;align-items:center;font-size:11px;">';
    h += `<span style="color:var(--green,#50fa7b);">●</span><span style="flex:1;min-width:0;overflow:hidden;` +
         `text-overflow:ellipsis;white-space:nowrap;">${esc(label)}</span>`;
    h += `<button type="button" class="memory-toolbar-btn" data-machine-action="disconnect" ` +
         `data-server="${esc(s.server_id)}" data-session="${esc(s.session_id)}" style="height:20px;" ` +
         `title="${held ? 'This window holds it' : 'Held by another tab or a client that vanished'}">` +
         `Disconnect</button>`;
    h += '</div>';
  }
  el.innerHTML = h;
}

function _toggleDisconnectAll(on) {
  const btn = _el('machines-disconnect-all');
  if (btn) btn.hidden = !on;
}

async function _render() {
  const servers = getSshServers();
  _renderEmpty(servers);
  _renderSlots(servers);
  await _renderLive();
  if (_selected && !_serverById(_selected)) {
    uiModule.showToast('That machine was not found');
    _select('');
  }
}

// ── Form dialog ─────────────────────────────────────────────────────────────

async function _openForm(id) {
  const dialog = _el('machines-form');
  if (!dialog) return;
  const s = id ? _serverById(id) : null;
  _formState = { id: s ? String(s.id) : '' };
  const title = _el('machines-f-title');
  if (title) title.textContent = s ? `Edit ${s.label || 'machine'}` : 'Add machine';
  const set = (elId, v) => { const el = _el(elId); if (el) el.value = v ?? ''; };
  set('machines-f-label', s?.label);
  set('machines-f-host', s?.host);
  set('machines-f-port', s?.port || 22);
  set('machines-f-user', s?.username);
  set('machines-f-auth', s?.auth_type || 'key');
  set('machines-f-pass', '');
  set('machines-f-sudo', '');
  const key = _el('machines-f-key');
  if (key) key.value = '';
  const hint = _el('machines-f-hint');
  if (hint) hint.textContent = s
    ? 'Show the public key to get copy-ready commands for this machine.'
    : 'Save the machine first, then come back for its copy-ready commands.';
  dialog.style.display = 'flex';
  _el('machines-f-label')?.focus?.();
}

function _closeForm() {
  const dialog = _el('machines-form');
  if (dialog) dialog.style.display = 'none';
}

async function _saveForm() {
  const body = sshServerPayload({
    label: _el('machines-f-label')?.value,
    host: _el('machines-f-host')?.value,
    port: _el('machines-f-port')?.value,
    username: _el('machines-f-user')?.value,
    auth_type: _el('machines-f-auth')?.value,
    password: _el('machines-f-pass')?.value,
    sudo_password: _el('machines-f-sudo')?.value,
  });
  const saving = !!_formState.id;
  try {
    if (saving) {
      await updateSshServer(_formState.id, body);
      uiModule.showToast('Machine saved');
    } else {
      const res = await createSshServer(body);
      uiModule.showToast('Machine added — run Test to pin the host key');
      const created = res && res.server;
      if (created && created.id) _selected = String(created.id);
    }
  } catch (err) {
    uiModule.showToast((saving ? 'Save failed: ' : 'Could not add machine: ') + err.message);
    return;
  }
  _closeForm();
  await refreshSshServers();
  await _render();
}

async function _showCommands() {
  if (!_formState.id) { uiModule.showToast('Save the machine first'); return; }
  const s = _serverById(_formState.id);
  try {
    const data = await sshServerPubkey(_formState.id);
    const keyEl = _el('machines-f-key');
    if (keyEl) keyEl.value = String(data.public_key || '');
    // One source of truth for the hint: the server builds it from the row's
    // real target and port (ssh_remote.copy_id_hint). The local fallback covers
    // an older cached payload.
    const copyHint = sshCopyIdHint(s || {}, data);
    const runHint = `ssh ${s?.username ? s.username + '@' : ''}${s?.host || 'host'}` +
                    `${s?.port && String(s.port) !== '22' ? ' -p ' + s.port : ''} '<command>'`;
    const hint = _el('machines-f-hint');
    if (hint) hint.textContent = copyHint;
    _formState.hints = { copyHint, runHint };
  } catch (err) {
    uiModule.showToast('Key unavailable: ' + err.message);
  }
}

/**
 * Install this user's public key on the machine the form is editing.
 *
 * Saves the form first when there are unsaved edits to an existing machine?
 * No — deliberately not: the install talks to the machine the *server* has
 * stored, so silently persisting a half-typed host would install the key on the
 * wrong place. The button therefore requires a saved machine, exactly like
 * `_showCommands`.
 */
async function _installKey() {
  if (!_formState.id) { uiModule.showToast('Save the machine first'); return; }
  const btn = _el('machines-f-installkey');
  if (btn && btn.disabled) return;
  if (btn) btn.disabled = true;
  const hint = _el('machines-f-hint');
  try {
    const res = await installSshKey(_formState.id);
    const msg = sshInstallMessage(res);
    uiModule.showToast(msg);
    if (hint) hint.textContent = msg;
    if (res && res.ok) {
      await refreshSshServers();
      await _render();
    }
  } catch (err) {
    uiModule.showToast('Install failed: ' + err.message);
    if (hint) hint.textContent = 'Install failed: ' + err.message;
  } finally {
    if (btn) btn.disabled = false;
  }
}

function _copy(text, label) {
  if (!text) { uiModule.showToast('Nothing to copy yet — press Show public key first'); return; }
  navigator.clipboard?.writeText(text);
  uiModule.showToast(label + ' copied');
}

// ── Transfer panel ──────────────────────────────────────────────────────────

function _openTransfer(id) {
  const panel = _el('machines-transfer');
  if (!panel) return;
  _hidePanel('machines-activity');
  const s = _serverById(id) || {};
  const label = s.label || id;
  let h = '<div class="admin-card" style="flex:0 0 auto;display:flex;flex-direction:column;gap:4px;">';
  h += `<h2 style="margin:0;padding:0;line-height:1;font-size:12px;">Transfer · ${esc(label)}</h2>`;
  h += '<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">';
  h += '<select class="hwfit-sf" id="machines-x-dir"><option value="upload">upload (local → remote)</option>' +
       '<option value="download">download (remote → local)</option></select>';
  h += '<input class="memory-search-input" id="machines-x-local" placeholder="local path inside the workspace" ' +
       'style="width:290px;height:23px;font-family:var(--mono,monospace);" />';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-x-browse" style="height:23px;" ' +
       'title="Fill the local field from the workspace">Browse</button>';
  h += '<input class="memory-search-input" id="machines-x-remote" placeholder="remote path" ' +
       'style="width:250px;height:23px;font-family:var(--mono,monospace);" />';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-x-go" style="height:23px;">Run</button>';
  h += '<button type="button" class="memory-toolbar-btn" data-machine-action="close-panel" style="height:23px;">Close</button>';
  h += '</div>';
  h += '<p class="memory-desc doclib-desc" style="margin:2px 0;">The local side is confined to this ' +
       'workspace — the server rejects paths outside it.</p>';
  h += '<pre id="machines-x-out" style="display:none;margin:0;max-height:200px;overflow:auto;white-space:pre-wrap;' +
       'font-family:var(--mono,monospace);font-size:11px;"></pre>';
  h += '</div>';
  panel.innerHTML = h;
  panel.classList.remove('hidden');
  _el('machines-x-browse')?.addEventListener('click', () => {
    const target = _el('machines-x-local');
    if (target) { target.focus(); uiModule.showToast('Paste or type the workspace-relative path'); }
  });
  _el('machines-x-go')?.addEventListener('click', async () => {
    const out = _el('machines-x-out');
    const form = {
      direction: _el('machines-x-dir')?.value,
      local_path: _el('machines-x-local')?.value,
      remote_path: _el('machines-x-remote')?.value,
    };
    if (!form.local_path || !form.remote_path) {
      uiModule.showToast('Both paths are required');
      return;
    }
    if (out) { out.style.display = 'block'; out.textContent = 'Transferring…'; }
    try {
      const res = await transferSshFile(id, form);
      if (out) out.textContent = JSON.stringify(res, null, 2);
      uiModule.showToast('Transfer complete');
    } catch (err) {
      if (out) out.textContent = 'Error: ' + err.message;
    }
    await _renderLive();
  });
}

// ── Activity view ───────────────────────────────────────────────────────────

async function _openActivity(opts = {}) {
  const panel = _el('machines-activity');
  if (!panel) return;
  _hidePanel('machines-transfer');
  const label = opts.serverId ? (_serverById(opts.serverId)?.label || opts.serverId) : 'All machines';
  let h = '<div class="admin-card" style="flex:0 0 auto;display:flex;flex-direction:column;gap:4px;">';
  h += `<h2 style="margin:0;padding:0;line-height:1;font-size:12px;">Activity · ${esc(label)}</h2>`;
  h += '<div style="display:flex;gap:6px;align-items:center;">';
  h += '<label id="machines-a-scopewrap" class="hidden" style="font-size:11px;display:flex;gap:4px;' +
       'align-items:center;"><input type="checkbox" id="machines-a-scope" />All users</label>';
  h += '<button type="button" class="memory-toolbar-btn" id="machines-a-refresh" style="height:23px;">Refresh</button>';
  h += '<button type="button" class="memory-toolbar-btn" data-machine-action="close-panel" style="height:23px;">Close</button>';
  h += '<span style="margin-left:auto;font-size:10px;opacity:0.55;">hashes only · never commands or secrets</span>';
  h += '</div>';
  h += '<div id="machines-a-rows" style="max-height:280px;overflow:auto;"></div>';
  h += '</div>';
  panel.innerHTML = h;
  panel.classList.remove('hidden');
  const load = () => _loadActivity(opts.serverId);
  _el('machines-a-refresh')?.addEventListener('click', load);
  _el('machines-a-scope')?.addEventListener('change', load);
  await load();
}

async function _loadActivity(serverId) {
  const rows = _el('machines-a-rows');
  if (!rows) return;
  const all = !!_el('machines-a-scope')?.checked;
  rows.textContent = 'Loading…';
  try {
    const data = await listSshAudit({
      limit: 100,
      server_id: serverId || undefined,
      scope: all ? 'all' : undefined,
    });
    const wrap = _el('machines-a-scopewrap');
    if (wrap) wrap.classList.toggle('hidden', !(data && data.admin));
    const list = (data && data.rows) || [];
    rows.innerHTML = list.length
      ? list.map(sshAuditRowHtml).join('')
      : '<p class="memory-desc doclib-desc">No activity yet.</p>';
  } catch (err) {
    rows.innerHTML = `<p class="memory-desc doclib-desc">Could not load activity: ${esc(err.message)}</p>`;
  }
}

// ── Event wiring ────────────────────────────────────────────────────────────

function _wire() {
  const body = _body();
  if (!body) return;

  // Row clicks: select the machine first (capture, so it runs before the body's
  // own data-ssh-action delegation), then let sshServers.js do the action.
  const list = _el('ssh-servers-list');
  if (list && !list._machinesWired) {
    list._machinesWired = true;
    list.addEventListener('click', (e) => {
      const row = e.target.closest('[data-ssh-row]');
      if (row) _select(row.dataset.sshRow);
    }, true);
  }

  // Each tool window binds its own ✖ (nothing generic does it), and the
  // "toggle window" hotkey closes the area by clicking this button — a silent
  // one would leave the window unclosable from its own header.
  const closeBtn = _el('close-machines-modal');
  if (closeBtn && !closeBtn._machinesWired) {
    closeBtn._machinesWired = true;
    closeBtn.addEventListener('click', (e) => { e.preventDefault(); close(); });
  }

  _el('machines-add-btn')?.addEventListener('click', () => _openForm(''));
  body.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-machine-action]');
    if (!btn) return;
    e.preventDefault();
    const action = btn.dataset.machineAction;
    if (action === 'add') { _openForm(''); return; }
    if (action === 'transfer') { _openTransfer(btn.dataset.id); return; }
    if (action === 'activity') { _openActivity({ serverId: btn.dataset.id }); return; }
    if (action === 'close-panel') { _hidePanel('machines-transfer'); _hidePanel('machines-activity'); return; }
    if (action === 'disconnect') {
      closeSshTerminalById(btn.dataset.server, btn.dataset.session)
        .then(() => { uiModule.showToast('Terminal closed'); return _renderLive(); });
    }
  });
  _el('machines-activity-btn')?.addEventListener('click', () => _openActivity({}));
  _el('machines-disconnect-all')?.addEventListener('click', async () => {
    const n = await disconnectAllTerminals();
    uiModule.showToast(n ? `Disconnected ${n} terminal(s)` : 'Nothing to disconnect');
    await _renderLive();
  });

  _el('machines-f-save')?.addEventListener('click', _saveForm);
  _el('machines-f-cancel')?.addEventListener('click', _closeForm);
  _el('machines-f-close')?.addEventListener('click', _closeForm);
  _el('machines-f-keybtn')?.addEventListener('click', _showCommands);
  _el('machines-f-installkey')?.addEventListener('click', _installKey);
  _el('machines-f-copykey')?.addEventListener('click', () => _copy(_el('machines-f-key')?.value, 'Public key'));
  _el('machines-f-copyid')?.addEventListener('click', () => _copy(_formState.hints?.copyHint, 'ssh-copy-id command'));
  _el('machines-f-copyrun')?.addEventListener('click', () => _copy(_formState.hints?.runHint, 'ssh command'));
}

async function _mount() {
  if (_mounted) return;
  const body = _body();
  if (!body) return;
  _mounted = true;
  // The add/edit dialog is absolutely positioned over the body only, so the
  // window header (minimize/close) stays clickable while it is open.
  body.style.position = 'relative';
  body.innerHTML = _shellHtml();
  setSshActionHandlers({
    edit: (id) => _openForm(id),
    // The body owns test/connect/disconnect/delete, so it tells the shell when
    // its derived panes went stale — otherwise the info pane still says "not
    // pinned" after a successful Test and the live-session list ignores a brand
    // new terminal until the window is remounted.
    changed: (reason) => {
      if (reason === 'deleted') _selected = '';
      _render().catch(() => {});
    },
  });
  _wire();
  await initSshServers(body);
  await _render();
}

// ── Public API ──────────────────────────────────────────────────────────────

export async function open(opts = {}) {
  const modal = _modal();
  if (!modal) return;
  const intent = async () => {
    if (opts && opts.serverId) {
      _select(opts.serverId);
      await _render();
      if (!_serverById(opts.serverId)) {
        uiModule.showToast('Machine not found');
        _select('');
      }
    }
  };
  // Minimized? Restore in place — all DOM (and any live terminal) is preserved.
  if (Modals.isMinimized(MODAL_ID)) {
    Modals.restore(MODAL_ID);
    await _mount();
    await intent();
    return;
  }
  // Already visible? Just honour the intent — never toggle-close.
  if (!modal.classList.contains('hidden')) {
    await _mount();
    await intent();
    return;
  }
  _closeGen++;
  const content = modal.querySelector('.modal-content');
  if (content) {
    content.classList.remove('modal-closing', 'sheet-ready');
    content.style.transform = '';
    content.style.transition = '';
    content.style.animation = '';
    content.style.opacity = '';
  }
  modal.style.display = '';
  Modals.register(MODAL_ID, {
    railBtnId: 'rail-machines',
    sidebarBtnId: 'tool-machines-btn',
    closeFn: () => _doClose(),
    // Restoring must not rebuild the body: a live terminal lives in it (AC5).
    restoreFn: () => { _renderLive(); },
  });
  if (!_dragWired) {
    const header = modal.querySelector('.modal-header');
    if (content && header) {
      _dragWired = true;
      makeWindowDraggable(modal, { content, header, skipSelector: '.close-btn, .modal-close', enableDock: true });
    }
  }
  await _mount();
  modal.classList.remove('hidden');
  await intent();
}

function _doClose() {
  const modal = _modal();
  if (!modal) return;
  const content = modal.querySelector('.modal-content');
  const myGen = ++_closeGen;
  if (content && !content.classList.contains('modal-closing')) {
    content.classList.add('modal-closing');
    content.addEventListener('animationend', () => {
      if (myGen !== _closeGen) return;
      modal.classList.add('hidden');
      content.classList.remove('modal-closing');
    }, { once: true });
    setTimeout(() => {
      if (myGen !== _closeGen) return;
      if (!modal.classList.contains('hidden')) {
        modal.classList.add('hidden');
        content.classList.remove('modal-closing');
      }
    }, 250);
  } else {
    modal.classList.add('hidden');
  }
}

/** Full close — hides the window; live sessions keep running server-side. */
export function close() {
  if (Modals.isRegistered(MODAL_ID)) Modals.close(MODAL_ID);
  else _doClose();
}

export function isVisible() {
  const modal = _modal();
  if (!modal) return false;
  if (Modals.isMinimized(MODAL_ID)) return false;
  return !modal.classList.contains('hidden');
}

// Escape while the add/edit dialog is open should close just that dialog, not
// the window — otherwise a half-typed host (and a typed password) is lost.
//
// Bound on WINDOW in the capture phase, which is load-bearing: ui.js's global
// Escape arbiter is a *document*-capture listener whose first act is to close
// the hovered window, and the pointer is over this window whenever someone is
// typing into the form. A document-level handler (the cookbook Serve-card
// pattern) loses that race and the whole window closes instead.
if (typeof window !== 'undefined' && !window._machinesFormEscBound) {
  window._machinesFormEscBound = true;
  window.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const dialog = _el('machines-form');
    if (!dialog || dialog.style.display === 'none') return;
    // Only while the window is actually showing, or a closed area would swallow
    // the app shell's Escape on the way to whatever is in front of it.
    const modal = _el(MODAL_ID);
    if (!modal || modal.classList.contains('hidden')) return;
    e.stopImmediatePropagation();
    e.preventDefault();
    _closeForm();
  }, true);
}

// Default export, mirroring cookbook.js: `static/app.js` imports modal tools as
// `import cookbookModule from './js/cookbook.js'`, so a missing default export
// here is a link-time error that breaks the whole app shell.
const machinesModule = { open, close, isVisible };
export default machinesModule;
