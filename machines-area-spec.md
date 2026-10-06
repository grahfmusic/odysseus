# SSH / Server Functionality → Its Own "Machines" Area — Spec

> Source: user interview (6 rounds via `ask_user`) + codebase reconnaissance.
> Repo: `~/git-ai/odysseus`, branch `deploy-script` @ `ca9b5ebc`. Status: **spec only — no code changes made.**
> Scope short name: `machines-area`.
> Relationship to earlier docs: this spec **amends** `ssh-rsh-spec.md` §8/§17 and
> `ssh-implementation-plan.md` §3 on one point only — **placement** (see §10.3).
> Everything else in those files (backend, security model, gating, audit, TOFU) stays normative.

## 1. Request in the user's words

> "the ssh/server functionality isn't the settings area"

Interpreted and confirmed through the interview as:

1. The owner-scoped SSH/servers feature (**today called "My servers"**) must **not** be presented as
   configuration. Specifically it must never live in the **main Settings dialog** (gear icon /
   `settings-modal`) and should not read as a settings panel anywhere.
2. It becomes a **first-class top-level area of its own**, peer to Cookbook / Brain / Library /
   Calendar: its own sidebar **Tools** entry, its own **icon-rail** button, its own **modal window**
   with the standard minimize-to-dock-chip lifecycle.
3. The frontend is **restructured**, not just moved: a new area module owns the window shell while the
   existing `static/js/sshServers.js` stays as the data/row/terminal body layer.
4. The area is named **Machines**. Everything user-facing — sidebar, rail tooltip, window title, dock
   chip, `/open machines`, README, agent-tool copy — uses that name.
5. The shared Cookbook → Servers block (`cookbook_state.json`, GPU/model-infra hosts) is **untouched**;
   only the per-user `ssh_servers` list is lifted out of Cookbook and out of Cookbook → Settings.
6. The existing "My servers" card is **removed from the Cookbook modal** (no leftover card, no
   pointer card — Cookbook keeps only HuggingFace Token + shared Servers).

## 2. Interview answers (authoritative)

### Round 1 — which settings surface / where it goes
| Q | Answer |
|---|---|
| Which surface is wrong? | **Main Settings modal** — the gear-icon Settings dialog must not carry SSH server management. |
| Where should it live? | **New top-level tool** — own sidebar Tools entry + icon-rail button + own modal/panel. |
| Scope | **Placement + restructure** — reorganise the module into its own area; drop the Cookbook coupling. |
| Shared Cookbook Servers block | **Yes, untouched** — only the owner-scoped list moves. |

### Round 2 — presentation
| Q | Answer |
|---|---|
| Name | **"Remotes / Machines"** → resolved in Round 3 to **Machines**. |
| Container | **Own modal with dock chip** — Cookbook/Gallery lifecycle (opens as a window, minimizes to a dock chip, remembers position). |
| Terminal | **Inline in the new area** (reuse the existing Phase-2 SSE terminal wiring in `sshServers.js`). |
| Integration points | **All of them**: sidebar Tools entry, icon-rail button, slash command, lazy-load registry, dock label, chat keyword routing. |

### Round 3 — fate of the old placement and of the docs
| Q | Answer |
|---|---|
| Exact label | **Machines** (slash command: `/open machines`). |
| Cookbook card | **Remove it completely** — Cookbook stops importing/initialising the SSH panel. |
| Add/edit UX | **Proper form dialog** — replaces the cramped inline add row. |
| Docs sweep | **Everything incl. specs** — README, agent-tool return strings, `ssh-rsh-spec.md`, `ssh-implementation-plan.md`, and per §10.4 `MODULE_SUMMARY.md`. |

### Round 4 — code shape, lifecycle, verification
| Q | Answer |
|---|---|
| Module split | **New shell + keep body**: new `static/js/machines.js` owns the modal shell; `sshServers.js` stays the data/row/terminal layer; `machines.js` imports it. |
| Terminal on minimize/close | **Always keeps running** — the session survives dock/minimize *and* closing the modal, until the 10-minute idle kill or an explicit Disconnect. |
| Sidebar/rail position | **Delegated to me** — decided in §11.1 (right after Cookbook). |
| Verification | **JS tests + browser smoke** — rewrite the source-pinning tests *and* drive the real UI in a browser with a screenshot. |

### Round 5 — v1 capability set
| Q | Answer |
|---|---|
| Extra capabilities | **All four**: file transfer, audit-log viewer, connection detail pane, copy run/`ssh-copy-id` command. |
| Deep links | **Deep link to a machine** — open the area focused on a specific server id (from chat/tool output or notices). |
| First-run | **Guided empty state** — explain what a machine is, surface the user's public key, prominent "Add your first machine". |
| Open behaviour when already open/minimized | **Delegated to me** — decided in §11.2. |
| Migration of in-flight Cookbook state | **Delegated to me** — decided in §11.3. |

### Round 6 — activity log, layout, transfer
| Q | Answer |
|---|---|
| Audit visibility | **Own rows + admin `scope=all`** — users see their own `ssh_audit_log`; admins get a cross-user view for support/security review. |
| Layout | **Master–detail split** — server list left; selected machine's detail, terminal, transfer and activity right. |
| Audit API | **Both** — a global `GET /api/ssh/audit` *and* the per-server subset. |
| Transfer UX | **Both paths + picker** — typed local/remote path fields with a browse affordance filling the local field from the workspace. |

## 3. Current state (reconnaissance)

All paths relative to repo root. Line anchors are as of `ca9b5ebc`.

### 3.1 Where the SSH servers UI lives today
- **Rendered inside the Cookbook modal's Settings tab.** `static/js/cookbook.js`:
  - `:13` `import { initSshServers } from './sshServers.js';`
  - `:3240` the tab block opens: `<div class="cookbook-group hidden cookbook-settings-stack" data-backend-group="Settings">`
  - `:3271-3278` HuggingFace Token card, `:3279-3296` shared **Servers** card (`#cookbook-servers-list`, `#cookbook-server-add`)
  - `:3280-3303` the **"My servers"** card: `#ssh-servers-card`, `#ssh-servers-status`, `#ssh-servers-list`,
    and the inline add row (`#ssh-add-label`, `#ssh-add-host`, `#ssh-add-port`, `#ssh-add-user`,
    `#ssh-add-auth`, `#ssh-add-pass`, `#ssh-add-sudo`, `#ssh-server-add`)
  - `:3306` `initSshServers(body);` — called from the Cookbook modal render path
- **`static/js/sshServers.js` (513 lines)** is the whole feature body today: `API = '/api/ssh/servers'`;
  pure helpers `sshServerPayload`, `sshTestMessage`, `sshErrorText`, `parseSshSse`, `sshServerRowHtml`,
  `sshServersListHtml`; `initSshServers(body)` at `:470` scoping to `#ssh-servers-list` (`:480`);
  terminal + SSE wiring later in the file.
- **Docs/agent copy that names the old placement:** `README.md:55` ("work on them from Cookbook → Settings → My servers"),
  `src/tool_implementations.py:174` (`"No SSH servers saved. Add one in Cookbook → My servers."`).

### 3.2 The app-shell integration points a first-class tool must touch
| Concern | File / anchor | Today |
|---|---|---|
| Sidebar Tools list | `static/index.html:859-960` (`<div class="section" id="tools-section">`, `#tool-*-btn` items: memory, calendar, compare, cookbook, research, gallery, library, notes, tasks, theme) | Cookbook entry at `:888` |
| Icon rail | `static/index.html:724-750` (`#rail-*-btn`: search, new, delete, chats, documents, calendar, compare, cookbook, research, email, gallery, archive, memory, notes, tasks, theme, settings) | Cookbook at `:737` |
| Modal markup | `static/index.html:1389-1397` (`#cookbook-modal` → `.modal-content` → `.modal-header` h4 + `.close-btn` → `.modal-body`) | pattern to copy |
| Dock chip label | `static/js/modalManager.js:~130` `_LABELS` map (modal id → `{label, icon}`) | no entry for SSH |
| Auto-wire rail/sidebar ↔ modal | `static/js/modalManager.js:~1402` `_AUTO_WIRE` (modal id → `{rail, sidebar}`) | no entry for SSH |
| Explicit register/restore | `static/js/cookbook.js:3399` `Modals.register('cookbook-modal', {railBtnId, sidebarBtnId, closeFn, restoreFn})` | pattern to copy |
| "Toggle Window" hotkey | `static/js/keyboard-shortcuts.js:~100` `_WINDOW_TRIGGERS` | lists all tool windows |
| Open-tool hotkeys | **six** places: `static/js/keyboard-shortcuts.js:9-17` (`_defaultKeybinds`), `:265` (`_toolBtns`), and `static/js/settings.js:1651` (`SHORTCUT_DEFAULTS`), `:1685` (`SHORTCUT_ICONS`), `:1710` (`SHORTCUT_LABELS`), `:1724` (`SHORTCUT_CATEGORIES` — the `'Open Tools'` key list that drives the panel) | `open_*` per tool |
| `/open` command | `static/js/slashCommands.js:1348` fallback list, `:1359-1361` target switch (`clickFirst('tool-cookbook-btn', 'rail-cookbook')`), `:1393` `_cmdToolPanel`, `:5995-6051` registrations; `:2868` is the Cookbook tour opener | `cookbook` |
| App-shell click wiring | `static/app.js:47` (`import cookbookModule from './js/cookbook.js'`), `:3739` `_railToolMap` (rail click → sidebar click), `:165` `initRailHoverLabels()` | eager import for the modal tool |
| Per-tool visibility (+ its test) | `static/js/ui_visibility.js:13-40` `UI_VIS_MAP`; `tests/test_ui_visibility_js.py:57-67` `EXPECTED_RAIL_PAIRS` + hardcoded selector lists at `:44-50` | every `tool-*` has a paired `#rail-*` |
| Agent loopback refusal | `src/tools/system.py:588-610` `_ssh_app_api_blocked` (GET allowed except `/terminal`; POST only `/test`); `routes/ssh_routes.py:96-100` `_owner()` **rejects the `internal-tool`/`api` loopback identity with 401** | no `/api/ssh/*` route is reachable via `app_api` at all | 
| **Settings → Appearance visibility row** | `static/index.html:1820-1913` (`data-settings-panel="appearance"` → the Sidebar card's `vis-toggles` list; last row `sidebar-settings-btn` at `:1912`; each row is `<input type="checkbox" data-ui-key="…">`, e.g. `tool-cookbook` at `:1872`); readers/writers `static/js/settings.js:1562`, `:1637`; per-card reset `:1616-1620`; persistence `app.js:2726-2745` | every `UI_VIS_MAP` key has a hard-coded row here |
| **Sidebar button click wiring** | `static/app.js` per-tool blocks (`:1008` research, `:1015-1027` cookbook: `if (!Modals.toggle('cookbook-modal')) cookbookModule.open()`); route map `_routeOpen` at `:1184-1200` (`'/cookbook': () => document.getElementById('tool-cookbook-btn')?.click()`) | one block per tool + a route entry |
| **Agent UI control (`ui_control open_panel`)** | backend list: `src/tool_schemas.py:472` + `:478` (enum/description), `src/tool_index.py:110`, runtime guidance `src/agent_loop.py:381` (incl. its alias list); frontend handler `static/js/chatStream.js:177-207` | `open_panel cookbook` works; `machines` is not a known name |
| CSS badge hooks | `static/style.css:860-869` (`.rail-minimized::after` nudge list naming each tool id), `:19766-19772` (`#tool-cookbook-btn` / `#rail-cookbook { position: relative }` for its status dot) | per-id rules; a new button gets the default dot position only |
| Sidebar section order | `static/js/storage.js:24` `SECTION_ORDER: 'sidebar-section-order'`; saved/restored in `static/js/section-management.js` (`onMouseUp`, restore loop) | **sections only, by id** — inserting a `list-item` inside `#tools-section` cannot disturb it |
| Chat panel-link routing | `static/js/chatStream.js:177-207` (`panel === 'documents' \| 'gallery' \| 'email' \| 'sessions' \| 'cookbook' \| 'notes' \| …`) | no `machines` |
| Slash palette / keyword hues | `static/js/tasks.js:2606-2612` (hue regexes) and `:2633-2640` (palette labels) | `cookbook` entry |
| Lazy panel registry | `static/js/panels.js` `LOADERS` (currently only `editor`) + `loadPanel`/`panelNames` | — |
| Service-worker precache | `static/sw.js:40+` `PRECACHE`, `:103+` `PANEL_PRECACHE` (`cookbook.js` is in `PRECACHE:67`) | add `machines.js` |
| Modal a11y | `static/js/a11y.js:~68` generic `MODAL_KINDS` over `.modal-content` (+ runtime mutation observer) | automatic — no per-modal registration |
| Modal list doc comment | `static/js/windowResize.js:3` | needs `Machines` added |
| Entity deep links | `static/js/chatRenderer.js:1361-1425` (`kind === 'session' \| 'document' \| 'note' \| 'image' \| 'email' \| 'event' \| 'task' \| 'skill' \| 'research'` chain), `static/js/init.js:20` `isEntityHash` regex (`#document-`, `#note-`, `#image-`, `#email-`, `#event-`, `#task-`, `#skill-`, `#research-`) | no `machine-` kind |

### 3.3 Backend: already complete except two read paths (audit + live sessions)
`routes/ssh_routes.py` (registered in `app.py:803-805`) already exposes, owner-scoped:
`GET/POST /api/ssh/servers`, `PATCH/DELETE /api/ssh/servers/{id}`, `GET …/pubkey`,
`POST …/test`, `POST …/exec`, `POST …/upload` + `POST …/transfer` (`TransferRequest{direction, local_path, remote_path}`,
local side confined by `src.tool_execution._resolve_tool_path`), the terminal set
(`POST …/terminal`, `GET …/terminal/{sid}/stream` SSE, `POST …/input`, `POST …/resize`, `DELETE …/terminal/{sid}`),
`POST /api/ssh/keygen`; plus a per-user 30/min rate limit (`_RATE_LIMIT`, 429 — asserted in `tests/test_ssh_api.py:96-98`).
Writers live in `src/ssh_remote.py` (`audit(owner, server_id, event, command, exit_code)` at `:336`, hashing the command itself) against `SshServer` / `SshAuditLog` in `core/database.py:649+`.
`SshAuditLog` (`core/database.py:675-693`, `TimestampMixin` → `created_at`/`updated_at`; `server_id` is a plain indexed String with **no FK** so rows survive deletion) records `event` in `test | exec | terminal_open | upload | download | **key_rotated | server_deleted**`, with `command_hash` (SHA-256 hex) and `exit_code`.
**There is no route that reads `ssh_audit_log`** — the new Activity view needs one (§8).
Terminal plumbing has three layers worth knowing:
- `src/ssh_remote.py:767 open_terminal_for(owner, ref, cols, rows)` — facade: resolves the row, applies the admin host-pattern check (`_require_allowed`), **refuses if `host_key_fingerprint` is unset** ("run Test first"), resolves auth with `force_paramiko=True`, then delegates; `close_terminal_for` at `:794`.
- `src/ssh_client.py:47-48` — `MAX_TERMINAL_SESSIONS_PER_USER = 3`, `TERMINAL_IDLE_KILL_S = 600`; `open_terminal` (`:409-432`) checks the cap **per owner, independent of server**, and `get_terminal`/`close_terminal`/`close_terminal_by_id`/`session_count` (`:449-478`) are the whole API. Sessions live in a module-global dict keyed by a random id; nothing persists them.
- **The idle kill is lazy.** `_reap_idle()` (`:458`) has exactly one call site — inside `open_terminal` (`:416`), *before* the cap check. There is no background sweeper (the app has long-lived loops it could join: `app.py:1139`, `:1233`, `:1251`, `:1281`). So a session whose client vanished *without* a clean disconnect (browser crash, killed tab process, laptop sleep, network drop with no FIN) survives past 600 s until the next Connect (try to open a 4th and the reaper runs first, then the cap applies). A clean reload is **not** this case — the stream's `finally` closes the PTY, see the bullet after next.
- **A clean disconnect frees the PTY.** `routes/ssh_routes.py:258-273`: the stream generator polls `await request.is_disconnected()` every 250 ms and its `finally:` calls `ssh_client.close_terminal_by_id(session_id)` — with the comment "A dropped browser must free the remote PTY". So reload / tab close / navigation tears the session down server-side; there is no reload leak.
- **No route lists live sessions.** `session_count()` is currently unused, so the UI cannot see, adopt, or close a session it no longer holds a handle to — relevant when a client vanished *without* a clean disconnect, and when a second tab opened its own sessions.

### 3.4 Tests that pin the current placement and the behaviour this spec changes
- `tests/test_ssh_servers_js.py` — `TestCookbookWiring`: asserts `cookbook.js` contains
  `import { initSshServers } from './sshServers.js';`, `initSshServers(body);`, the card's element ids,
  and that `// ── Servers block` precedes `// ── My servers`. **This class is replaced (§13).**
- `tests/test_ssh_servers_js.py` — `TestTerminalContract::test_live_session_is_closed_when_the_panel_goes_away`
  asserts the **opposite** of the new requirement: `src.count('_closeTerminal(d);') >= 2` and
  `'t.controller.abort();' in src`, i.e. "hiding the detail panel must not orphan the remote PTY".
  AC5 requires minimize/close to keep the session, so this assertion must be **inverted** (not deleted) — see §13.
- `tests/test_ui_visibility_js.py` — `EXPECTED_RAIL_PAIRS` (`:57-67`) and the selector constants
  (`:44-50`) enumerate the tools by hand, so a new `tool-machines` is silently uncovered unless added.
- `tests/test_panel_loader_js.py` — `:132` asserts the editor is registered in `panels.js`; `:187`
  `test_every_lazy_editor_module_is_precached_for_offline_use` walks a module's import graph and asserts
  every file is in `PANEL_PRECACHE`. That graph-walk is the precedent for asserting the Machines
  modules' offline coverage (it is editor-scoped today, so a new area needs its own case).
- `tests/test_external_context_tool_gate.py:281` references `list_ssh_servers` (agent-tool gate, unrelated to placement — leave alone).
- `tests/bombadil-spec.ts` — the UI-exploration harness clicks every `.list-item` / `.icon-rail-btn`,
  so the new entries only widen its action space; no inventory to update.

## 4. Goals

- **G1 — Machines is a first-class area.** Sidebar + rail entry, own modal, own dock chip, own hotkey
  binding slot, `/open machines`, entity deep link `#machine-<id>`, chat panel-link routing, slash-palette
  entry, and an offline-safe module (either the Cookbook pattern — eager import + `PRECACHE` — or the
  panel-registry pattern; §9 picks one).
- **G2 — No settings surface.** No SSH server management in the main `settings-modal` (assert with a test),
  and nothing named "settings" in the area's UX copy.
- **G3 — Cookbook decoupled.** `cookbook.js` no longer imports or renders the SSH panel; the Cookbook
  Settings tab keeps HuggingFace Token + the shared Servers block only.
- **G4 — Structure: shell vs body.** `static/js/machines.js` = window shell (markup, open/close,
  register/restore, master–detail layout, form dialog, transfer panel, activity view, deep link);
  `static/js/sshServers.js` = body/data layer (API calls, pure helpers, row rendering, terminal + SSE)
  imported by the shell. Pure helpers and their node tests survive.
- **G5 — Feature parity plus the four agreed additions.** Everything "My servers" does today (list, add,
  edit, delete, Test/TOFU, Run, Connect terminal, Key/public key, status) works in Machines, plus
  file transfer, activity log, connection detail pane, and copyable `ssh-copy-id` / one-shot commands.
- **G6 — Terminal lifecycle per the interview.** Minimizing *and* closing the Machines window leaves a
  live remote session running (subject to the existing server-side 3-per-user cap and 10-minute idle kill);
  only Disconnect or the idle reaper ends it.
- **G7 — Name consistency.** "Machines" everywhere user-facing; internal names (`ssh_servers` table,
  `/api/ssh/*`, agent tools `ssh_exec` / `list_ssh_servers`, threat-model wording) stay as they are.

## 5. Non-goals

- **N1 — No backend rework.** Existing routes, tables, gating, TOFU, audit writer and rate limits are
  unchanged. The only backend additions are two **read** paths: the audit reads (§8) and, per the §8.2
  decision, the live-session inventory `GET /api/ssh/terminals`. No session lifetime, cap or reaper
  behaviour changes.
- **N2 — No settings-modal integration of any kind** (no Settings panel, no Settings row, no
  "Configuration → SSH" entry). `ssh_allowed_host_patterns` stays a backend-only setting, exactly as
  `tool_path_extra_roots` does today.
- **N3 — The shared Cookbook → Servers block does not move** and is not merged with Machines.
- **N4 — No multi-user sharing, no ad-hoc hosts, no `rsh` protocol** (unchanged from `ssh-rsh-spec.md` §5).
- **N5 — No rename of the data layer or agent tools.** `ssh_exec`/`list_ssh_servers` keep their names and
  schemas; only their human-readable copy stops pointing at Cookbook.
- **N6 — No new server-side session store.** Terminal sessions stay in-memory, capped, idle-killed
  (unchanged); closing the window must not tear a session down client-side either.

## 6. Target architecture

### 6.1 Modal markup (`static/index.html`)
Add a sibling of `#cookbook-modal`, after it (mirror `:1389-1397`):

```
<!-- Machines Modal -->
<div id="machines-modal" class="modal hidden">
  <div class="modal-content" role="dialog" aria-label="Machines"
       style="width: min(1000px, 94vw); background: var(--bg);">
    <div class="modal-header">
      <h4>…icon…Machines</h4>
      <button class="close-btn" id="close-machines-modal" aria-label="Close machines">✖</button>
    </div>
    <div class="modal-body machines-body"></div>
  </div>
</div>
```

- Element ids use the `machines-*` / `tool-machines-btn` / `rail-machines` prefixes; the body keeps the
  existing `ssh-*` ids it needs (`#ssh-servers-list` etc. may be renamed to `machines-*` as part of the
  restructure — if renamed, `sshServers.js`'s `_root()`/`scope.querySelector` selectors and
  `tests/test_ssh_servers_js.py` move together; see §13).
- The nested `.modal-content` is enough for the generic a11y enhancer (`a11y.js:68-105`) — no a11y registration.

### 6.2 Module split
- **`static/js/machines.js` (new)** — the area shell:
  - imports `initSshServers` (and the pure helpers it needs) from `./sshServers.js`;
  - builds the modal body DOM (master list + detail pane + form dialog + transfer panel + activity tab);
  - `export async function open(opts = {})` supporting `{ serverId }` for deep links, mirroring
    `cookbook.js` (`open()` at `:3353`, minimized-restore at `:3374-3378`, already-visible no-op at
    `:3379-3382`, `_doClose()` at `:3483`, `close()` at `:3504`) — generation guard, clear leftover
    inline modal-closing styles, `Modals.register(...)`;
  - `export function close()` — hide + unregister, **without** touching live terminal sessions (§7.3);
  - wires its own rail/sidebar/hotkey/`/open` entry points.
- **`static/js/sshServers.js`** — unchanged responsibility, updated wiring contract:
  - keeps `API = '/api/ssh/servers'` and all pure/exported helpers and their node tests;
  - `initSshServers(scope)` keeps its signature (a container element), so the new shell passes its own body;
  - row markup gains the new actions (Transfer, Activity, detail) — the shell owns the layout around it.
- **`static/js/cookbook.js`** — remove the SSH card markup (`:3280-3303`), the `initSshServers(body)` call
  (`:3306`) and the import (`:13`).

### 6.3 Layout (master–detail, per Round 6)
```
┌ Machines ────────────────────────────────────────────── ✖ ┐
│ [ + Add machine ]                        [ Activity ]     │
│ ┌─ list ─────────┐ ┌─ detail (selected) ────────────────┐ │
│ │ home-lab   ✓   │ │ target · auth · pinned fingerprint │ │
│ │ vps-eu         │ │ last test + latency                │ │
│ │ pi-4          │ │ [Test] [Connect] [Run] [Key]        │ │
│ └────────────────┘ │ ── terminal (inline, when open) ── │ │
│                    │ ── transfer: dir · local · remote ─│ │
│                    │ ── activity for this machine ────── │ │
│                    └────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```
- The **list** is the existing row renderer (Test/Connect/Run/Key/Edit/Delete + host-key pin status).
- The **detail** pane shows target `user@host:port`, auth type, pinned fingerprint (or "not pinned — run Test"),
  last test result/time — i.e. the connection detail pane agreed in Round 5.
- **Activity** is the area-level view (own rows; admins may switch to `scope=all`), and the per-machine
  subset is shown in the detail pane.
- **Transfer** panel: direction toggle (upload/download), local path field + **Browse** affordance filling
  it from the workspace, remote path field, run button; fields mirror `TransferRequest` exactly.
- **Form dialog** (Add/Edit): Label, Host (or `user@host`), Port (default 22), Username, Auth type
  (key/password/both), Password (placeholder "unchanged" on edit), Sudo password (optional),
  and a key panel: Generate key / Show public key / **Install key on machine** / Copy /
  `ssh-copy-id -i <path> <user>@<host>` / one-shot `ssh <target> '<cmd>'` line to copy. Secrets are
  blank-omitted on PATCH (existing `sshServerPayload` behaviour — keep it).
  *Install added later (not in the original spec): the panel only ever showed the `ssh-copy-id` line,
  which meant a machine that could only authenticate by password could not be set up for key login at
  all — see `POST /api/ssh/servers/{id}/install-key`.*
- **Guided empty state**: what a machine is, the user's public key surfaced with a copy button, and a
  prominent "Add your first machine".

### 6.4 Open/close/dock lifecycle
- Copy the Cookbook pattern: `Modals.register('machines-modal', { railBtnId: 'rail-machines',
  sidebarBtnId: 'tool-machines-btn', closeFn, restoreFn })` (`cookbook.js:3399-3404`; `_doClose`
  `:3483` only adds `.hidden` + a closing animation — the DOM and any live fetch survive it), plus entries in
  `modalManager.js` `_LABELS` (dock chip: label `Machines`, machine/server glyph) and `_AUTO_WIRE`
  (`{ rail: 'rail-machines', sidebar: 'tool-machines-btn' }`).
- Wire the two triggers: `static/app.js:3739` `_railToolMap` (`'rail-machines': 'tool-machines-btn'`) and the sidebar button's own click handler, which opens the area the same way `tool-cookbook-btn` does.
- Add `machines-modal` to `keyboard-shortcuts.js` `_WINDOW_TRIGGERS` so "Toggle Window" can close/reopen it.
- **Trigger semantics are already settled by `modalManager.js:1297-1304`:** `Modals.toggle(id)` restores a minimized modal and otherwise returns `false` — it never minimizes a visible one. Every tool button relies on that (`app.js:1015-1027`): `if (!Modals.toggle(id)) module.open()`, and `open()`'s visible branch is the no-op. Copy this exactly; do not invent a toggle-close.

## 7. Feature scope (v1)

### 7.1 List / CRUD / auth / test (parity with today)
Unchanged behaviour, new home: list, add, edit, delete, `Test` (TOFU capture + fingerprint pin + latency),
`Run` (one-shot, timeout, `sudo -S` stdin path), `Key` (generate/reuse per-user key, show public key +
`ssh-copy-id` hint), host-key pin status per row, owner scoping enforced server-side.

### 7.2 Additions
| Feature | Behaviour | Backing |
|---|---|---|
| Connection detail pane | target, auth type, pinned fingerprint, last test result/time | existing `GET /api/ssh/servers` payload |
| Copy commands | `ssh-copy-id -i <pub> user@host` and a one-shot `ssh user@host 'cmd'` line, copyable | existing `GET …/pubkey` (`ssh_copy_hint`, now with the row's real target and port) |
| Install key | append the user's public key to the remote `~/.ssh/authorized_keys` over SSH (idempotent, 0600/0700); signs in with the saved password, else the key | **new** `POST /api/ssh/servers/{id}/install-key` → `ssh_remote.install_public_key` |
| File transfer | direction + local/remote path + workspace picker; server confines the local side | existing `POST …/upload` / `…/transfer` |
| Activity log | own rows (event, machine, time, exit code, command hash prefix, never secrets); admin `scope=all` | **new** read route + existing `SshAuditLog` |

### 7.3 Terminal lifecycle (decided) — the one real behaviour change
Exact mechanics today (`static/js/sshServers.js`):
- `_onConnect` (`:289-330`) POSTs `/terminal`, renders `_terminalHtml` into the row's detail div, and
  keeps `{ sid, serverId, controller }` on `d._sshTerminal`; the SSE reader runs off
  `fetch(… + '/stream', { signal: controller.signal })`.
- `_showDetail` (`:153-159`) and `_hideDetail` (`:161-167`) — and therefore switching rows or
  collapsing the detail — both call `_closeTerminal(d)` (`:174-183`), whose docstring says
  "a live PTY must not keep running behind a new panel". It aborts the controller **and** DELETEs the
  session, so the server's generator `finally` (`routes/ssh_routes.py:265-273`) closes the remote PTY.
- The server side is capped and self-healing: 3 sessions/user, 600 s idle kill
  (`src/ssh_client.py:47-48`, `_reap_idle:458`).

Required behaviour (Round 4):
- **Minimizing and closing the Machines window must not end the session.** The shell must therefore
  (a) never destroy/blank the terminal node while the window is hidden — a minimized modal keeps its
  DOM, so simply *not* calling `_closeTerminal` from the hide path is enough for minimize; and (b) own
  teardown explicitly: `_showDetail`/`_hideDetail` must stop tearing the session down on panel switch,
  and the only in-UI teardown becomes a **Disconnect** control (plus the idle reaper / session cap).
- Where the *old* rule was load-bearing (switching machines while a PTY is live), replace it with an
  explicit choice: keep the per-machine session and show the live indicator, or prompt before dropping it.
  Silent teardown is what AC5 forbids.
- The dock chip is the visible affordance that a session is still live; add a small live indicator on
  the chip/list entry while a session exists (presentational only, needs a `position: relative` rule on
  the new button the way `#tool-cookbook-btn`/`#rail-cookbook` have one — `static/style.css:19766-19772`).
- **Multi-session policy (researched, resolved).** Nothing server-side forces one session at a time:
  `MAX_TERMINAL_SESSIONS_PER_USER = 3` is counted per *owner*, not per server, and `open_terminal` will
  happily open a second PTY on the same machine. So the UI choice is purely presentational. Prescribe:
  one terminal per machine, several machines in parallel up to the server's cap of 3, a live indicator
  per machine, and a 4th Connect surfaced verbatim as the server's `too many open terminals (max 3)`
  (400) with a Disconnect hint — never swallowed or retried.
- **Reload/disconnect behaviour (corrected against the server code).** A *clean* client loss does **not**
  orphan a session. `routes/ssh_routes.py:258-273`: the SSE generator polls `await request.is_disconnected()`
  each 250 ms and its `finally:` calls `ssh_client.close_terminal_by_id(session_id)` ("A dropped browser must
  free the remote PTY"), so reload, tab close and navigation all tear the remote PTY down server-side. There
  is nothing to repair here and nothing for §11.3 to migrate; an earlier draft of this spec claimed the
  session survived a reload — that was wrong.
- **The surviving gap is the *unclean* disappearance.** If the client never reports a disconnect (browser
  crash, killed tab process, laptop sleep, network drop), the generator keeps polling a socket nobody reads,
  the session holds one of the owner's 3 slots, and no UI surface can see it. The reaper is lazy
  (`src/ssh_client.py:416`), so the slot is only reclaimed if the user happens to Connect again — which is
  exactly when they instead get `too many open terminals (max 3)` with no way to diagnose or clear it. Two
  browser tabs are two such clients, each blind to the other's sessions.
- **Resolved: §8.2's `GET /api/ssh/terminals` ships in v1**, turning that invisible state into a list plus a
  "disconnect all" affordance. It is read-only and changes no session lifetime, cap, or reaper behaviour.
- **`tests/test_ssh_servers_js.py::TestTerminalContract::test_live_session_is_closed_when_the_panel_goes_away`
  pins the old rule** (`_closeTerminal(d);` count ≥ 2 + `controller.abort()`) and must be inverted, not
  deleted (§13).

### 7.4 Deep link
- Entity-hash form **`#machine-<server_id>`**, following the `#note-<id>` / `#document-<id>` precedent:
  add a `machine` branch to the entity chain in `static/js/chatRenderer.js:1361-1425` (lazy-import
  `./machines.js`, call `open({ serverId })`, then strip the hash like the note branch does) and add
  `machine` to the `isEntityHash` regex in `static/js/init.js:20` so the composer-restore logic treats
  it as an entity target rather than a session id (`hasSessionTarget` at `:22`).
- Guard: unknown/deleted id opens the area with the list and a non-blocking "machine not found" notice.

## 8. Backend addition — activity read path

New owner-scoped read endpoints in `routes/ssh_routes.py` (both listed in §2 Round 6):

| Method | Path | Behaviour |
|---|---|---|
| `GET` | `/api/ssh/audit` | Own `ssh_audit_log` rows, newest first. Query: `limit` (default 50, cap 200), `event`, `server_id`, and `scope=all` (**admin only** — non-admin gets 403). |
| `GET` | `/api/ssh/servers/{server_id}/audit` | The same payload filtered to one owned server (404 for another owner's id, matching every other route). |

- Serializer returns: `id`, `server_id`, `server_label` (looked up, best-effort), `event`
  (**all** values the writer stores: `test | exec | terminal_open | upload | download |
  key_rotated | server_deleted` — see `core/database.py:687`), `created_at`, `exit_code`,
  `command_hash` (**never** the command text — `src/ssh_remote.py:336` hashes it on write).
- Implement the read side next to the writer in `src/ssh_remote.py` (e.g. `list_audit(owner, ...)`)
  so the route stays a thin owner-checked wrapper, matching the module's existing shape.
- No secrets, no key material, no remote output in the payload.
- Reads are not connection-touching: **do not** put them behind `_check_rate_limit` (which is for
  test/exec/terminal/transfer).
- Retention/pruning stays out of scope (follow-up in `ssh-rsh-spec.md` §17); the UI shows a
  "retained ~90 days" note.
- **Loopback status (corrected).** `_ssh_app_api_blocked` (`src/tools/system.py:588-610`) allows GETs
  other than `/terminal`, but that is moot: `_owner()` (`routes/ssh_routes.py:96-100`) raises 401 for the
  `internal-tool`/`api` loopback identity, so **no** `/api/ssh/*` route is reachable through `app_api`.
  The new reads inherit that — no blocklist change is needed, and `scope=all` cannot be reached by the
  agent. The stale comment above `_ssh_app_api_blocked` ("Reachable via app_api: GET list/detail/pubkey
  + POST test") should be corrected to say the routes refuse the loopback identity (§10).

### 8.2 Companion route — live terminals (**decision: included in v1**)

**Recommendation, recorded: `GET /api/ssh/terminals` ships in v1.** The rationale was originally written
around page reloads; that premise was wrong (§7.3), so the decision rests on the grounds that survive:

- **The reload case does not need it.** A reload is a clean disconnect, and `routes/ssh_routes.py:265-273`
  already closes the PTY in the stream's `finally`. Nothing is left to adopt or clean up afterwards.
- **What does need it:** sessions whose client vanished *without* a disconnect (crash, killed tab, sleep,
  network drop) and sessions opened by *another* tab or window. Each holds one of the owner's
  `MAX_TERMINAL_SESSIONS_PER_USER = 3` slots, is invisible to every other client, and is reclaimed only if
  the next `open_terminal` happens to trigger `_reap_idle` — so the failure the user actually hits is
  `too many open terminals (max 3)` with no way to see or clear the holders. That is the v1 justification.
- **Cost is small and correctness is trivial here:** uvicorn runs single-process (`Dockerfile:113`,
  `deploy.sh:489`/`:507`, `deploy.sh:605` `ExecStart` — no `--workers` anywhere in the repo), so the
  in-memory `_sessions` dict is process-global and one read sees every live session for that owner.

| Method | Path | Behaviour |
|---|---|---|
| `GET` | `/api/ssh/terminals` | The caller's live sessions: `[{session_id, server_id, server_label, port}]`, read from a new `list_terminals(owner)` helper in `src/ssh_client.py` (mirroring the currently-unused `session_count`). Read-only; changes no session lifetime, cap or reaper; no rate-limit; loopback-unreachable like every other `/api/ssh/*` route. |

What the UI does with it: (a) show true cap usage ("2 of 3 terminals open") and which machines hold the
slots, (b) offer **Disconnect** / **Disconnect all** so a stale slot is cleared without restarting the app
or hunting for the owning tab, and (c) re-attach where the session's `server_id` matches a machine, instead
of stranding a live PTY behind an invisible handle.

Scope discipline: this is the **only** backend addition recommended beyond §8's audit reads. It is
owner-scoped and read-only. If the implementing PR defers it, that deferral must be stated in the PR body
together with the `too many open terminals` UX consequence above — AC13 is then dropped explicitly, not
silently skipped.

## 9. IA integration checklist (all confirmed in Round 2)

- [ ] `static/index.html` — sidebar Tools `<div class="list-item" id="tool-machines-btn">` (label "Machines", rail-consistent icon) **and** icon rail `<button class="icon-rail-btn" id="rail-machines" title="Machines">`.
- [ ] `static/index.html` — `#machines-modal` markup (§6.1).
- [ ] `static/js/modalManager.js` — `_LABELS['machines-modal']` (dock chip) and `_AUTO_WIRE['machines-modal'] = { rail: 'rail-machines', sidebar: 'tool-machines-btn' }`.
- [ ] Hotkeys — **six** edits, all needed or the binding half-exists: `keyboard-shortcuts.js` `_defaultKeybinds` (`:9-17`, add `open_machines: ''`), `_WINDOW_TRIGGERS` (`:98`, add `'machines-modal': 'tool-machines-btn'`), `_toolBtns` (`:265`, add `open_machines: 'tool-machines-btn'`); and `settings.js` `SHORTCUT_DEFAULTS` (`:1651`), `SHORTCUT_ICONS` (`:1685`), `SHORTCUT_LABELS` (`:1710`, `'Open Machines'`), `SHORTCUT_CATEGORIES` (`:1724`, append to the `'Open Tools'` key list or the panel never renders the row).
- [ ] `static/js/slashCommands.js` — `/open machines` branch in the `:1359` target switch (or `_cmdToolPanel`), a `:5995+` registration entry, and the `/open` fallback hint text at `:1348`.
- [ ] `static/js/chatStream.js` — `panel === 'machines'` branch that opens the area (used by chat panel links).
- [ ] `static/js/tasks.js` — slash-palette label (`:2633+`) and a keyword hue (`:2606+`) for machines/ssh/remote hosts.
- [ ] Module loading — follow the **Cookbook precedent**: `static/app.js:47` already imports the modal tool eagerly (`import cookbookModule from './js/cookbook.js'`) and `cookbook.js` sits in `sw.js` `PRECACHE:67`. So: import `machines.js` from `static/app.js` and add **both** `/static/js/machines.js` **and** `/static/js/sshServers.js` to `PRECACHE`.
  - Note the pre-existing gap this closes: `sshServers.js` is *not* in either sw list today even though `cookbook.js` imports it, so the old SSH panel could fail offline.
  - If instead the area is made lazy, add `LOADERS.machines = () => import('./machines.js')` in `static/js/panels.js` **and** list the files in `PANEL_PRECACHE`, **and** every trigger must `await loadPanel('machines')` before calling `open()` (pattern: `static/js/chat.js:6613`). Do not mix the two (`PRECACHE` entries must match the exact requested URL — `sw.js:32-39`).
- [ ] `static/js/init.js` + `static/js/chatRenderer.js` — `machine` entity hash (§7.4).
- [ ] `static/js/windowResize.js:3` doc comment — add Machines to the modal list.
- [ ] `static/js/a11y.js` — nothing to do (generic `.modal-content` handling).
- [ ] `static/app.js:3739` `_railToolMap` — add `'rail-machines': 'tool-machines-btn'`; this is what makes the rail button click the sidebar button (without it the rail button is dead).
- [ ] `static/js/ui_visibility.js:23` `UI_VIS_MAP` — add `'tool-machines': '#tool-machines-btn, #rail-machines'` so the new tool participates in Settings → Appearance "Customize UI" (and is hidden when `tools-section` is off, per `resolveVisibility`'s `tool-` prefix rule; `app.js:2740` applies the resolved map).
- [ ] `static/index.html:1820-1913` — add the matching **Appearance visibility row** in the Sidebar card's `vis-toggles` list, i.e. `<label class="vis-row">` with an icon, `<span class="vis-label">Machines</span>`, and `<input type="checkbox" checked data-ui-key="tool-machines">`, directly after the Cookbook row (`data-ui-key="tool-cookbook"`, `:1872`) so the panel mirrors the sidebar order. This markup is hand-written per tool; the UI_VIS_MAP key alone renders no checkbox. `settings.js:1562/1637` read/write it and `:1616-1620` resets it per card.
  - Nuance to state in the PR: this row is the **only** Settings-surface touch and it is generic appearance chrome (identical for every tool), not SSH server management — it does not violate G2/AC2.
- [ ] `static/app.js` — add the sidebar button block next to `:1015-1027` (`if (!Modals.toggle('machines-modal')) machinesModule.open()`), and a `'/machines'` entry in the `_routeOpen` map (`:1184-1200`).
- [ ] `ui_control open_panel machines` (agent-facing) — add `machines` to the three backend name lists (`src/tool_schemas.py:472` + `:478`, `src/tool_index.py:110`) and the runtime guidance + alias list in `src/agent_loop.py:381`; the frontend half is the `chatStream.js` branch below.
- [ ] `static/style.css` — add `#tool-machines-btn` / `#rail-machines` to the `.rail-minimized::after` right-offset list (`:860-869`) if the live-session dot should align like the other tools, and give both ids `position: relative` (`:19766-19772` pattern) when the indicator is added.
- [ ] `tests/test_ui_visibility_js.py` — add `"tool-machines": "#rail-machines"` to `EXPECTED_RAIL_PAIRS` (`:57-67`) and to the selector constants (`:44-50`) plus the `tools-off` assertion loop, or the new tool is silently outside the coverage that guards this class of bug.
- [ ] `src/tools/system.py:588-589` — correct the comment that claims GET list/detail/pubkey are reachable via `app_api` (§8).
- [ ] Backend §8 + §8.2 — `GET /api/ssh/audit`, `GET /api/ssh/servers/{server_id}/audit` and `GET /api/ssh/terminals`, with `list_audit()` in `src/ssh_remote.py` and `list_terminals(owner)` in `src/ssh_client.py`; owner-scoped, read-only, outside `_check_rate_limit`.
- [ ] `static/app.js:165` `initRailHoverLabels()` — optionally add `'rail-machines': 'Machines'`; it degrades to the button's `title` attribute if absent.
- [ ] `static/js/cookbook.js` — **remove** `import { initSshServers }`, the card markup, and the `initSshServers(body)` call.

## 10. Docs and copy sweep (everything, per Round 3)

1. `README.md:55` — rewrite the **"My servers (SSH)"** bullet: the feature is now **Machines**, reached
   from the sidebar/rail (not Cookbook → Settings), and mention the new transfer + activity surfaces.
2. `src/tool_implementations.py:174` — `do_list_ssh_servers` empty-state string becomes
   `"No SSH servers saved. Add one in Machines."` (agent-facing copy, no code path change).
3. `ssh-rsh-spec.md` — amend **§8** (UX proposal: placement is now a first-class *Machines* area, not
   Cookbook → Servers) and **§17 Phase 1** (frontend task mentions the Machines area); leave the rest normative.
   Same amendment note to `ssh-implementation-plan.md` **§3** (frontend pointers) and its §1/§2 task lists
   where "My servers" appears.
4. `MODULE_SUMMARY.md` — add/update the frontend module map so `sshServers.js` + `machines.js` are listed
   under a Machines entry.
5. Anything else that names the old path: re-run
   `grep -rn "My servers\|Cookbook → Settings\|Cookbook → My servers" --include=*.md --include=*.py --include=*.js`
   and fix each hit.
6. `src/tools/system.py:588-589` — the comment above `_ssh_app_api_blocked` claims GET
   list/detail/pubkey + POST test are "reachable via app_api"; `routes/ssh_routes.py:96-100` refuses the
   loopback identity, so correct the comment (no behaviour change).

## 11. Decisions I made (delegated items)

### 11.1 Sidebar and rail position — **immediately after Cookbook**
In the sidebar `#tools-section`, insert `#tool-machines-btn` directly after `#tool-cookbook-btn`
(`index.html:888-898`) and, in the icon rail, `#rail-machines` directly after `#rail-cookbook` (`:737`).
Rationale: Machines is the tool that was carved out of Cookbook, and both orderings stay consistent with
each other (the rail already mirrors the sidebar order for cookbook/compare/calendar). Appending at the
end would separate it from the model/infra tooling it belongs near and would reorder users' muscle memory.

### 11.2 Trigger behaviour — **same as Cookbook (restore + focus, never duplicate)**
Clicking `#tool-machines-btn` / `#rail-machines` opens the window if closed, and if it is minimized,
restores it. It never duplicates and never toggle-closes from the trigger (matching `cookbook.js`
`:3374-3378` minimized-restore and `:3379-3382` already-visible no-op). The rail click reaches the sidebar
button through `_railToolMap` (`static/app.js:3739`), so the sidebar button's handler is the single
implementation both entry points share. Only the window's own ✖ (and the "Toggle Window" hotkey path)
closes it.

### 11.3 Migration — **nothing to preserve; no shim, no notice**
- Server data is not stored client-side — the list always comes from `GET /api/ssh/servers`, so no
  state can be orphaned by the move.
- An in-flight **interactive terminal** hosted by the old Cookbook card could not survive the swap anyway:
  the Cookbook body is re-rendered from scratch (`body.innerHTML = html` in the tab render path), which
  drops the module's `d._sshTerminal` handle without aborting it — the stream is neither reused nor
  cleanly closed, so the session lingers until something else triggers the (lazy) reaper and its output
  goes nowhere. No user state is worth carrying across; the new area's explicit Disconnect (§7.3) is the
  fix, not a migration.
- No redirect from Cookbook, no one-time banner (the user explicitly asked that the card be removed
  completely). Discoverability instead comes from the guided empty state and the sidebar/rail entry.

### 11.4 Sidebar position is safe by construction (researched)
Section drag-reorder persists **section ids only** (`Storage.KEYS.SECTION_ORDER = 'sidebar-section-order'`,
`static/js/section-management.js` on save/restore), so inserting `#tool-machines-btn` inside the existing
`#tools-section` cannot disturb a user's saved order or the restore loop. No migration, reorder fix, or
position-related regression work is needed for §11.1.

## 12. Acceptance criteria

- **AC1 — Machines is top-level.** Fresh load: sidebar Tools shows **Machines** right after Cookbook; the
  icon rail shows the Machines button; clicking **either** opens `#machines-modal` (the rail button works
  via `_railToolMap`, not by luck); the window minimizes to a dock chip labelled **Machines** and
  restores; and Settings → Appearance "Customize UI" can hide the tool from both the sidebar and the rail.
- **AC2 — Nothing SSH-related is in Settings.** The main Settings dialog (`#settings-modal`,
  `static/js/settings.js` + `static/js/settings/registry.js` panel list) contains no SSH/Machines panel,
  row, or link; assert in a test that the settings registry has no machines/ssh panel.
- **AC3 — Cookbook is clean.** The Cookbook modal's Settings tab renders HuggingFace Token + shared
  Servers only; `static/js/cookbook.js` contains no `sshServers` import, no `ssh-` panel ids, no
  `initSshServers` call.
- **AC4 — Full loop in the new area.** Add machine (form dialog) → Test green + fingerprint pinned +
  detail pane populated → Run one-shot → Connect terminal inline → transfer upload + download round-trip →
  Activity shows the events (hash prefixes, no secrets) → Edit → Delete.
- **AC5 — Terminal survives the window.** With a session open, minimize (dock chip) and close/restore the
  modal, then type in the terminal: output still flows; the session ends only on Disconnect or the idle
  kill. No new session is created by minimize/close/restore. A clean page reload is *not* a hole in this
  AC: the server tears the PTY down on disconnect (`routes/ssh_routes.py:265-273`) and the reopened area
  starts fresh (§7.3).
- **AC6 — Deep link.** `#machine-<id>` (e.g. from a chat panel link) opens Machines focused on that
  machine; an unknown id opens the area with a not-found notice and no error toast-storm.
- **AC7 — /open machines** works, and the `/open` fallback hint lists Machines.
- **AC8 — Keyword/panel routing.** `chatStream.js` panel link for machines opens the area; the slash
  palette offers Machines; the `/machines` entry in `static/app.js`'s `_routeOpen` map opens it; and the
  agent tool works end-to-end — `ui_control open_panel machines` opens the window (backend name lists +
  frontend handler).
- **AC9 — Ownership unchanged.** User B cannot see, test, exec on, transfer from, or read audit rows for
  user A's machine (existing 403/404 semantics); the new audit route enforces the same.
- **AC10 — Copy sweep done.** No remaining `Cookbook → Settings → My servers` / `Cookbook → My servers`
  references in `README.md`, `src/tool_implementations.py`, the two SSH spec/plan files, or any other
  `.md`/`.py`/`.js` (grep clean).
- **AC11 — Regression suites green.** `tests/test_ssh_servers_js.py` (rewritten — including the inverted
  terminal-contract pin), the SSH backend suites (`test_ssh_servers.py`, `test_ssh_exec.py`,
  `test_ssh_api.py`, `test_ssh_password_auth.py`, `test_ssh_terminal.py`), `test_tool_policy.py`,
  `test_review_regressions.py`, `test_tool_path_confinement.py`, `test_workspace_confine.py`, and the
  frontend shell tests (`test_ui_visibility_js.py`, `test_panel_loader_js.py`,
  `test_plain_ui_control_open_panel.py`, `test_keybind_altgr_js.py`, keyboard-shortcut tests).
- **AC12 — Wiring-parity guard (new).** A test asserts every `UI_VIS_MAP` key has a matching
  `data-ui-key` row in the Appearance panel (`static/index.html`) **and** a paired `#rail-*` button —
  the class of bug that produced this review's `tool-machines` finding, and no such test exists today.
- **AC13 — Live terminals are visible and clearable** (the §8.2 decision). With sessions open — including
  one held by a second tab and one whose client died without disconnecting — `GET /api/ssh/terminals`
  returns exactly the caller's sessions with `server_id`/label, the area displays them and the cap usage,
  and **Disconnect all** empties the list; no other owner's session ever appears.

## 13. Test plan

**Frontend source-pinning tests (rewrite):**
- Reframe `tests/test_ssh_servers_js.py::TestCookbookWiring` → `TestMachinesWiring`:
  assert `machines.js` imports `initSshServers` from `./sshServers.js`; assert the Machines modal ids
  exist in `static/index.html`; assert `cookbook.js` **no longer** imports/initialises the panel.
- **Invert the terminal-contract pin (required by AC5).**
  `TestTerminalContract::test_live_session_is_closed_when_the_panel_goes_away` currently *requires*
  `src.count('_closeTerminal(d);') >= 2` and `controller.abort()`. Change it to assert the new rule:
  `_hideDetail`/`_showDetail` do **not** call `_closeTerminal`, an explicit Disconnect path exists and is
  the only in-UI teardown, and the abort + `DELETE /terminal/{sid}` live on that path. Keep the sibling pins
  (`test_terminal_verbs_match_the_server_routes`, `test_input_is_line_oriented_and_escaped_into_the_dom`,
  `test_server_derived_strings_are_escaped`).
- New assertions that the IA hooks exist: `tool-machines-btn` + `rail-machines` in `index.html`,
  `_AUTO_WIRE`/`_LABELS` entries in `modalManager.js`, `_railToolMap` entry in `static/app.js`,
  the six hotkey touchpoints, `/open machines` registration in `slashCommands.js`, the `machines` panel-link
  branch in `chatStream.js`, and the `machine` entity hash in `init.js`/`chatRenderer.js`.
- Offline coverage: extend `tests/test_panel_loader_js.py` (its `:187` case is the precedent) or add a
  sibling test asserting the Machines modules are precached — `PRECACHE` in the eager-import design,
  `PANEL_PRECACHE` + `"machines" in panelNames()` in the lazy design.
- Extend `tests/test_ui_visibility_js.py` (`EXPECTED_RAIL_PAIRS` + selector constants) so the new tool is
  inside the rail-pairing guard, and add the AC12 parity guard (UI_VIS_MAP ⇄ `data-ui-key` ⇄ rail pair)
  in the same file so the next tool cannot drift out of sync silently.
- Extend the `ui_control` coverage: `tests/test_plain_ui_control_open_panel.py` only pins parsing today;
  add an assertion that `machines` appears in the three backend name lists
  (`src/tool_schemas.py:472/478`, `src/tool_index.py:110`, `src/agent_loop.py:381`), or a route/dispatch
  test that `open_panel machines` reaches the frontend handler.
- Negative test (AC2): the settings registry/panel list contains no `machines`/`ssh` panel.
- Keep the existing node-run helper tests unchanged (`sshServerPayload`, `sshTestMessage`,
  `sshErrorText`, `parseSshSse`, row/list HTML, escaping).

**Backend tests (new, small):**
- `GET /api/ssh/audit` returns only the caller's rows; `scope=all` is 403 for non-admins and returns other
  users' rows for admins; `command_hash` is present and no secret fields/command text appear;
  per-server route 404s for another owner's id; neither route is behind the rate limiter.
- `GET /api/ssh/terminals` (AC13): returns only the caller's live sessions (a second owner's session never
  appears); returns `[]` after the client is disconnected, since the stream's `finally` already closed the
  PTY; carries `server_id`/label; and is not behind the rate limiter.

**Browser smoke (per Round 4):**
- Drive the real UI and capture a screenshot: app loads → click the Machines rail button → modal opens
  (guided empty state) → open the add form → fill a field → Escape/close → reopen and confirm the window
  restores from its dock chip. Where a throwaway `sshd` is available (the `tests/helpers/ssh_fixture.py`
  chain from the implementation plan), extend the smoke pass to Test + Run + Connect and re-verify AC5
  (minimize → output still flows).

**Commands:** run the affected pytest files directly (e.g. `python -m pytest tests/test_ssh_servers_js.py
tests/test_panel_loader_js.py -q`) and the SSH backend suite; keep each invocation's exit status visible.

## 14. Risks / watch-outs

- **Terminal teardown is the trap — and it sits in the hide path, not the close path.** `sshServers.js`
  calls `_closeTerminal(d)` from both `_showDetail` (`:156`) and `_hideDetail` (`:164`), so a naive move
  keeps killing sessions on row switch/collapse and silently breaks AC5; the existing test pin
  (`TestTerminalContract`) then *rewards* the wrong behaviour. Verify with the browser smoke pass, not just
  source assertions.
- **Anchors drift.** Every `:line` in this spec was verified against `ca9b5ebc`; re-check before editing,
  especially in `static/app.js` (194 KB) and `static/js/settings.js` (5.6 k lines).
- **Pre-existing offline gap.** `sshServers.js` is absent from both `sw.js` lists while `cookbook.js` is in
  `PRECACHE` — fix it in the same change (`sw.js:32-39` explains the two lists' contracts).
- **"Settings" nuance to state out loud.** The one Settings-surface edit is the generic appearance
  checkbox row (`data-ui-key="tool-machines"`) that every tool has; say so in the PR body so a reviewer
  does not read it as "SSH was added to Settings" and so AC2 stays honest.
- **Don't promise a timer.** The 10-minute idle kill is lazy (fired only by the next Connect —
  `src/ssh_client.py:416`). UI copy and tests must not describe it as a running guard.
- **UI-fuzz harness (`tests/bombadil-spec.ts`).** `package.json` has no scripts and no workflow
  references it, so it runs out-of-band; its `noModalStacking <= 2` property is unaffected in kind by
  adding one more modal (modalManager has no global exclusivity — only `_bringToFront` and per-tool rules
  like `_closeCompareIfActive`). Mention it in the PR only if the harness is run there.
- **Double-registration.** `modalManager.js` has both `_LABELS`/`_AUTO_WIRE` and explicit
  `Modals.register(...)`; missing one gives a window that cannot minimize or restore (the badge/dock
  silently no-ops). Add all three touchpoints at once.
- **Silent dead rail button.** `static/app.js:3739` `_railToolMap` is what binds `rail-*` clicks to
  `tool-*` buttons — a missing `rail-machines` entry leaves a button that renders, hovers, and does
  nothing. Likewise a missing `UI_VIS_MAP` key makes the tool impossible to hide from Customize UI.
- **`init.js` hash regex.** A missed `machine` entry makes `#machine-<id>` look like a session id, so the
  composer-draft logic treats it as a session target — subtle, and easy to miss.
- **Precache contract.** `sw.js` warns that entries must match the exact requested URL; if `machines.js`
  is only reachable through `panels.js`, it belongs in `PANEL_PRECACHE`, not `PRECACHE`.
- **Renaming ids vs keeping them.** Renaming `#ssh-servers-list` → `#machines-*` touches `sshServers.js`
  internals and several test assertions; keeping them is cheaper but leaves `ssh-` names in a
  "Machines" UI. Pick one in the implementation and be consistent (the spec's ACs do not depend on it).
- **Scope creep.** Audit viewer + transfer + detail pane are all v1 per Round 5; if time is short, the
  ordering to cut is Activity → Transfer → detail pane, keeping parity (AC4 core) intact.
- **Do not touch**: `_ADMIN_TOOLS` prompt visibility, `app_api` blocklist entries, `NON_ADMIN_BLOCKED_TOOLS`,
  plan-mode gating, `THREAT_MODEL.md`/`SECURITY.md` wording (already correct — only the *place* changes).

## 15. Appendix — file / anchor index

| Purpose | File |
|---|---|
| Area shell (new) | `static/js/machines.js` |
| Feature body | `static/js/sshServers.js` (`initSshServers:470`, `_root:130`, helpers `:17-120`) |
| Remove SSH card from | `static/js/cookbook.js:13, 3280-3306` |
| Modal + sidebar + rail markup | `static/index.html:724-750`, `:859-960`, `:1389-1397` |
| Dock chip / auto-wire | `static/js/modalManager.js:~130`, `:~1402` |
| Register/restore precedent | `static/js/cookbook.js:3353` (`open`), `:3399-3404` (`Modals.register`), `:3483` (`_doClose`), `:3504` (`close`) |
| Window + tool hotkeys | `static/js/keyboard-shortcuts.js:9-17`, `:98`, `:265`; `static/js/settings.js:1651`, `:1685`, `:1710`, `:1724` |
| App shell wiring | `static/app.js:47` (eager modal import), `:3739` (`_railToolMap`), `:165` (`initRailHoverLabels`), `:2725+` (Customize UI apply) |
| Per-tool visibility | `static/js/ui_visibility.js:13-40` (`UI_VIS_MAP`, `resolveVisibility`); `tests/test_ui_visibility_js.py:44-67` |
| Loopback refusal | `src/tools/system.py:588-610` (`_ssh_app_api_blocked`), `routes/ssh_routes.py:96-100` (`_owner` rejects `internal-tool`/`api`) |
| Terminal caps / reaper | `src/ssh_client.py:47-48` (`MAX_TERMINAL_SESSIONS_PER_USER`, `TERMINAL_IDLE_KILL_S`), `_reap_idle:458` |
| Slash command | `static/js/slashCommands.js:1348, 1359-1361, 1393, 5995-6051`, tour opener `:2868` |
| Chat panel link | `static/js/chatStream.js:177-207` |
| Slash palette / keywords | `static/js/tasks.js:2606-2612`, `:2633-2640` |
| Lazy loading | `static/js/panels.js`, `static/sw.js:40+`, `:103+` |
| Deep links | `static/js/chatRenderer.js:1361-1425`, `static/js/init.js:20` (regex) / `:22` (`hasSessionTarget`) |
| Appearance visibility rows | `static/index.html:1820-1913` (`data-settings-panel="appearance"`, `data-ui-key` rows; `tool-cookbook` at `:1872`, last row `:1912`); `static/js/settings.js:1562`, `:1616-1620`, `:1637` |
| Sidebar button blocks + route map | `static/app.js:1008-1060` (per-tool click wiring), `:1184-1200` (`_routeOpen`) |
| Agent UI control (`open_panel`) | `src/tool_schemas.py:471-478`, `src/tool_index.py:110`, `src/agent_loop.py:381`; frontend `static/js/chatStream.js:177-207` |
| CSS badge hooks | `static/style.css:860-869` (rail-minimized offsets), `:19766-19772` (`position: relative` per id) |
| Section-order storage | `static/js/storage.js:24`, `static/js/section-management.js` (save/restore by section id) |
| Terminal session API | `src/ssh_client.py:409-478` (`open_terminal`/`get_terminal`/`close_terminal`/`session_count`/`_reap_idle`), `src/ssh_remote.py:767` / `:794` (facade); new `list_terminals(owner)` for §8.2 (`session_count` is its shape) |
| a11y | `static/js/a11y.js:59-153` (automatic) |
| Doc comments listing modals | `static/js/windowResize.js:3` |
| Routes | `routes/ssh_routes.py` (register `app.py:803-805`) |
| Store / audit writer | `src/ssh_remote.py` (`audit()` `:336`), `core/database.py:649+` (`SshServer`), `:675-693` (`SshAuditLog`) |
| Agent tools | `src/tool_implementations.py:130-183`, `src/tool_schemas.py:960-980`, `src/tool_index.py:139, 492`, `src/agent_loop.py:488, 538, 811-815` |
| Copy to update | `README.md:55`, `src/tool_implementations.py:174` |
| Specs to amend | `ssh-rsh-spec.md` (§8, §17), `ssh-implementation-plan.md` (§3), `MODULE_SUMMARY.md` |
| Tests to rewrite / extend | `tests/test_ssh_servers_js.py` (`TestCookbookWiring` → machines; invert `TestTerminalContract`), `tests/test_ui_visibility_js.py`, `tests/test_panel_loader_js.py` |
| Terminal behaviour under test | `static/js/sshServers.js:153-183` (`_showDetail`/`_hideDetail`/`_closeTerminal`), `:289-330` (`_onConnect` + SSE), `routes/ssh_routes.py:258-273` (stream generator + `finally`) |
