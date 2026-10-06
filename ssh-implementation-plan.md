# SSH Remote Execution — Implementation Plan

> Builds `ssh-rsh-spec.md` (302 lines, all limitations resolved). Spec is normative on
> behavior; this plan is normative on **where code goes and in what order**.
> No code written yet — this file is the build checklist.
>
> **Repo & branch (updated):** work happens on the fork
> `grahfmusic/odysseus`, branch `ssh-spec` (based on fork `dev`, shares history
> — PR target is the fork's `dev`). Upstream `pewdiepie-archdaemon/odysseus`
> (`origin`) stays untouched. Local remote name for the fork is `fork`.

## 0. Key decisions this plan locks (derived from wiring found in-tree)

1. **Two agent tools, not one.** The spec sketches only `ssh_exec`, but the gate
   analysis forces a split: `ssh_exec` (mutating → plan-mode blocked) needs a
   read-only companion `list_ssh_servers` (plan-mode allowed, mirroring
   `list_cookbook_servers` in `PLAN_MODE_READONLY_TOOLS`). The agent cannot
   discover saved servers without it.
2. **Direct DB access, no HTTP loopback.** `do_ssh_exec` / `do_list_ssh_servers`
   import the store module directly (like `do_list_cookbook_servers` reads state).
   Rationale: loopback routes are owner-filtered for tool identity (the
   `/api/email/accounts` trap documented in `tool_index.py`) — direct access
   with an explicit `owner` argument avoids that class of bug entirely.
3. **One new module: `src/ssh_remote.py`.** Store (CRUD + validation + audit
   writer + key helpers) and Phase-1 execution (OpenSSH argv via
   `core/platform_compat._ssh_exec_argv`) live together, imported by both
   `routes/ssh_routes.py` and `src/tool_implementations.py`. Matches the repo's
   big-module style; avoids a premature `src/ssh_*` package.
4. **The `.ssh` exception is admin-blast-radius only.** `read_file`/`write_file`
   are in `NON_ADMIN_BLOCKED_TOOLS`, so the managed-dir exception (§6.4) only
   ever serves admins / admin-session agents. No owner parameter needed in the
   path resolvers — a managed-dir + filename allowlist suffices.

## 1. Phase 0 — test infra + key plumbing

| # | Task | Files |
|---|------|-------|
| 0.1 | `tests/helpers/ssh_fixture.py`: resolution chain `SSHD_TEST_HOST` env → temp local `sshd` on 127.0.0.1 (host key + `authorized_keys` in `tmp_path`, skip if `ssh`/`sshd` missing) → `pytest.skip`. Mark `ssh_integration`. Follow `tests/helpers/sqlite_db.py` (`make_temp_sqlite`) for fixture style. | new `tests/helpers/ssh_fixture.py` |
| 0.2 | `ensure_managed_ssh_dir()` in `src/ssh_remote.py`: `data/ssh` (`0700`), per-user `ssh-keygen -t ed25519` if missing (`0600`). Call from app startup (find lifespan/startup block in `app.py`) **and** `docker/entrypoint.sh` (covers fresh `compose up`). | `src/ssh_remote.py`, `app.py`, `docker/entrypoint.sh` |
| 0.3 | Docker build assertion that `ssh` exists (test or CI step; `openssh-client` already in `Dockerfile`). | `Dockerfile` / CI yml |

## 2. Phase 1 — backend

### 2.1 Database (spec §15 verbatim)
Add `SshServer` + `SshAuditLog` to `core/database.py` (conventions: `TimestampMixin`,
`EncryptedText`, nullable indexed `owner`, composite indexes). Auto-created by
`init_db()` → `Base.metadata.create_all` — **no migration function needed** for new
tables (migrations like `_migrate_encrypt_endpoint_keys` only cover new columns).

### 2.2 Store + execution (`src/ssh_remote.py`, new)
- CRUD with mandatory `owner` filter on every query; `validate_remote_host` /
  `validate_ssh_port` from `routes/_validators.py` (NOT just `_ssh_exec_argv` —
  the argv builder alone passes `-o ProxyCommand=…`).
- `ssh_allowed_host_patterns` enforcement (globs over `user@host:port` + CIDR via
  `ipaddress`; default `[]` = allow). Setting default goes in
  `src/settings.py:DEFAULT_SETTINGS` next to `tool_path_extra_roots`; read via
  `get_setting` (pattern: `tool_execution.py:118`).
- Audit writer: `test | exec | terminal_open | upload | download` + command
  SHA-256 (never text) + exit code.
- `exec_one_shot(server_id, owner, cmd, timeout, stdin)`: resolve row by id or
  per-owner label (mirror `_resolve_cookbook_host` name→host logic in
  `tool_implementations.py:1975`), build argv via `_ssh_exec_argv` with pinned
  `UserKnownHostsFile=data/ssh/known_hosts.d/<id>` + `ConnectTimeout`, run with
  timeout, truncate to `MAX_OUTPUT_CHARS` (`src/constants.py:62`, cap pinned by
  `tests/test_agent_loop_tool_output_truncation.py`).
- TOFU: `ssh-keyscan` capture on Test/first-connect → store fingerprint + write
  pinned known_hosts file; `StrictHostKeyChecking=yes` thereafter, fail closed.
- Key rotation/revocation per §6.1 (`.new` → atomic rename → one `.bak` → audit).
- **Argv-only, never `shell=True`** (cf. `task_routes` warning on `run_local`).

### 2.3 Agent tools (`ssh_exec`, `list_ssh_servers`)
Wire **both** names through every registry (miss one = silent failure; precedent:
the `agent_tools/__init__.py:81` comment about cookbook tools rejected as
"Unknown function call"):

1. `src/tool_implementations.py`: `do_ssh_exec(content, owner)` +
   `do_list_ssh_servers(content, owner)` (JSON args via `_parse_tool_args`;
   `ssh_exec` returns `{output|stdout, stderr, exit_code, host, server_id}`).
2. `src/tool_execution.py`: import + `elif tool == "ssh_exec"` /
   `elif tool == "list_ssh_servers"` next to the cookbook branches (~line 827).
   Add to **neither** `_ADMIN_TOOLS` (~line 293) **nor** `NON_ADMIN_BLOCKED_TOOLS`.
3. `src/tool_security.py`: `ssh_exec` → `_PLAN_MODE_KNOWN_MUTATORS`;
   `list_ssh_servers` → `PLAN_MODE_READONLY_TOOLS` (beside `list_cookbook_servers`).
4. `src/tool_schemas.py`: `FUNCTION_TOOL_SCHEMAS` entries
   (`ssh_exec {server, cmd, timeout?, stdin?}`, `list_ssh_servers {}`).
5. `src/tool_index.py`: `BUILTIN_TOOL_DESCRIPTIONS` entries + new SSH keyword
   frozenset (e.g. `{"ssh", "remote server", "my server", "run on", "on my box"}`)
   beside the cookbook hint sets (~line 438).
6. `src/agent_tools/__init__.py`: allowed-names set += both.
7. `src/tool_policy.py`: `_COMMON_TOOL_NAMES` += both.
8. `src/agent_loop.py`: `TOOL_SECTIONS` entries (fenced ```` ```ssh_exec ````
   usage) + new `"ssh"` domain in `_DOMAIN_TOOL_MAP` + short `_DOMAIN_RULES`
   string (saved-servers-only, never raw hosts, `sudo` decided remotely).
9. Prompts: `src/teacher_escalation.py:219` + `agent_loop.py:149-154`
   anti-pattern text — keep the `serve_model` rule, add `ssh_exec` as the
   correct general-remote channel.
10. Invocation check: fenced blocks use the tool name as language tag
    (`agent_loop.py:65,177`) so ```` ```ssh_exec ```` flows through
    `parse_tool_blocks` like other tools — prove with a dispatch test, no
    parser change expected.
11. Remote output is untrusted — RESOLVED, concrete site: tool outputs are NEVER
    wrapped at dispatch (`format_tool_result` → `_append_tool_results` in
    `agent_loop.py:2878-2894` emits raw `role:tool` / `[Tool execution results]`
    text; wrapping today happens only for preface sources — docs/skills in
    `agent_loop.py:1018,1205`, web/email/memories in `chat_processor.py:217-331`,
    research in `chat_routes.py:417,1373`). So wrap inside `do_ssh_exec` itself:
    add a 5-line public `wrap_untrusted_text(label, text) -> str` helper to
    `src/prompt_security.py` (same `UNTRUSTED_CONTEXT_HEADER` + `GUARD_OPEN` /
    `GUARD_CLOSE` + guard-escape as `untrusted_context_message`, but returning
    a string), and apply it to the stdout/stderr text placed in the result's
    `output` field. Structured fields (`exit_code`, `server_id`) stay raw.
    Test in `test_prompt_security.py` style (injection string stays inert).

### 2.4 Routes (`routes/ssh_routes.py`, new; register in `app.py`)
`setup_ssh_routes()` following `setup_shell_routes` / `setup_task_routes` shape,
but **owner-scoped, not admin-only** (do NOT reuse `_require_admin`): every query
filters `owner == current_user`; cross-owner → 403/404 (mirror
`test_companion_readonly.py` precedent). Endpoints per §10 (exec/upload/download
+ CRUD + test + pubkey; terminal in Phase 2). Simple per-user rate limit
(§6.4: 30/min → 429) — in-memory window counter is fine for MVP.
`app_api` blocklist (`tool_implementations.py:2220-2248`): add
`("POST", "/api/ssh/servers/{id}/exec")`-shaped entries (prefix form:
`/api/ssh/servers/` for POST/PUT/PATCH/DELETE as appropriate) so the agent must
use `ssh_exec` — same pattern as `/api/model/serve`, with `test_app_api_blocks_ssh_*`
cases in `tests/test_review_regressions.py`.

### 2.5 `.ssh` exception (`src/tool_execution.py`)
`_is_managed_ssh_path(resolved)`: under `realpath(DATA_DIR/ssh)` AND
(filename matches per-user key pattern `<owner>_ed25519*` / `*.pub`, or under
`known_hosts.d/`). Consult first in `_resolve_tool_path` and
`_resolve_tool_path_in_workspace`. Tests: managed key allowed;
`~/.ssh/authorized_keys`, `~/.ssh/config` still denied (extend
`tests/test_tool_path_confinement.py`, `test_workspace_confine.py`).

### 2.6 Settings row — RESOLVED: no Settings-UI work in MVP
`tool_path_extra_roots` (the direct precedent) has zero UI surface anywhere in
`static/js` — it is backend-only, set via `manage_settings` / `settings.json`.
`ssh_allowed_host_patterns` follows the same path: `DEFAULT_SETTINGS` default
+ `get_setting` enforcement only. No `settings.js` / `admin.js` change.

## 3. Phase 1 — frontend (**Machines** area) — RESOLVED pointers, variance bounded

> **Placement amended by `machines-area-spec.md`.** The owner-scoped list is no longer a
> Cookbook component. It is its own top-level area: `static/js/machines.js` owns the shell
> (modal + dock chip, master–detail layout, add/edit form dialog, transfer panel, activity
> view, `#machine-<id>` deep link) and imports the **unchanged** body layer
> `static/js/sshServers.js` (data/rows/terminal, still bound to `/api/ssh/servers`). The SSH
> card and its `initSshServers` import are removed from `static/js/cookbook.js`, and the
> main Settings dialog gains nothing. The `cookbook.js` row-render pointers below are now
> *style* precedent only — the two `servers` arrays are still never mixed.

Servers UI previously lived in `static/js/cookbook.js`: state `_envState.servers` (:75),
option/lookup helpers `_serverOptions` / `_serverByVal` (:113-146), row renderer
with Save/Cancel/Delete + key button (:1693-1830), list container
`#cookbook-servers-list` + `#cookbook-server-add` (:2037-2041), `_sshCmd`
wrapper (:195-198). Those patterns informed the Machines row renderer, bound to the
`/api/ssh/servers` endpoints instead of cookbook state.
Phase-1 actions: Test + Run (+CRUD); add/edit form dialog fields per spec §8.

## 4. Phase 2 — password + terminal
- `paramiko` (unpinned) in `requirements.txt` + wrapper per §6.2
  (RejectPolicy + manual pin check, `asyncio.to_thread`).
- SFTP `put`/`get` for transfer routes; `sudo -S` stdin-pipe for one-shot (AC5).
- Terminal protocol per §6.3 (open/stream/input/resize/close, 3-session cap,
  10-min idle kill; in-memory session table, loss on restart acceptable and
  documented); Windows → one-shot degrade via `PTY_UNSUPPORTED_ERROR` pattern.

## 5. Docs + PR discipline
- `THREAT_MODEL.md` amendment (§16: roles-table row + subsection after Internal
  Tool Loopback) and `SECURITY.md` bullet land **in the same PR that opens the
  gates** — never earlier.
- PRs go to the **fork's `dev`** (`grahfmusic/odysseus`), never upstream.
- Token scope gotcha (learned setting up the fork): pushing a branch that
  creates or modifies `.github/workflows/*` requires the `workflow` OAuth scope
  — the current token lacks it. Implementation phases touch no workflow files,
  so this should not bite; if CI changes become necessary, add the scope first
  (`gh auth refresh -s workflow`) rather than working around it.
- `README.md`: document the **Machines** area (sidebar/rail entry, transfer, activity log, copy-ready `ssh-copy-id` / `ssh` commands) — amended by `machines-area-spec.md`, no longer a Cookbook SSH-key section extension.

## 6. Test matrix (spec §12 + §11)
- New: `tests/test_ssh_servers.py` (validation, redaction, owner-scope, audit),
  `tests/test_ssh_exec.py` (dispatch, non-admin-own OK, cross-owner denied,
  plan-mode blocked, prompt wrap), `tests/test_ssh_api.py` (TestClient
  owner-scope, 429, secret redaction — pattern: `test_cleanup_owner_scope.py`).
- Fixture-backed (`ssh_integration`): full loop add→test→exec→transfer→delete,
  TOFU pin + change detection, sudo with/without password.
- Regression (must stay green): `test_tool_path_confinement`,
  `test_workspace_confine`, `test_tool_policy`, `test_review_regressions`,
  `test_shell_routes`, plus `test_tool_rag_keyword_hints` (ALWAYS set untouched)
  and `test_platform_compat`.

## 7. Risks / watch-outs
- **Prompt injection via remote output** — verify the wrap layer before shipping
  exec to non-admins; a missed wrapper is a finding, not a follow-up.
- **`agent_loop._ADMIN_TOOLS` (line 1256)** is prompt-visibility, not execution —
  `ssh_exec` must NOT be added there or non-admin agents never see the tool.
- **Paramiko + SQLite threads** — one scoped session per `to_thread` call; check
  `core/database.py` session handling before Phase 2.
- **Scheduled `ssh_command` stays admin-only** (`task_routes._ADMIN_ONLY_ACTIONS`)
  — out of scope, do not "fix" opportunistically.
- **Frontend scope creep** — Machines variance is now bounded (§3 pointers:
  clone row-render patterns, repoint data source). Backend + agent tool still
  deliver value alone, so Phase-1 MVP can ship API-first if the UI slips.
