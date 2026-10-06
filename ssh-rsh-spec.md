# SSH / Remote-Shell — Out-of-the-Box, Unblocked — Spec

> Source: user interview (4 rounds via `ask_user`) + codebase reconnaissance on `dev` branch.
> Status: **spec only — no code changes made.**
> Scope short name: `ssh-rsh`

## 1. Request in the user's words

> "i want to add ssh/rsh function out of the box without it being blocked"

Interpreted + confirmed through interview as:

1. A **first-class remote-shell (SSH) function** that works immediately after clone / `docker compose up` with **no extra setup**.
2. **Nothing in the app blocks it by design** — today four things feel (or would feel) like blocks:
   - `read_file` / `write_file` **sensitive-path deny-list** refuses `.ssh`, keys, `authorized_keys`, `known_hosts` (`src/tool_execution.py: _SENSITIVE_BASENAMES`, `_SENSITIVE_FILE_PATTERNS`, `_resolve_tool_path`).
   - **Non-admin tool gate** blocks `bash`/`python`/file tools for non-admins (`src/tool_security.py: NON_ADMIN_BLOCKED_TOOLS`, `THREAT_MODEL.md` roles table).
   - **Docker ergonomics**: `openssh-client` + `data/ssh` volume exist for Cookbook but are not framed/tested as a general SSH feature.
   - Anticipated blocks (user hasn't hit one yet — wants the spec to **guarantee** SSH is unblocked by design).
3. A **menu to add servers: host + username + password**, with **SSH-key generation** as the preferred auth path.
4. Available to **all logged-in users** (not admin-only), reusing/extending the **Cookbook → Servers** UI rather than a brand-new sidebar section.

## 2. Interview answers (authoritative)

### Round 1 — scope / terminology / targets
| Q | Answer |
|---|---|
| What does "ssh/rsh function" mean? | **All of the above** (custom text): new agent tool + unblock `ssh` in `bash` + unblock `.ssh` file access + extend Cookbook remote servers |
| What does "rsh" mean? | **Remote shell generally** — NOT the literal legacy `rsh`/`rlogin`/`rexec` protocol |
| Where should SSH connect? | Custom text: **"i want an option in the menu to add servers, username and password"** — i.e. user-defined saved-server list, not an open "any host" free-for-all nor LAN-only restriction |

### Round 2 — auth / permissions / UI
| Q | Answer |
|---|---|
| Auth + storage | **Username + SSH key gen** (app generates keypair per server, user copies public key — current Cookbook flow) |
| Who can use it | **All logged-in users** (each manages/uses servers; breaks current admin-only shell model — see §7) |
| UI | **Cookbook servers reuse** — extend existing Cookbook → Servers UI to be the single server list |

### Round 3 — trust / interaction / non-admin risk
| Q | Answer |
|---|---|
| Host-key verification | **Accept-on-first-use** (current Cookbook behavior: `StrictHostKeyChecking=no`, `ConnectTimeout=5`) |
| Interaction shape | **All of the above** (custom text): one-shot commands + interactive PTY terminal + file transfer (SFTP-style up/down) |
| Non-admin shell-equivalent risk | Custom text: **"allowed for all users but for sudo access it will check against the server if they have that access"** — i.e. the app does NOT gate privilege; the **remote server** is the authority on what the login user (incl. `sudo`) may do |

### Round 4 — current pain / out-of-box / sudo
| Q | Answer |
|---|---|
| What's blocked today (multi)? | All four: `.ssh` deny-list + non-admin tool gate + missing-client-in-Docker ergonomics + "haven't hit yet — design guarantee" |
| Out-of-box must-haves (multi) | **Client + key + volume ready** (openssh-client in image, `data/ssh` mounted, key auto-generated if missing) + **works native too** (Linux/macOS, no Docker-only assumptions) + **no signup friction** (add first server without visiting extra settings); **offline-safe NOT required** |
| Sudo handling | **Optional sudo password**: per-server optional escalation password stored alongside login creds |

## 3. Current state (reconnaissance findings)

These are the exact mechanisms the spec must change or explicitly carve through. All paths relative to repo root.

- **File-tool deny-list blocks `.ssh`.**
  `src/tool_execution.py: _SENSITIVE_BASENAMES` (`.ssh`, `.gnupg`, …), `_SENSITIVE_FILE_PATTERNS` (`authorized_keys`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `known_hosts`), enforced in `_resolve_tool_path` / `_resolve_tool_path_in_workspace` and vetted at bind time in `vet_workspace`. Tests pin this: `tests/test_tool_path_confinement.py`, `tests/test_workspace_confine.py`.
- **Non-admin tool gate blocks shell.**
  `src/tool_security.py: NON_ADMIN_BLOCKED_TOOLS` includes `bash`, `python`, `read_file`, `write_file`, `edit_file`, `grep`, `glob`, `ls`, …; plan-mode allow-list `PLAN_MODE_READONLY_TOOLS` deliberately excludes `bash`/`python`. `THREAT_MODEL.md` + `SECURITY.md` document shell/files/MCP as **privileged admin functionality** and list missing shell sandbox / SSRF as known gaps.
- **Cookbook already shells out to `ssh` for remote model servers.**
  `services/hwfit/hardware.py` (`_run` over SSH), `src/cookbook_serve_lifecycle.py:104` (`ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no`), `src/tool_implementations.py` (`_resolve_cookbook_host`, `do_serve_model`/`do_download_model` with `remote_host`/`ssh_port`/`env_prefix`), `core/platform_compat.py: _ssh_exec_argv` / `run_ssh_command` (centralized argv builder with `ConnectTimeout`, `StrictHostKeyChecking`, `-p` handling + `ValueError("Invalid SSH remote host")` on `-`-prefixed hosts), `routes/shell_routes.py: _ssh_base_argv`, `scripts/odysseus-cookbook --host user@box --ssh-port`.
- **Out-of-box SSH plumbing already half-exists.**
  `Dockerfile` installs `openssh-client` (comment: "required for Cookbook remote server tests, setup, probes…"); `docker-compose.yml` (+ gpu overlays) mount `./data/ssh:/app/.ssh:z`; `README.md` documents `ssh-copy-id -i data/ssh/id_ed25519.pub user@server`. No general-purpose SSH tool/UI is built on it.
- **Shell execution paths.**
  Agent one-shot: `src/tool_execution.py: execute_tool_block` (+ `agent_cwd`, workspace confinement). Human terminal: `routes/shell_routes.py` (PTY via `pty`/`fcntl`, `PTY_SUPPORTED` flag, Windows fallback). Teacher prompt currently forbids raw ``ssh <host> 'tmux …'`` incantations (`src/teacher_escalation.py:219`) — will need updating.
- **No literal `rsh` binary usage** anywhere in the tree (only color-code false positive in `static/js/calendar/utils.js`). `rsh` as a protocol is confirmed out of scope.

## 4. Goals

1. **G1 — Saved servers menu.** New owner-scoped **"My servers"** list surfaced alongside (not merged into) Cookbook → Servers: add/edit/delete/test/remove; fields: label, host, port (default 22), username, auth (key and/or password — see §6.2), optional sudo password, per-user ownership. Rationale: `cookbook_state.json` is a single global file with a shared `remoteHost` default and no owner column — merging personal credentials there would break isolation and `_resolve_cookbook_host` name matching.
2. **G2 — Key-first auth, password-capable.** Keep key-gen flow (generate per-server or per-user key in `data/ssh`, show public key + `ssh-copy-id` hint); also support the requested username+password entry and optional sudo/escalation password.
3. **G3 — Three interaction modes, all unblocked.**
   - (a) **One-shot command** (agent + UI): send command, get `stdout`/`stderr`/`exit_code` with timeout + truncation (reuse `MAX_OUTPUT_CHARS` conventions).
   - (b) **Interactive terminal** (human UI): persistent PTY session to the saved server (reuse `shell_routes` PTY streaming where possible).
   - (c) **File transfer**: upload/download between app workspace and remote path (SFTP/`scp` under the hood; exact transport is implementation detail).
4. **G4 — Agent tool.** New dedicated tool (proposed name `ssh_exec`; bikeshed at implementation) so the agent does not have to smuggle `ssh …` through `bash` strings; `bash`-issued `ssh` also works (no command-string filter for `ssh`).
5. **G5 — Scoped unblocking of `.ssh`.** File tools keep the broad deny-list, but gain a **narrow, audited exception** for the app-managed identity dir (`data/ssh` ↔ `/app/.ssh` in Docker) so keygen/show-key/`known_hosts` flows work without opening `~/.ssh` generally.
6. **G6 — Out-of-the-box.** Fresh clone + `docker compose up` (and native `venv` install): client present, volume mounted, key auto-generated if missing, zero settings visits before first server can be added.
7. **G7 — All-users access with server-side authority.** Any authenticated user can add/use **their own** servers; whether they can `sudo` is decided **by the remote host** (wrong password → remote refuses; surface stderr), never by the app granting extra rights.

## 5. Non-goals

- **N1 — Literal `rsh`/`rlogin`/`rexec` protocol.** User confirmed "remote shell generally"; do not add or unblock the insecure `rsh` binary.
- **N2 — General `~/.ssh` browsing.** The exception is only the app-managed identity dir + per-server `known_hosts` pinning; arbitrary home-dir `.ssh` access stays denied.
- **N3 — App-side privilege elevation.** No app-side `sudo`/role grant; no bypass of the remote host's own auth.
- **N4 — New top-level sidebar section.** Reuse Cookbook → Servers (per user vote); don't build a parallel server manager.

## 6. Functional requirements

### 6.1 Server records (DECIDED: new DB table — not `cookbook_state.json`)
- Model: new SQLAlchemy table `ssh_servers` in `core/database.py` (auto-created by `init_db()` → `Base.metadata.create_all`, pattern: `EmailAccount`, `ModelEndpoint`, `ProviderAuthSession`). Columns: `id` (String PK, indexed), `owner` (String, indexed, nullable=True → legacy/shared semantics like `sessions.owner`/`model_endpoints.owner`), `label` (String, required), `host` (String), `port` (Integer, default 22), `username` (String), `auth_type` (`key` | `password` | `both`), `password = Column(EncryptedText)` (login password, nullable), `sudo_password = Column(EncryptedText)` (nullable), `ssh_key_ref` (String — relative key filename under `data/ssh`, never inline key material), `host_key_fingerprint` (String — pinned TOFU fingerprint, see §6.2), `created_at`, `last_tested_at`, `last_test_result` (via `TimestampMixin`). Encryption via `EncryptedText` → `src/secret_storage.encrypt` (Fernet, key at `data/.app_key` mode `0600`); threat model is stolen-DB-file, not live-process compromise (cf. `EmailAccount` docstring).
- Key layout (DECIDED: per-user keypair): `data/ssh/<owner>_ed25519` + `.pub` (`0600` / `0700` dir), one key per user referenced by all their servers (fewer keys to rotate; §13 Q5 resolved). `ssh_key_ref` stores only the filename.
- Rotation/revocation (DECIDED — resolves L6): stable per-user filename ⇒ **rotate** = generate `<owner>_ed25519.new` → atomic rename over the live key → keep one `<owner>_ed25519.bak` → audit `key_rotated` event; user re-copies the new `.pub` to their remotes. **Revocation** = delete the server row + delete `known_hosts.d/<server_id>` + audit `server_deleted`. **Suspected compromise** = rotate + clear that user's pinned `host_key_fingerprint` values (forces re-TOFU confirm on next connect). No schema change needed.
- Validation: `routes/_validators.py:validate_remote_host` (regex `^(?:user@)?host$`, rejects spaces/`-o`/flags/`ssh://`) + `validate_ssh_port` (1–65535) — NOT just `core/platform_compat._ssh_exec_argv` (which only rejects empty/`-`-leading and would pass `ssh -o ProxyCommand=…`). Execution must build **argv lists, never `shell=True`** (cf. `task_routes` warning on `run_local`).
- Ownership: users see/use **only their own** rows (`owner == current_user` filter on every query); admins may list all (support) but **cannot exec** via another user's row (default: no cross-owner use — mirrors `test_companion_readonly.py` precedent). No sharing in MVP.
- Serializers: list/detail APIs return `has_password: bool` / `has_sudo_password: bool` only — never secret values or key material.

### 6.2 Auth flows
- **Key (default):** "Generate key" creates (or reuses) managed keypair, shows public key + copy button + `ssh-copy-id -i … user@host` hint (existing README pattern). "Test connection" runs `ssh -o ConnectTimeout=5 <user@host> true` (or equivalent via `_ssh_exec_argv`).
- **Host-key TOFU with pinning (DECIDED — replaces bare `StrictHostKeyChecking=no`):** on Test/first-connect, capture the host key via `ssh-keyscan` (or library equivalent), **show the fingerprint in the UI for confirm**, store in `host_key_fingerprint` + per-server known_hosts file `data/ssh/known_hosts.d/<server_id>` (`0600`). Subsequent connects enforce the pin (`StrictHostKeyChecking=yes` + `UserKnownHostsFile=<pinned file>`); on mismatch, fail closed with a host-key-changed warning (never silently accept). This keeps the user's accept-on-first-use vote while making it auditable.
- **Password (requested) — transport DECIDED (two phases; resolves L1):** Phase 1 (MVP, no new deps): **key-only via OpenSSH argv** (`core/platform_compat._ssh_exec_argv` / `routes/shell_routes._ssh_base_argv` minus the hardcoded `StrictHostKeyChecking=no`, plus pinned `UserKnownHostsFile`). Phase 2: add **`paramiko`** (unpinned, matching `requirements.txt` style) behind a thin wrapper (e.g. `src/ssh_client.py`): `SSHClient` with `RejectPolicy`, then a **manual pin check** — compare `transport.get_remote_server_key()` fingerprint/base64 against the row's `host_key_fingerprint`, abort on mismatch (fail closed, never auto-accept); password passed as a `connect(..., password=...)` API arg (never cmdline/env); one-shot via `exec_command(cmd, timeout=...)`; SFTP via `open_sftp()` (`put`/`get`). Paramiko is blocking → run every call in `asyncio.to_thread` under the same timeout/cap rules as one-shot (§6.4). **Rejected: `sshpass`** (new `Dockerfile` apt layer + `sshpass -p` leaks via `ps`; even `sshpass -e` exposes `SSHPASS` in `/proc/<pid>/environ`). Until Phase 2 lands, password fields are stored (encrypted) but login uses key auth; UI labels password auth "coming soon".
- **Sudo (optional) — two paths:** one-shot uses `sudo -S` with the stored sudo password piped via **stdin pipe to the remote session only** (never to the app-host shell, never logged); interactive terminal passes the remote `sudo` prompt through live with no app-side injection. Omitted → remote decides (`sudo: a password is required` stderr surfaced as-is).

### 6.3 Execution modes
- **One-shot (`ssh_exec` agent tool + UI "Run command"):**
  args: `server` (id or label; labels resolve per-owner like `_resolve_cookbook_host`), `cmd` (string), `timeout` (default ~30s, cap ~120s), stdin optional (needed for `sudo -S`).
  returns: `{ output|stdout, stderr, exit_code, host, server_id }`, truncated per `MAX_OUTPUT_CHARS`; timeouts reported as `exit_code != 0` + clear error, never hang.
- **Interactive terminal (UI) — Phase 2 protocol (resolves L2; one-shot + key-transfer are Phase 1):** transport is paramiko `invoke_shell` + `get_pty(term, cols, rows)` (same Phase-2 dep as L1 — no `ssh -tt` subprocess to manage). HTTP shape mirrors `POST /api/shell/stream` (SSE, `text/event-stream`): `POST /api/ssh/servers/{id}/terminal` → `{session_id}`; `GET .../terminal/{sid}/stream` (SSE output, `_generate_pty`-shaped frames: `data: {"stream": "stdout"|"stderr", "data": ...}` … `data: {"exit_code": N}`); `POST .../terminal/{sid}/input {data}` (keystrokes/stdin); `POST .../terminal/{sid}/resize {cols, rows}`; `DELETE .../terminal/{sid}` (close). Limits: max 3 open sessions per user, 10-min idle kill, disconnect surfaced as an `exit_code` frame; `sudo` prompts pass through live (no app-side injection). Rationale: `_generate_pty` spawns a *local* shell, so remote PTY is new relay work reusing only the SSE frame shapes. Windows native degrades to one-shot with the existing `PTY_UNSUPPORTED_ERROR` message pattern.
- **File transfer:** `upload(local_path, remote_path)` / `download(remote_path)` scoped to the agent workspace / `data/` allow-list on the local side (reuse `_resolve_tool_path`); remote side is the login user's own filesystem (server enforces).

### 6.4 "Unblocked by design" checklist
- [ ] `bash` command-string filter (if any is added later) must **allow** `ssh`/`scp`/`sftp` tokens; no denylist entry for them. (No such filter exists today — this is a forward-guard, not a current behavior change.)
- [ ] New `ssh_exec` tool is **not** in `NON_ADMIN_BLOCKED_TOOLS`; it **is blocked in plan mode** (DECIDED — like `bash`/`python`, remote execution mutates; add to `_PLAN_MODE_KNOWN_MUTATORS` and keep out of `PLAN_MODE_READONLY_TOOLS`).
- [ ] Narrow `.ssh` exception: only app-managed `data/ssh` paths (`<owner>_ed25519*`, `known_hosts.d/<server_id>`) bypass `_is_sensitive_path`; the user's real `~/.ssh/authorized_keys`, `~/.ssh/config` stay blocked; tests added for both sides.
- [ ] `app_api` (which is a **blocklist**, not allow-list: `_APP_API_BLOCKLIST_PREFIXES` + `_APP_API_BLOCKLIST_METHOD_PATH` in `src/tool_implementations.py:2220-2248`): new `/api/ssh/servers/*` exec/terminal/transfer routes must be **added to the method-path blocklist** (POST exec/upload, terminal WS/SSE) so the generic loopback cannot reach them — the agent must use the named `ssh_exec` tool instead (same pattern as `/api/model/serve`, `/api/cookbook/kill-pid`). Read-only list/test endpoints may stay reachable; `GET /api/ssh/servers` returns no secrets either way. Existing `test_app_api_blocks_*` tests in `tests/test_review_regressions.py` get new cases.
- [ ] Docker + native both verified (see §9).
- [ ] Caps (DECIDED): one-shot default timeout 30s, hard cap 120s; output truncated per `MAX_OUTPUT_CHARS`; rate-limit exec/test per user (e.g. 30/min, 429 on excess); max 3 concurrent interactive terminals per user with 10-min idle kill.

## 7. Security & threat-model considerations (must-read for implementer)

### 7.0 Gate matrix (DECIDED — the full change surface)

| Surface | Today | After this spec | Enforcing code |
|---|---|---|---|
| Agent one-shot (`ssh_exec` named tool) | n/a (no tool) | Any authenticated user on **own** servers only; **blocked in plan mode** | `src/tool_security.py` (`NON_ADMIN_BLOCKED_TOOLS` stays shut, add to `_PLAN_MODE_KNOWN_MUTATORS`), owner-scoped server lookup |
| `bash`-issued `ssh`/`scp`/`sftp` | Allowed for admins (no string filter), blocked for non-admins (whole `bash` blocked) | **Unchanged**: admins keep it, non-admins still have no `bash` — they use `ssh_exec` instead | no `bash` string-filter change |
| Human exec API `POST /api/ssh/servers/{id}/exec` | n/a | Any authenticated user, owner-scoped row check, rate-limited | new `routes/ssh_routes.py` (owner filter + 429) |
| Interactive terminal `WS/SSE /api/ssh/servers/{id}/terminal` | n/a (local-only PTY in `shell_routes`, `_require_admin` = admin-only) | Any authenticated user on own servers; **local shell PTY stays admin-only** (`routes/shell_routes._require_admin` untouched) | new route, separate from `shell_routes` |
| File transfer upload/download | n/a | Any authenticated user, local side confined to workspace/`data/` via `_resolve_tool_path`, remote side = login user's own fs | new route + resolver |
| Scheduled tasks (`run_local`/`run_script`/`ssh_command`) | Admin-only (`routes/task_routes._ADMIN_ONLY_ACTIONS`, 403 for non-admins) | **Unchanged in MVP** (stays admin-only; opening scheduled remote exec is a follow-up with its own review) | no change |
| Generic loopback `app_api` | Blocklist-gated (`_APP_API_BLOCKLIST_*`) | New exec/terminal/transfer paths **added to the blocklist** (agent must use `ssh_exec`) | `src/tool_implementations.py:2220-2248` + new `test_app_api_blocks_ssh_*` |
| Audit | none | Every test/exec/terminal-open/transfer appends owner, server id, timestamp, command hash, exit code — never secrets (new `ssh_audit_log` table or append-only log; retention e.g. 90 days, admin-readable) | new model + writer |

Threat-model delta (for the `THREAT_MODEL.md` amendment): non-admins gain **scoped remote execution as their own remote login user** — not local shell. Compensating controls: owner-scoped rows, `EncryptedText` secrets, audit log, argv-only construction + `validate_remote_host`/`validate_ssh_port`, pinned TOFU fingerprints, timeouts/rate-limits/caps, prompt-injection wrapping of remote output.

- **Deliberate tension with current model.** `THREAT_MODEL.md` says non-admins get no shell/files and the agent loop enforces it via `owner_is_admin_or_single_user`. This feature **intentionally punches a scoped hole**: any user gets *remote* execution as *their own* remote login user. The app's `bash` gate stays; the new tool is a separate, per-server, owner-scoped capability.
- **Why this is defensible (and what must compensate):**
  - Remote host re-authenticates the user (key/password) — the app never mints remote privilege; `sudo` is checked **by the server** per user answer.
  - Compensating controls (required): per-owner server isolation, encrypted secrets, **audit log** of every connect/one-shot/transfer (who, which server, when, command hash, exit code — never secret values), rate-limit + timeout, host validation via `_ssh_exec_argv`, accept-on-first-use fingerprint **shown + pinned** after first success (log fingerprint; warn on change).
- **Prompt-injection.** Remote command strings and remote file contents are **untrusted**: route outputs through `src/prompt_security.py: untrusted_context_message` like web/email content. Never let remote output auto-execute as further tool calls without user/agent confirmation boundary.
- **SSRF/pivot.** SSH to arbitrary user-supplied hosts from the server is inherent to the feature. Mitigations: connections only to **saved, owner-scoped servers** (no ad-hoc `ssh_exec(host=…)` to unsaved hosts — agent must reference a saved server id/label), optional admin setting to restrict CIDR/host patterns (defer to follow-up if time is short, but leave the hook).
- **Secrets hygiene.** Follow `SECURITY.md`: never log passwords/keys, never echo private key material to chat outputs, `0600`/`0700` perms, no secrets in URLs or list endpoints.

## 8. UX proposal (Cookbook → Servers extension)

- Placement (DECIDED): new **"My servers"** section alongside — not merged into — the existing Cookbook → Servers list (which stays the shared GPU-infra list with its shared `remoteHost` default). Rows gain: `Test` button (runs `true`, captures + shows latency/fingerprint for TOFU confirm), status dot, `Connect` (terminal, Phase 2) + `Run` (one-shot, Phase 1) actions.
- Add/edit modal fields: Label, Host, Port (22), Username, Auth type radio (Key / Password / Both), Password (optional, placeholder "unchanged" on edit), Sudo password (optional), Generate-key + Show-public-key + Copy + `ssh-copy-id` hint box.
- First-run empty state: "No servers yet — Add your first server" (satisfies "no signup friction").
- Terminal view: reuse shell-panel PTY streaming; title shows `user@host:port (label)`; explicit Disconnect.
- Errors in plain language: bad host, timeout, auth failed (no secret leakage), host-key-changed warning.

## 9. Out-of-the-box / platform requirements

- **Docker:** `openssh-client` already in `Dockerfile` — keep + assert in build test; `./data/ssh:/app/.ssh:z` mounts already in all three compose files — keep; entrypoint ensures dir exists, perms `0700`, key auto-gen (`ssh-keygen -t ed25519`) if missing; container runs as expected UID (existing `entrypoint.sh` ownership repair covers it).
- **Native Linux/macOS:** detect `ssh` at startup; if missing, show one-line install hint (`apt install openssh-client` / `xcode-select --install` note for macOS where `ssh` ships by default); key auto-gen in `data/ssh` same as Docker.
- **Windows (best-effort):** `routes/shell_routes.py` has no PTY on native Windows — one-shot + transfer must still work (via bundled OpenSSH), interactive terminal may degrade to one-shot with a clear message (mirror `PTY_UNSUPPORTED_ERROR` pattern).
- **Offline behavior:** server CRUD works with no network; only Test/Connect/Run dial out; connection failures return actionable errors, never stack traces.

## 10. Data / API sketch (non-binding, for estimation)

- Storage: DECIDED — new `ssh_servers` (+ optional `ssh_audit_log`) tables in `core/database.py` with `EncryptedText` secret columns (see §6.1). Explicitly NOT `cookbook_state.json` (global, no owner column, whole-file-overwrite hazard that `app_api` blocklists for good reason).
- Suggested endpoints (all auth-required, owner-scoped):
  - `GET /api/ssh/servers` (no secrets), `POST /api/ssh/servers`, `PATCH /api/ssh/servers/{id}`, `DELETE /api/ssh/servers/{id}`
  - `POST /api/ssh/servers/{id}/test`, `POST /api/ssh/servers/{id}/exec` (one-shot), `GET /api/ssh/servers/{id}/pubkey`
  - Terminal, Phase 2 (paramiko `invoke_shell`; SSE frame shapes mirror `_generate_pty`): `POST /api/ssh/servers/{id}/terminal` → `{session_id}`; `GET .../terminal/{sid}/stream`; `POST .../terminal/{sid}/input {data}`; `POST .../terminal/{sid}/resize {cols, rows}`; `DELETE .../terminal/{sid}`
  - `POST /api/ssh/servers/{id}/upload`, `GET /api/ssh/servers/{id}/download`
- Agent tool schema sketch: `ssh_exec { server: string, cmd: string, timeout?: number, stdin?: string }`.

## 11. Acceptance criteria

- [ ] AC1 — Fresh `docker compose up --build` (and native venv): SSH Servers UI reachable, "Add server" works with zero prior SSH setup; key auto-generated; `ssh` binary present.
- [ ] AC2 — Full loop against a test SSH host (new `sshd` fixture or `host.docker.internal` test account — no such fixture exists today, budget test-infra work): add (host/user/key) → Test green + fingerprint pinned → one-shot `echo ok` → upload+download round-trip → delete. Interactive echo moves to Phase-2 acceptance. Password-auth loop is Phase-2 acceptance (after `paramiko` lands).
- [ ] AC3 — "Unblocked" proofs: no `bash` string filter denies `ssh`/`scp`/`sftp` (forward-guard regression test — vacuously true today since no filter exists); `ssh_exec` callable by **non-admin** on **own** server and **blocked in plan mode**; managed-key show/generate works despite the `.ssh` deny-list; arbitrary `~/.ssh/authorized_keys` read/write still **blocked** (negative test).
- [ ] AC4 — Cross-owner isolation: user B cannot exec via user A's server id (403/blocked test, cf. `test_companion_readonly.py`).
- [ ] AC5 — Sudo semantics: command needing elevation fails cleanly without stored sudo password (remote stderr surfaced); succeeds when correct sudo password stored; wrong sudo password surfaces remote failure with no secret in logs/output.
- [ ] AC6 — Host-key behavior: first connect succeeds (TOFU), fingerprint recorded; changed-key connect warns/refuses per decided policy.
- [ ] AC7 — Audit: every connect/exec/transfer appends owner, server id, timestamp, command hash, exit code; no passwords/keys in logs or chat transcripts.
- [ ] AC8 — Regression: existing suites for path confinement (`test_tool_path_confinement.py`, `test_workspace_confine.py`), tool policy (`test_tool_policy.py`), review regressions (`test_review_regressions.py`), shell routes (`test_shell_routes.py`) still pass; new tests added for §6.4 checklist.

## 12. Test plan (suggested)

- Unit: host/port validation (`_ssh_exec_argv` reuse), server CRUD owner-scoping, secret redaction in serializers, `.ssh`-exception allow/deny matrix, audit writer.
- Integration (resolves L3): one-shot exec + timeout + truncation; terminal open/input/resize/close over the §6.3 protocol; upload/download round-trip; sudo with/without password; TOFU fingerprint pin + change detection. Remote-backed cases run under a new `tests/helpers/ssh_fixture.py` — resolution order: (1) `SSHD_TEST_HOST` env (CI-provided `user@host` + key), else (2) temp local `sshd` on 127.0.0.1 (host key + `authorized_keys` in `tmp_path`, only if `ssh`/`sshd` binaries exist), else (3) `pytest.skip`. Remote cases marked `ssh_integration`; pure-logic cases (validation, redaction, audit writer) use fakes and always run.
- Security: non-admin allowed-own / denied-other, plan-mode blocked (assert `ssh_exec` in `plan_mode_disabled_tools()`), prompt-injection wrapping of remote output, `authorized_keys`/`config` still denied, secrets absent from logs (grep test).
- Platform: Docker build asserts `ssh` present; native missing-`ssh` hint path; Windows PTY-degraded path.

## 13. Open questions — RESOLVED except where noted

1. `ssh_exec` in **plan mode**: DECIDED — **blocked** (like `bash`); add to `_PLAN_MODE_KNOWN_MUTATORS` (§6.4).
2. Password auth transport: DECIDED — **Phase 1 key-only via OpenSSH argv (no new deps); Phase 2 `paramiko`** in `requirements.txt` for password + SFTP; `sshpass` **rejected** (`ps`/`/proc` exposure + new apt layer). See §6.2.
3. Ad-hoc hosts: DECIDED — **saved-servers-only** (agent takes server id/label, never a raw host; no one-off host even with confirmation) — bounds SSRF/pivot.
4. Admin CIDR/host-pattern restriction: DECIDED — resolves L4. New admin-only setting `ssh_allowed_host_patterns` in `DEFAULT_SETTINGS` (`src/settings.py`, next to `tool_path_extra_roots`): default `[]` = allow any saved host; entries are fnmatch globs over `user@host:port` plus CIDR ranges matched via stdlib `ipaddress`; read via `get_setting` and enforced at server-create, test, and exec (400 "host not permitted by admin policy"). Settings UI row is admin-only; no per-server UI in MVP.
5. Per-user vs. per-server keypairs: DECIDED — **per-user** (`data/ssh/<owner>_ed25519`, §6.1).

## 14. Remaining limitations — ALL RESOLVED (decisions below; § references are normative)

- **L1 — RESOLVED (§6.2):** password login + SFTP via `paramiko` wrapper (RejectPolicy + manual pin check, `asyncio.to_thread`, secrets as API args only); `sshpass` stays rejected. Phase 1 remains key-only; UI labels password auth "coming soon" until Phase 2.
- **L2 — RESOLVED (§6.3, §10):** terminal protocol fixed — open/stream/input/resize/close over SSE with `_generate_pty`-shaped frames, paramiko `invoke_shell` transport, 3 sessions/user, 10-min idle kill.
- **L3 — RESOLVED (§12):** `tests/helpers/ssh_fixture.py` with env → temp-local-`sshd` → skip chain, `ssh_integration` mark; logic tests on fakes always run.
- **L4 — RESOLVED (§13 Q4):** admin-only `ssh_allowed_host_patterns` setting (glob + CIDR via `ipaddress`), enforced at create/test/exec.
- **L5 — RESOLVED as spec text (§16):** exact roles-table row, subsection placement, and `SECURITY.md` bullet defined; file edits land in the implementing PR, not before.
- **L6 — RESOLVED (§6.1):** rotation = `.new` → atomic rename → one `.bak` → audit `key_rotated`; revocation = delete row + `known_hosts.d/<id>` + audit; compromise = rotate + clear pins (force re-TOFU). No schema change.

## 15. DB model drafts (for `core/database.py` — follow `EmailAccount` / `ApiToken` conventions)

Notes: `TimestampMixin` supplies `created_at`/`updated_at` (`utcnow_naive`); `EncryptedText` transparently Fernet-encrypts at rest via `src/secret_storage` (key at `data/.app_key`, `0600`); `owner` is nullable + indexed (NULL = legacy/shared, same semantics as `sessions.owner` / `model_endpoints.owner`); tables are auto-created by `init_db()` → `Base.metadata.create_all` (no separate migration needed for new tables — migrations like `_migrate_encrypt_endpoint_keys` only cover new columns on old tables). `server_id` on the audit table is a plain indexed String (no FK) so audit rows survive server deletion.

```python
class SshServer(TimestampMixin, Base):
    """Owner-scoped saved SSH server. Secrets encrypted at rest.

    Key material itself lives in data/ssh/<owner>_ed25519(.pub) (0600/0700);
    only the filename is stored here. Fingerprint pinning per §6.2."""
    __tablename__ = "ssh_servers"

    id             = Column(String, primary_key=True, index=True)
    owner          = Column(String, nullable=True, index=True)
    label          = Column(String, nullable=False)
    host           = Column(String, nullable=False)
    port           = Column(Integer, default=22, nullable=False)
    username       = Column(String, nullable=False, default="")
    auth_type      = Column(String, nullable=False, default="key")  # key | password | both
    password       = Column(EncryptedText, nullable=True)   # login password (Phase 2)
    sudo_password  = Column(EncryptedText, nullable=True)   # optional escalation (Phase 2)
    ssh_key_ref    = Column(String, nullable=True)          # e.g. "<owner>_ed25519"
    host_key_fingerprint = Column(String, nullable=True)    # pinned TOFU fingerprint
    last_tested_at = Column(DateTime, nullable=True)
    last_test_result = Column(String, nullable=True)        # e.g. "ok" / error short string

    __table_args__ = (
        Index('ix_ssh_servers_owner_label', 'owner', 'label'),
    )


class SshAuditLog(TimestampMixin, Base):
    """Append-only audit of SSH test/exec/terminal/transfer events.

    Never stores secrets — command text is stored as a SHA-256 hash."""
    __tablename__ = "ssh_audit_log"

    id           = Column(String, primary_key=True, index=True)
    owner        = Column(String, nullable=True, index=True)
    server_id    = Column(String, nullable=True, index=True)  # no FK: survives deletion
    event        = Column(String, nullable=False)  # test | exec | terminal_open | upload | download
    command_hash = Column(String, nullable=True)   # SHA-256 hex of command text, if any
    exit_code    = Column(Integer, nullable=True)

    __table_args__ = (
        Index('ix_ssh_audit_owner_created', 'owner', 'created_at'),
    )
```

Retention: e.g. 90 days (periodic prune job or on-read cutoff); reads admin-scoped (admins all, users own rows only).

## 16. THREAT_MODEL.md amendment — draft text (apply in the implementing PR, per L5)

> ### SSH remote execution (scoped non-admin capability)
>
> Saved SSH servers (`ssh_servers`, owner-scoped rows) let **any authenticated
> user** run commands on **their own** remote hosts via the named `ssh_exec`
> tool and the `/api/ssh/*` routes. This is an intentional, scoped exception
> to the admin-only shell rule: it grants **remote** execution as the user's
> own remote login — never local shell. `bash`/`python`, the local PTY
> (`/api/shell/*`), and scheduled shell actions (`run_local`/`run_script`/
> `ssh_command`) **stay admin-only**.
>
> Compensating controls (all required): per-owner row isolation (cross-owner
> use denied), `EncryptedText` secrets, append-only `ssh_audit_log` (no
> secret values), argv-only SSH construction validated by
> `validate_remote_host`/`validate_ssh_port`, pinned TOFU host fingerprints
> (fail closed on change), timeouts/truncation/rate-limits, `ssh_exec`
> blocked in plan mode, remote outputs treated as untrusted
> (`untrusted_context_message`), and the exec/terminal/transfer routes added
> to the `app_api` blocklist so only the named tool reaches them.
> `sudo` authority stays with the remote host. The legacy `rsh` protocol is
> out of scope and must not be added.

Placement (resolves L5 — apply in the implementing PR, not before):
- `THREAT_MODEL.md` roles table: add row `| SSH remote execution (own saved servers) | ✓ | ✓ (own only, named tool) |`; insert the quoted subsection above as `### SSH remote execution` immediately after the `## Internal Tool Loopback` section.
- `SECURITY.md` Deployment Guidance: append bullet `- Treat saved SSH servers as personal credentials: users may only reach their own servers; review \`ssh_audit_log\` on shared or serious deployments.`

## 17. Phased implementation tasks

- **Phase 0 — test infra + key plumbing:** `tests/helpers/ssh_fixture.py` (env → temp local `sshd` → skip) + `ssh_integration` mark; `data/ssh` dir ensure (`0700`) + per-user `ssh-keygen -t ed25519` auto-gen; Docker build assertion that `ssh` exists.
- **Phase 1 — key-only MVP:** `SshServer` + `SshAuditLog` tables; `routes/ssh_routes.py` CRUD + test + exec + upload/download (key auth via OpenSSH argv, pinned `UserKnownHostsFile`, `validate_remote_host`/`validate_ssh_port`, owner filter, rate-limit); `ssh_exec` agent tool (non-admin allowed, plan-mode blocked, saved-server-id/label only); `app_api` blocklist additions + `test_app_api_blocks_ssh_*`; narrow `data/ssh` exception to `_is_sensitive_path`; "My servers" UI (add/edit/delete/test/run, pubkey show/copy, `ssh-copy-id` hint, TOFU fingerprint confirm); audit writer; AC1–AC4, AC6–AC8 (key paths) + §12 unit/integration/security suites.
- **Phase 2 — password + terminal:** `paramiko` dep + wrapper (RejectPolicy + manual pin check, `to_thread`); password login, SFTP transfer, `sudo -S` stdin-pipe path for one-shot; terminal protocol per §6.3 (open/stream/input/resize/close, 3-session cap, 10-min idle kill) + Windows degrade message; AC5 + interactive acceptance.
- **Follow-ups (not MVP):** server sharing; audit retention job; opening scheduled `ssh_command` to non-admins (own review). (Host-pattern setting, rotation, and fixture are now specified — Phase 0–2.)

## 18. Appendix — key file references

- `src/tool_security.py` (blocked tools, plan-mode allow-list)
- `src/tool_execution.py` (`_SENSITIVE_*`, `_resolve_tool_path`, `execute_tool_block`, `agent_cwd`)
- `src/tool_implementations.py` (`_resolve_cookbook_host`, `do_serve_model`, serve-cmd allow-list hint)
- `src/tool_index.py` / `src/tool_schemas.py` (`app_api` blocked-paths description)
- `core/platform_compat.py` (`_ssh_exec_argv`, `run_ssh_command`)
- `routes/shell_routes.py` (PTY streaming, `_ssh_base_argv`, `PTY_SUPPORTED`)
- `routes/cookbook_helpers.py: _validate_serve_cmd`, `routes/cookbook_routes.py`, `routes/codex_routes.py:400,520`
- `services/hwfit/hardware.py` (SSH `_run`), `src/cookbook_serve_lifecycle.py:94-104`
- `THREAT_MODEL.md`, `SECURITY.md`, `README.md` (Cookbook SSH key section), `.env.example:153`
- `Dockerfile` (openssh-client), `docker-compose.yml` (+ gpu overlays: `data/ssh` mount)
- Tests: `test_tool_path_confinement.py`, `test_workspace_confine.py`, `test_tool_policy.py`, `test_review_regressions.py`, `test_shell_routes.py`, `test_platform_compat.py`, `test_cookbook_same_host_server_profiles_js.py`
- DB conventions: `core/database.py` (`TimestampMixin:22`, `EncryptedText:58`, `EmailAccount:294`, `ApiToken:447`, `init_db:1726`, `_migrate_encrypt_endpoint_keys:1901`); secrets: `src/secret_storage.py`; validators: `routes/_validators.py`; gates: `routes/task_routes.py:419` (`_ADMIN_ONLY_ACTIONS`)
