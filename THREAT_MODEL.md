# Threat Model

Odysseus is a **self-hosted AI workspace with privileged local access**. This document states the trust boundary so contributors can reason about security decisions without reading through the full auth and middleware stack.

## Trust Boundary

Odysseus is designed for **trusted users on a private network**, not public exposure. The README describes it as "treat it like an admin console" — that framing is accurate. A logged-in admin can execute shell commands, read and write files, send email, and control model serving. This is intentional. The threat model does not try to prevent admins from doing these things. It does try to prevent:

- Unauthenticated access
- Non-admins reaching admin-only capabilities
- The AI agent acting on instructions injected through untrusted content (web results, emails, fetched pages, memories)
- Internal services (ChromaDB, Ollama, SearXNG, etc.) being reachable from outside the host

## Roles and Capabilities

| Capability | Admin | Non-admin (default) |
|---|---|---|
| Chat with agent | ✓ | ✓ |
| Browser tool | ✓ | ✓ |
| Documents | ✓ | ✓ |
| Research mode | ✓ | ✓ |
| Image generation | ✓ | ✓ |
| Memory management | ✓ | ✓ |
| Shell / Python execution | ✓ | ✗ |
| File read / write | ✓ | ✗ |
| Email send / read | ✓ | ✗ |
| MCP tools | ✓ | ✗ |
| Calendar management | ✓ | ✗ |
| Token / webhook management | ✓ | ✗ |
| Model serving | ✓ | ✗ |
| Vault | ✓ | ✗ |
| Settings | ✓ | ✗ |
| SSH remote execution (own saved servers) | ✓ | ✓ (own only, named tool) |
| SSH interactive terminal (own saved servers) | ✓ | ✓ (own only) |

Non-admin defaults are in `core/auth.py:DEFAULT_PRIVILEGES`. Tool enforcement is in `src/tool_security.py:NON_ADMIN_BLOCKED_TOOLS`. Any tool whose name starts with `mcp__` is also blocked for non-admins. Admins always get full access regardless of stored privilege values.

## Authentication

- **Sessions:** bcrypt passwords, 7-day session tokens stored atomically in `data/sessions.json` via `core/atomic_io.py`.
- **2FA:** TOTP with 8 single-use backup codes. Verified after password check, before session issuance.
- **Reserved usernames:** request sentinels and the Default/Local storage owner cannot be registered or renamed into. Defined in `core/auth.py:RESERVED_USERNAMES`.
  - `internal-tool` is security-critical: `core/middleware.py:require_admin` treats any request where `request.state.current_user == "internal-tool"` as the in-process tool loopback and grants admin unconditionally. A real account with that name would silently pass every `require_admin` check.
- **Orphan sessions:** `validate_token` re-checks that the user record still exists on every call. A deleted user's cookie is dropped on next request rather than continuing to authenticate.

## Internal Tool Loopback

Agent tool calls reach admin-gated HTTP routes over an in-process HTTP loopback. The mechanism:

1. At app startup, `core/middleware.py` generates a random `INTERNAL_TOOL_TOKEN` via `secrets.token_hex(32)`. It is never persisted and never sent to clients.
2. Loopback requests carry `X-Odysseus-Internal-Token: <token>` or have `request.state.current_user` already set to `"internal-tool"` by the auth middleware.
3. `require_admin` recognises either signal and grants access without checking the session user.

The agent may be running in a non-admin user's session, but tool dispatch first calls `src/tool_security.py:owner_is_admin_or_single_user` to verify the session owner is an admin before issuing any loopback call. Non-admin users cannot invoke admin tools even via the agent.

### SSH remote execution (scoped non-admin capability)

Saved SSH servers (`ssh_servers`, owner-scoped rows in `core/database.py`) let **any authenticated user** run commands on **their own** remote hosts via the named `ssh_exec` tool, the `/api/ssh/*` routes, and an interactive **remote** terminal. This is an intentional, scoped exception to the admin-only shell rule: it grants **remote** execution as the user's own remote login — never local shell. `bash`/`python`, the local PTY (`/api/shell/*`), and scheduled shell actions (`run_local`/`run_script`/`ssh_command`) **stay admin-only**.

Compensating controls (all required): per-owner row isolation (cross-owner use denied), `EncryptedText` secrets, append-only `ssh_audit_log` (command text only as a SHA-256 hash — never secret values), argv-only SSH construction validated by `validate_host`/`validate_port` in `src/ssh_remote.py`, pinned TOFU host fingerprints that fail closed on change, timeouts/output truncation/per-user rate limits, `ssh_exec` blocked in plan mode, remote outputs wrapped as untrusted via `src/prompt_security.py:wrap_untrusted_text`, and the exec/transfer/terminal routes added to the `app_api` blocklist in `src/tools/system.py` so only the named tool and the UI reach them. `sudo` authority stays with the remote host — the app never mints remote privilege. The legacy `rsh` protocol is out of scope and must not be added.

**Password auth, SFTP, and the terminal** (`src/ssh_client.py`, paramiko) extend the same capability to servers that do not accept a key. Additional controls: the password is passed only as a `paramiko` `connect(password=...)` argument — never on a command line and never in the environment (`sshpass` is deliberately not used, because `-p` is visible in `ps` and `-e` in `/proc/<pid>/environ`); the stored host-key pin is enforced **before** authentication, so a credential is never offered to a host that fails its pin, and a server whose host or port is edited has its pin dropped rather than carried over; SFTP transfers are scoped to the same workspace-resolved local path as the SCP path; the terminal is a relayed PTY on a saved server, capped at 3 sessions per user with a 10-minute idle kill, its SSE stream and input channel are *refused* by the generic `app_api` loopback in both directions, and a dropped browser closes the remote session. Terminal sessions live in memory only, so a restart drops them.

**TOFU capture.** `ssh-keyscan` is invoked with an explicit `-t rsa,ecdsa,ed25519` list. Its default probe set now includes smartcard and hybrid ML-DSA types that a normal host key never matches, and it opens one connection per type; OpenSSH ≥ 9.8 counts those against `PerSourcePenalties` and will begin dropping connections from this host — including the app's own. Pinning asks only for the three classic types.

## Prompt-Injection Hardening

External content that reaches the LLM is treated as untrusted via `src/prompt_security.py`:

- `untrusted_context_message(label, content)` wraps the content in a `user`-role message with a header block instructing the model not to follow instructions inside it. Content goes in as data, not as a system instruction.
- `UNTRUSTED_CONTEXT_POLICY` is a system-prompt preamble that states the same policy at the top of every session where untrusted data may appear.

**Untrusted surfaces that must go through this wrapper:** web search results, fetched URLs, emails (read), saved memories, skill text, notes, and any tool output sourced from outside the server. Injecting untrusted content directly into the system role is a security bug.

## Security Headers

`core/middleware.py:SecurityHeadersMiddleware` sets headers on every response:

- `X-Frame-Options: DENY` + `frame-ancestors 'none'` on all routes except tool-render iframes (which are sandboxed at the HTML level).
- `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` everywhere.
- **CSP:** nonce-based `script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net`. `style-src 'unsafe-inline'` is intentionally kept — `static/index.html` ships inline `<style>` blocks and JS modules set `style=""` attributes at runtime. Inline styles do not execute script so the risk is visual-only. Removing this requires templating the HTML files and auditing all JS-set style attributes.

## Known Gaps

These are open, acknowledged, and contributor help is welcome:

1. **No shell/filesystem sandbox.** The agent `bash` and `read_file`/`write_file` tools run as the app process user with no network egress filtering or filesystem confinement. A successful prompt-injection reaching a shell-enabled admin session can make outbound requests to internal services. See #1058 for the sandbox proposal.

2. **SSRF via `/api/v1/chat` `base_url` parameter.** A chat-scoped API token can supply an arbitrary `base_url`; the server forwards the LLM request to that host without validating the scheme or address. PR #1039 fixes this.

3. **`src/search/` partial consolidation.** `src.search.core` and `src.search.providers` correctly alias `services.search` via `sys.modules` replacement. `analytics`, `cache`, `content`, `query`, and `ranking` are still independent copies that can drift. The SSRF regression tests in `tests/test_webhook_ssrf_resilience.py` test `src.webhook_manager` directly (separate from search), so the safety net there is intact. See #1058.

4. **Token scopes are coarse.** There is no way to grant a session a subset of the owning user's privileges. Companion/mobile tokens carry either `chat` or `admin` scope with no per-capability granularity.
