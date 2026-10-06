#!/usr/bin/env bash
#
# Odysseus — one-command deploy, with or without Docker.
#
#   ./deploy.sh                 # auto: Docker Compose when it is usable, else native
#   ./deploy.sh --docker        # Docker Compose (recommended on Linux)
#   ./deploy.sh --native        # native venv + uvicorn, no Docker
#
# Verbs (first non-flag argument; default: deploy):
#   deploy    prepare and start (re-running is safe)
#   stop      stop the app (and the local ChromaDB in native mode)
#   restart   stop, then deploy
#   status    show what is running and whether the UI answers
#   logs      follow the application log
#   update    pull the latest code, then redeploy
#
# Flags:
#   --auto | --docker | --native  pick the mode (default: auto)
#   --optional                    Docker: build locally with INSTALL_OPTIONAL=true
#                                 (adds AGPL-licensed extras — see requirements-optional.txt)
#   --no-build                    Docker: start the published image instead of
#                                 building from this checkout
#   --image REF                   Docker: run this image, e.g. the immutable
#                                 ghcr.io/odysseus-dev/odysseus:1.0.2-7c8070f
#                                 (implies --no-build; production deployments
#                                 should pin a tag, since :latest moves)
#   --foreground                  native: stay attached instead of daemonising
#   --no-chromadb                 native: do not start a local ChromaDB
#   --with-chromadb               native: install the full `chromadb` package when no
#                                 local server binary is present (a large download; see
#                                 the ChromaDB note further down)
#   --systemd                     native: also write a systemd unit for you to install
#   --host HOST                   bind address (default: APP_BIND from .env, else 127.0.0.1)
#   --port PORT                   port (default: APP_PORT from .env, else 7000)
#   --dry-run                     print every command instead of running it
#   -h | --help                   this text
#
# Environment overrides: ODYSSEUS_MODE, ODYSSEUS_HOST, ODYSSEUS_PORT
#
# Every step is idempotent and nothing here deletes data. The script never
# rewrites an existing .env, and it never runs sudo: when a step needs root it
# prints the exact command instead.
#
# Why the native path exists at all: Cookbook serves models on whatever machine
# Odysseus runs on, and Docker on macOS is a Linux VM with no access to the
# Metal GPU. On Linux, Docker Compose is the recommended path — it starts
# ChromaDB, SearXNG and ntfy alongside the app.
#
# ChromaDB: Docker starts it for you. Native mode starts a local ChromaDB only
# when a `chroma` server binary is already present, because requirements.txt
# ships the HTTP-only chromadb-client (which can only talk to a server someone
# else runs, and which must not be installed alongside the full package). Pass
# --with-chromadb to install the full package, or --no-chromadb to manage the
# vector store yourself.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

ENV_FILE="$REPO_DIR/.env"
PID_DIR="$REPO_DIR/data/run"
APP_PID_FILE="$PID_DIR/odysseus.pid"
CHROMA_PID_FILE="$PID_DIR/chromadb.pid"
LOG_DIR="$REPO_DIR/logs"
APP_LOG="$LOG_DIR/odysseus.log"
CHROMA_LOG="$LOG_DIR/chromadb.log"

DRY_RUN=0
OPTIONAL=0
NO_BUILD=0
IMAGE_REF=""
FOREGROUND=0
WRITE_SYSTEMD=0
START_CHROMADB=1
INSTALL_CHROMADB=0
MODE="${ODYSSEUS_MODE:-}"
VERB="deploy"
HOST_OPT=""
PORT_OPT=""

VERBS="deploy stop restart status logs update"

log()  { printf '%s\n' "$*"; }
step() { printf '\n▶ %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*" >&2; }
die()  { printf '\n✗ %s\n' "$*" >&2; exit 1; }

usage() {
    # Print the header comment block (everything after the shebang) as help.
    sed -n '3,/^set -euo pipefail/p' "${BASH_SOURCE[0]}" \
        | sed '$d' | sed 's/^# \{0,1\}//'
}

# Run a command, or describe it under --dry-run. Mutating steps go through this
# so `./deploy.sh --dry-run` is a faithful preview of a real run.
run() {
    if [ "$DRY_RUN" = 1 ]; then
        printf '   [dry-run] %s\n' "$*"
        return 0
    fi
    "$@"
}

have() { command -v "$1" >/dev/null 2>&1; }

# Read one KEY=value out of .env without exporting the whole file. The app
# parses .env itself (python-dotenv) for everything it needs; this script only
# consults the handful of deployment-level keys that decide *where* to bind.
# Commented lines (`# APP_PORT=7000`) intentionally do not match, so defaults
# apply until the operator uncomments them.
env_value() {
    local key="$1" line=""
    [ -f "$ENV_FILE" ] || return 0
    line="$(grep -E "^[[:space:]]*${key}=" "$ENV_FILE" 2>/dev/null | tail -1 || true)"
    [ -n "$line" ] || return 0
    line="${line#*=}"
    line="${line%$'\r'}"
    case "$line" in
        \"*\") line="${line#\"}"; line="${line%\"}" ;;
        \'*\') line="${line#\'}"; line="${line%\'}" ;;
    esac
    printf '%s' "$line"
}

port_open() { (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null; }

wait_for_port() {
    local host="$1" port="$2" tries="${3:-90}" i
    for ((i = 0; i < tries; i++)); do
        port_open "$host" "$port" && return 0
        sleep 1
    done
    return 1
}

pid_alive() {
    local file="$1" pid=""
    [ -f "$file" ] || return 1
    pid="$(cat "$file" 2>/dev/null || true)"
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

# ---------------------------------------------------------------- arguments --
while [ $# -gt 0 ]; do
    case "$1" in
        --auto)   MODE=auto;   shift ;;
        --docker) MODE=docker; shift ;;
        --native) MODE=native; shift ;;
        --optional)   OPTIONAL=1;      shift ;;
        --no-build)   NO_BUILD=1;      shift ;;
        --image) [ $# -ge 2 ] || die "--image needs a value"; IMAGE_REF="$2"; shift 2 ;;
        --image=*)    IMAGE_REF="${1#*=}"; shift ;;
        --foreground|--fg) FOREGROUND=1; shift ;;
        --no-chromadb)   START_CHROMADB=0;   shift ;;
        --with-chromadb) INSTALL_CHROMADB=1; shift ;;
        --systemd)       WRITE_SYSTEMD=1;    shift ;;
        --dry-run)    DRY_RUN=1;       shift ;;
        --host) [ $# -ge 2 ] || die "--host needs a value"; HOST_OPT="$2"; shift 2 ;;
        --host=*)  HOST_OPT="${1#*=}"; shift ;;
        --port) [ $# -ge 2 ] || die "--port needs a value"; PORT_OPT="$2"; shift 2 ;;
        --port=*)  PORT_OPT="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown argument: $1 (try --help)" ;;
        *)
            case " $VERBS " in
                *" $1 "*) VERB="$1"; shift ;;
                *) die "unknown verb: $1 (expected one of: $VERBS)" ;;
            esac
            ;;
    esac
done

MODE="${MODE:-auto}"

# --------------------------------------------------------------- resolution --
# Precedence matches start-macos.sh and app.py: an exported ODYSSEUS_* / APP_*
# beats .env, which beats the built-in default.
BIND="$HOST_OPT"
[ -n "$BIND" ] || BIND="${ODYSSEUS_HOST:-}"
[ -n "$BIND" ] || BIND="${APP_BIND:-}"
[ -n "$BIND" ] || BIND="$(env_value APP_BIND)"
[ -n "$BIND" ] || BIND="127.0.0.1"

PORT="$PORT_OPT"
[ -n "$PORT" ] || PORT="${ODYSSEUS_PORT:-}"
[ -n "$PORT" ] || PORT="${APP_PORT:-}"
[ -n "$PORT" ] || PORT="$(env_value APP_PORT)"
[ -n "$PORT" ] || PORT="7000"

AUTH_ENABLED="$(env_value AUTH_ENABLED)"
# Absent from .env means the app's own default applies, which is enabled.
[ -n "$AUTH_ENABLED" ] || AUTH_ENABLED="true"

# A bind-all address is reachable at loopback from this host; probe the loopback
# address so the health check works from outside a container too.
PROBE_HOST="$BIND"
case "$PROBE_HOST" in
    0.0.0.0|::|"") PROBE_HOST="127.0.0.1" ;;
esac

COMPOSE_CMD=()
detect_compose() {
    if have docker && docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD=(docker compose)
    elif have docker-compose; then
        COMPOSE_CMD=(docker-compose)
    else
        return 1
    fi
}

docker_usable() {
    have docker || return 1
    # A running daemon is what matters; the CLI alone is not enough.
    docker info >/dev/null 2>&1 || return 1
    detect_compose
}

resolve_mode() {
    [ "$MODE" = "auto" ] || return 0
    if docker_usable && [ -f "$REPO_DIR/docker-compose.yml" ]; then
        MODE=docker
    else
        MODE=native
        if have docker && ! docker info >/dev/null 2>&1; then
            warn "Docker is installed but its daemon is not reachable — deploying natively."
        fi
    fi
}

security_notice() {
    case "$PROBE_HOST" in
        127.0.0.1|localhost|::1) return 0 ;;
    esac
    if [ "$AUTH_ENABLED" = "false" ]; then
        warn "AUTH_ENABLED=false while binding $BIND — this exposes the whole"
        warn "workspace (shell, files, models) to anyone who can reach the port."
        warn "Set AUTH_ENABLED=true and reboot the app before doing that."
    fi
}

print_url_block() {
    local url="http://$PROBE_HOST:$PORT"
    log ""
    log "  Odysseus is up at $url   (mode: $MODE)"
    if [ "$BIND" != "$PROBE_HOST" ]; then
        log "  Reachable on $BIND:$PORT (bound beyond loopback — keep auth enabled)."
    fi
    log ""
    log "  Stop it with:   ./deploy.sh --$MODE stop"
    log "  Follow logs:    ./deploy.sh --$MODE logs"
}

# ================================================================== DOCKER ===
docker_ensure_env() {
    if [ ! -f "$ENV_FILE" ] && [ -f "$REPO_DIR/.env.example" ]; then
        step "Creating .env from .env.example"
        run cp "$REPO_DIR/.env.example" "$ENV_FILE"
        log "  Edit .env to set LLM endpoints, API keys and a pre-seeded admin password."
    fi
}

# docker-compose.yml publishes "${APP_BIND}:${APP_PORT}:7000" and Compose lets
# the shell environment win over .env, so export the resolved values before any
# compose call that maps the port. Without this, --host/--port would move the
# health probe but not the published port, and a perfectly healthy stack would
# be reported as a 120s timeout. Only the host-side mapping is affected: the
# container's environment does not carry APP_PORT, so it still listens on 7000.
docker_export_bind() {
    export APP_BIND="$BIND"
    export APP_PORT="$PORT"
}

docker_deploy() {
    command -v docker >/dev/null 2>&1 \
        || die "Docker is not installed. Install Docker, or run: ./deploy.sh --native"
    docker info >/dev/null 2>&1 \
        || die "The Docker daemon is not reachable. Start Docker, or run: ./deploy.sh --native"
    detect_compose \
        || die "Neither 'docker compose' nor 'docker-compose' is available."

    docker_ensure_env
    docker_export_bind

    # docker-compose.yml carries both a registry `image:` and a local `build:`,
    # so which one you get depends on the flags. README.md and website/setup.md
    # both document a plain `docker compose up -d --build`, so building from this
    # checkout is the default — which is also what a fork with local changes
    # needs, since the published image is upstream's, not yours.
    if [ -n "$IMAGE_REF" ]; then
        if [ "$OPTIONAL" = 1 ]; then
            die "--image and --optional cannot be combined: optional extras need a local build."
        fi
        export ODYSSEUS_IMAGE="$IMAGE_REF"
        step "Starting containers from $IMAGE_REF (no local build)"
        run "${COMPOSE_CMD[@]}" pull odysseus
        run "${COMPOSE_CMD[@]}" up -d
    elif [ "$OPTIONAL" = 1 ]; then
        warn "INSTALL_OPTIONAL=true pulls AGPL-licensed packages (PyMuPDF)."
        step "Building the image with optional extras, then starting containers"
        run "${COMPOSE_CMD[@]}" build --build-arg INSTALL_OPTIONAL=true
        run "${COMPOSE_CMD[@]}" up -d
    elif [ "$NO_BUILD" = 1 ]; then
        step "Starting containers from the published image (no local build)"
        run "${COMPOSE_CMD[@]}" up -d
    else
        step "Building and starting containers (odysseus, chromadb, searxng, ntfy)"
        run "${COMPOSE_CMD[@]}" up -d --build
    fi

    step "Waiting for the web UI on $PROBE_HOST:$PORT"
    if [ "$DRY_RUN" = 1 ]; then
        log "   [dry-run] wait_for_port $PROBE_HOST $PORT"
    elif wait_for_port "$PROBE_HOST" "$PORT" 120; then
        log "  ✓ the app is answering"
    else
        warn "The app did not answer within 120s. Inspect the logs:"
        warn "  ${COMPOSE_CMD[*]} logs --tail=120 odysseus"
        return 0
    fi

    log ""
    log "  First-run admin password (printed by setup.py):"
    log "      ${COMPOSE_CMD[*]} logs odysseus | grep -i password"
    print_url_block
}

docker_stop() {
    detect_compose || die "Neither 'docker compose' nor 'docker-compose' is available."
    step "Stopping containers (data and volumes are left intact)"
    run "${COMPOSE_CMD[@]}" stop
}

docker_status() {
    detect_compose || die "Neither 'docker compose' nor 'docker-compose' is available."
    docker_export_bind
    step "Compose services"
    run "${COMPOSE_CMD[@]}" ps
    if port_open "$PROBE_HOST" "$PORT"; then
        log "  ✓ web UI answers on http://$PROBE_HOST:$PORT"
    else
        log "  ✗ nothing answering on http://$PROBE_HOST:$PORT"
    fi
}

docker_logs() {
    detect_compose || die "Neither 'docker compose' nor 'docker-compose' is available."
    run "${COMPOSE_CMD[@]}" logs -f --tail=120 odysseus
}

# ================================================================== NATIVE ===
find_python() {
    local cands="" cand p
    if [ "$(uname -s)" = "Darwin" ] && [ "$(uname -m)" = "arm64" ]; then
        # An x86 interpreter under Rosetta builds a venv whose compiled wheels
        # load as the wrong architecture. Prefer Homebrew's arm64 Python.
        cands="/opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 python3.13 python3.12 python3.11"
    else
        cands="python3.13 python3.12 python3.11 python3"
    fi
    for cand in $cands; do
        p="$(command -v "$cand" 2>/dev/null)" || continue
        if "$p" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)' 2>/dev/null; then
            printf '%s' "$p"
            return 0
        fi
    done
    return 1
}

native_venv() {
    local py="" req_hash="" hash_file="$REPO_DIR/venv/.requirements_hash"
    if [ -x "$REPO_DIR/venv/bin/python" ]; then
        VENV_PY="$REPO_DIR/venv/bin/python"
        log "  ✓ using the existing venv ($("$VENV_PY" --version 2>&1))"
    else
        py="$(find_python)" || die "Python 3.11+ is required but was not found on PATH."
        step "Creating the Python environment (venv/)"
        log "  using $py"
        run "$py" -m venv "$REPO_DIR/venv"
        VENV_PY="$REPO_DIR/venv/bin/python"
    fi

    if [ "$DRY_RUN" = 1 ]; then
        log "   [dry-run] pip install -r requirements.txt (only if requirements.txt changed)"
        return 0
    fi

    # Only reinstall when requirements.txt actually changed — a full install is
    # the slow step and there is no reason to repeat it on every deploy.
    if have md5; then
        req_hash="$(md5 -q "$REPO_DIR/requirements.txt")"
    else
        req_hash="$(md5sum "$REPO_DIR/requirements.txt" | cut -d' ' -f1)"
    fi
    if [ ! -f "$hash_file" ] || [ "$req_hash" != "$(cat "$hash_file" 2>/dev/null)" ]; then
        step "Installing Python packages (first run downloads a few — can take minutes)"
        "$VENV_PY" -m pip install --quiet --upgrade pip
        "$VENV_PY" -m pip install -r "$REPO_DIR/requirements.txt"
        printf '%s' "$req_hash" > "$hash_file"
    else
        log "  ✓ Python packages up to date"
    fi
}

native_setup() {
    step "Preparing data directories and the first admin (setup.py)"
    # setup.py is idempotent: it skips .env, the DB and the admin if present.
    run env ODYSSEUS_SKIP_RUN_HINT=1 "$VENV_PY" "$REPO_DIR/setup.py"
}

native_chromadb_start() {
    local c_host c_port c_bind="" chroma_bin=""
    c_host="$(env_value CHROMADB_HOST)"
    [ -n "$c_host" ] || c_host="${CHROMADB_HOST:-localhost}"
    c_port="$(env_value CHROMADB_PORT)"
    [ -n "$c_port" ] || c_port="${CHROMADB_PORT:-8100}"

    case "$c_host" in
        localhost|127.0.0.1) c_bind="127.0.0.1" ;;
        0.0.0.0)             c_bind="0.0.0.0" ;;
        *)                   log "  ✓ CHROMADB_HOST=$c_host is remote — not starting a local one"; return 0 ;;
    esac
    # Bind and probe on IPv4 loopback: the app resolves "localhost" to 127.0.0.1,
    # but binding chroma to the literal name can land on IPv6 ::1, unreachable.
    if port_open "127.0.0.1" "$c_port"; then
        log "  ✓ ChromaDB already listening on 127.0.0.1:$c_port"
        return 0
    fi
    # The `chroma` server binary lives in the full `chromadb` package, not in the
    # HTTP-only `chromadb-client` that requirements.txt declares: that client can
    # only *talk* to a server someone else runs. Installing the full package is a
    # large download that also pulls transitive upgrades, so the deploy script
    # never does it on its own — it reports what is missing and how to fix it,
    # and only installs when explicitly asked with --with-chromadb.
    chroma_bin="$(dirname "$VENV_PY")/chroma"
    if [ ! -x "$chroma_bin" ]; then
        chroma_bin="$(command -v chroma 2>/dev/null || true)"
    fi
    if [ -z "$chroma_bin" ] && [ "$INSTALL_CHROMADB" = 1 ]; then
        step "Installing the full chromadb package (--with-chromadb)"
        warn "This replaces the HTTP-only chromadb-client and downloads a large tree."
        run "$VENV_PY" -m pip uninstall -y chromadb-client
        run "$VENV_PY" -m pip install chromadb
        if [ "$DRY_RUN" = 1 ]; then
            # Nothing was actually installed, so don't claim the binary is missing.
            log "   [dry-run] start chromadb on $c_bind:$c_port (log: $CHROMA_LOG)"
            return 0
        fi
        chroma_bin="$(dirname "$VENV_PY")/chroma"
    fi
    if [ -z "$chroma_bin" ] || [ ! -x "$chroma_bin" ]; then
        warn "No local ChromaDB server binary found — the tool index and vector RAG will degrade."
        warn "Odysseus still runs; fix it with any one of:"
        warn "  ./deploy.sh --native --with-chromadb     (installs chromadb here)"
        warn "  ./deploy.sh --docker                      (starts a ChromaDB container)"
        warn "  point CHROMADB_HOST at a ChromaDB you already run"
        return 0
    fi
    if [ "$DRY_RUN" = 1 ]; then
        log "   [dry-run] start chromadb on $c_bind:$c_port (log: $CHROMA_LOG)"
        return 0
    fi
    step "Starting ChromaDB on $c_bind:$c_port (log: $CHROMA_LOG)"
    mkdir -p "$PID_DIR" "$LOG_DIR"
    nohup "$chroma_bin" run --host "$c_bind" --port "$c_port" \
        --path "$REPO_DIR/data/chroma" >>"$CHROMA_LOG" 2>&1 &
    printf '%s' "$!" > "$CHROMA_PID_FILE"
}

native_deploy() {
    step "Deploying natively (venv + uvicorn)"
    native_venv
    native_setup
    if [ "$START_CHROMADB" = 1 ]; then
        native_chromadb_start
    fi

    if [ "$FOREGROUND" = 1 ]; then
        # exec replaces this shell, so --dry-run has to stop here: a preview
        # that hands the terminal to a real server is not a preview.
        if [ "$DRY_RUN" = 1 ]; then
            log "   [dry-run] exec $VENV_PY -m uvicorn app:app --host $BIND --port $PORT"
            print_url_block
            return 0
        fi
        step "Starting Odysseus on $BIND:$PORT (foreground — Ctrl+C to stop)"
        exec "$VENV_PY" -m uvicorn app:app --host "$BIND" --port "$PORT"
    fi

    if pid_alive "$APP_PID_FILE"; then
        log "  ✓ Odysseus is already running (pid $(cat "$APP_PID_FILE")) — restarting it"
        native_stop
    fi

    if [ "$DRY_RUN" = 1 ]; then
        log "   [dry-run] start uvicorn on $BIND:$PORT (log: $APP_LOG)"
        print_url_block
        return 0
    fi

    step "Starting Odysseus in the background on $BIND:$PORT (log: $APP_LOG)"
    mkdir -p "$PID_DIR" "$LOG_DIR"
    # nohup + setsid-free backgrounding: the PID file is what `stop`/`status`
    # use, so it must be the uvicorn process itself, not a wrapping shell.
    nohup "$VENV_PY" -m uvicorn app:app --host "$BIND" --port "$PORT" \
        >>"$APP_LOG" 2>&1 &
    printf '%s' "$!" > "$APP_PID_FILE"

    if wait_for_port "$PROBE_HOST" "$PORT" 60; then
        log "  ✓ the app is answering"
        print_url_block
    else
        warn "Odysseus did not answer within 60s. Check the log:"
        warn "  tail -n 80 $APP_LOG"
        return 0
    fi

    log "  First-run admin password (only printed the first time) is in $APP_LOG."
}

native_stop() {
    local stopped=0
    if pid_alive "$APP_PID_FILE"; then
        step "Stopping Odysseus (pid $(cat "$APP_PID_FILE"))"
        run kill "$(cat "$APP_PID_FILE")"
        if [ "$DRY_RUN" != 1 ]; then
            local i
            for ((i = 0; i < 20; i++)); do
                if ! pid_alive "$APP_PID_FILE"; then break; fi
                sleep 0.5
            done
            if pid_alive "$APP_PID_FILE"; then
                kill -9 "$(cat "$APP_PID_FILE")" 2>/dev/null || true
            fi
            rm -f "$APP_PID_FILE"
        fi
        stopped=1
    fi
    if pid_alive "$CHROMA_PID_FILE"; then
        step "Stopping the local ChromaDB (pid $(cat "$CHROMA_PID_FILE"))"
        run kill "$(cat "$CHROMA_PID_FILE")"
        [ "$DRY_RUN" = 1 ] || rm -f "$CHROMA_PID_FILE"
        stopped=1
    fi
    [ "$stopped" = 1 ] || log "  (nothing to stop)"
}

native_status() {
    if pid_alive "$APP_PID_FILE"; then
        log "  ✓ Odysseus running (pid $(cat "$APP_PID_FILE"))  log: $APP_LOG"
    else
        log "  ✗ Odysseus not running (no live pid in $APP_PID_FILE)"
    fi
    if pid_alive "$CHROMA_PID_FILE"; then
        log "  ✓ ChromaDB running (pid $(cat "$CHROMA_PID_FILE"))  log: $CHROMA_LOG"
    fi
    if port_open "$PROBE_HOST" "$PORT"; then
        log "  ✓ web UI answers on http://$PROBE_HOST:$PORT"
    else
        log "  ✗ nothing answering on http://$PROBE_HOST:$PORT"
    fi
}

native_logs() {
    [ -f "$APP_LOG" ] || die "no log yet at $APP_LOG — has Odysseus been deployed?"
    # tail -f never returns, so it must not run under --dry-run.
    if [ "$DRY_RUN" = 1 ]; then
        log "   [dry-run] tail -n 120 -f $APP_LOG"
        return 0
    fi
    tail -n 120 -f "$APP_LOG"
}

# The commands a root operator runs to install the generated unit. Printed
# rather than executed: installing touches /etc and needs root, and a deploy
# script should not escalate privileges behind the operator's back.
print_systemd_install_cmds() {
    log "  Install it (needs sudo — deliberately not run for you):"
    log "      sudo install -m 0644 $1 /etc/systemd/system/odysseus.service"
    log "      sudo systemctl daemon-reload"
    log "      sudo systemctl enable --now odysseus"
}

# systemd unit generation. Written to data/ and printed rather than installed.
native_write_systemd() {
    local unit_dir unit content
    unit_dir="$REPO_DIR/data/systemd"
    unit="$unit_dir/odysseus.service"

    content="$(cat <<EOF
# Generated by deploy.sh — install with the commands printed below.
[Unit]
Description=Odysseus
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(id -un)
Group=$(id -gn)
WorkingDirectory=$REPO_DIR
EnvironmentFile=-$ENV_FILE
ExecStart=$REPO_DIR/venv/bin/uvicorn app:app --host $BIND --port $PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
)"

    # --dry-run must not touch the filesystem, so print the unit and the paths
    # instead of creating them. The body is generated either way so the preview
    # shows the real thing, and `verify` needs a file on disk — skip it here.
    if [ "$DRY_RUN" = 1 ]; then
        log "   [dry-run] mkdir -p $unit_dir"
        log "   [dry-run] write $unit:"
        printf '%s\n' "$content" | sed 's/^/   [dry-run]   /'
        if have systemd-analyze; then
            log "   [dry-run] systemd-analyze verify $unit"
        fi
        print_systemd_install_cmds "$unit"
        return 0
    fi

    mkdir -p "$unit_dir"
    printf '%s\n' "$content" > "$unit"
    step "Wrote a systemd unit to $unit"
    if have systemd-analyze; then
        if systemd-analyze verify "$unit" >/dev/null 2>&1; then
            log "  ✓ systemd-analyze verify: the unit is valid"
        else
            warn "systemd-analyze verify reported a problem with the unit above."
        fi
    fi
    print_systemd_install_cmds "$unit"
}

# ================================================================== COMMON ===
do_update() {
    step "Pulling the latest code"
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        # --ff-only refuses to guess a merge: a diverged checkout fails loudly
        # instead of silently creating a merge commit, as update_windows.bat does.
        run git pull --ff-only
    else
        warn "Not a git checkout — skipping the pull."
    fi
    case "$MODE" in
        docker)
            docker_deploy
            step "Removing dangling images left by the rebuild"
            run docker image prune -f
            ;;
        native)
            native_deploy
            ;;
    esac
}

main() {
    resolve_mode
    security_notice

    case "$VERB" in
        deploy)
            if [ "$MODE" = docker ]; then docker_deploy; else native_deploy; fi
            ;;
        stop)
            if [ "$MODE" = docker ]; then docker_stop; else native_stop; fi
            ;;
        restart)
            if [ "$MODE" = docker ]; then
                docker_stop
                docker_deploy
            else
                native_stop
                native_deploy
            fi
            ;;
        status)
            log "mode: $MODE   bind: $BIND   port: $PORT"
            if [ "$MODE" = docker ]; then docker_status; else native_status; fi
            ;;
        logs)
            if [ "$MODE" = docker ]; then docker_logs; else native_logs; fi
            ;;
        update)
            do_update
            ;;
    esac

    if [ "$MODE" = native ] && [ "$WRITE_SYSTEMD" = 1 ] && [ "$VERB" = deploy ]; then
        native_write_systemd
    fi
}

main
