#!/usr/bin/env bash
# deploy.sh - set up and run the Container Vulnerability Scanner locally.
#
# Usage (from anywhere; the script finds the repo root itself):
#   ./deploy.sh check        Check prerequisites only. Changes nothing.
#   ./deploy.sh setup        Python venv + packages, Trivy, PDF libraries, unit tests.
#   ./deploy.sh jenkins      Build and start the local Jenkins (port 8080).
#   ./deploy.sh monitoring   Start exporter + Prometheus (9090) + Grafana (3000).
#   ./deploy.sh status       Show what is running and whether it responds.
#   ./deploy.sh down         Stop both stacks. Data volumes are kept.
#   ./deploy.sh all          check, setup, jenkins, monitoring, status.
#
# Safe to run again: every step skips what is already done.
# Never deletes Docker volumes, so Jenkins jobs/history and dashboard data stay.
# Secrets are only ever typed at a hidden prompt (read -s) into the
# git-ignored .env files; they are never printed or passed as arguments.
#
# LOCAL LAB USE ONLY. Targets Ubuntu on WSL2 (or Linux) with Docker running.

set -euo pipefail

# Docker attaches a fresh build-provenance record to every local build by
# default, which gives even a fully cached image a new ID. Compose then
# treats the image as changed and restarts the container (a re-run would
# interrupt a running Jenkins build). Without it, a cached build keeps the
# same ID and running containers are left alone.
export BUILDX_NO_DEFAULT_ATTESTATIONS=1

TRIVY_VERSION="0.76.0"          # keep in step with scan.yml and ci/jenkins/Dockerfile
MIN_PY_MINOR=10                 # requirements.txt needs Python 3.10+

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

JENKINS_COMPOSE="ci/jenkins/docker-compose.yml"
JENKINS_ENV="ci/jenkins/.env"
JENKINS_IMAGE="vuln-scanner-jenkins:local"
MON_COMPOSE="monitoring/docker-compose.yml"
MON_ENV="monitoring/.env"
MON_KEYS=(GITHUB_REPOSITORY GITHUB_TOKEN JENKINS_USER JENKINS_TOKEN GRAFANA_ADMIN_PASSWORD)

ok()   { printf '  [ OK ] %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# HTTP status code of a local URL, or 000 if nothing answers.
http_code() { curl -s -o /dev/null -m 5 -w '%{http_code}' "$1" || true; }

# Is something listening on 127.0.0.1:<port>?
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

container_running() {
    [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || true)" = "true" ]
}

# Wait until <url> returns one of the accepted codes, up to <seconds>.
wait_http() {
    local url="$1" accept="$2" secs="$3" code="000" i
    for ((i = 0; i < secs; i += 5)); do
        code="$(http_code "$url")"
        case " $accept " in *" $code "*) return 0 ;; esac
        sleep 5
    done
    echo "    last HTTP code from $url: $code" >&2
    return 1
}

# True if <file> has KEY=<non-empty value>.
env_has() { [ -f "$1" ] && grep -qE "^$2=.+" "$1"; }

trivy_version() { trivy --version 2>/dev/null | awk '/^Version:/ {print $2; exit}'; }

pango_present() { ldconfig -p 2>/dev/null | grep -q 'libpango-1.0.so'; }

# ---------------------------------------------------------------- check
cmd_check() {
    step "Checking prerequisites (read-only)"
    local fail=0

    if [ "$(id -u)" -eq 0 ]; then
        warn "Running as root. Run as your normal user; the script uses sudo only where needed."
    fi

    for c in git curl python3; do
        if have "$c"; then ok "$c found"; else bad "$c not found"; fail=1; fi
    done

    if have python3; then
        local minor
        minor="$(python3 -c 'import sys; print(sys.version_info[1] if sys.version_info[0] == 3 else 0)')"
        if [ "$minor" -ge "$MIN_PY_MINOR" ]; then
            ok "Python $(python3 -c 'import platform; print(platform.python_version())') (needs 3.$MIN_PY_MINOR+)"
        else
            bad "Python 3.$MIN_PY_MINOR or newer is needed"; fail=1
        fi
        if python3 -c 'import venv, ensurepip' 2>/dev/null; then
            ok "python3 venv module available"
        else
            bad "python3 venv module missing (sudo apt install python3-venv)"; fail=1
        fi
    fi

    if ! have docker; then
        bad "docker not found (install Docker Desktop and enable WSL integration)"; fail=1
    elif ! docker info >/dev/null 2>&1; then
        bad "Docker is installed but not running, or this user can't reach it"
        echo "         Linux/cloud VM: sudo usermod -aG docker \"\$USER\", then log out and back in"
        fail=1
    else
        ok "Docker is running"
        if docker compose version >/dev/null 2>&1; then
            ok "docker compose available"
        else
            bad "docker compose (v2) not available"; fail=1
        fi
    fi

    if have trivy; then
        local tv; tv="$(trivy_version)"
        if [ "$tv" = "$TRIVY_VERSION" ]; then ok "Trivy $tv"
        else warn "Trivy $tv found; the project is pinned to $TRIVY_VERSION"; fi
    else
        warn "Trivy not installed (./deploy.sh setup installs $TRIVY_VERSION)"
    fi

    if pango_present; then ok "Pango libraries (PDF reports)"
    else warn "Pango libraries missing; PDF reports will fail (./deploy.sh setup installs them)"; fi

    if [ -x .venv/bin/python ]; then ok "Project venv exists (.venv)"
    else warn "No project venv yet (./deploy.sh setup creates it)"; fi

    # Ports: fine if free, or if our own container is the one using them.
    local spec port name
    for spec in 8080:vuln-scanner-jenkins 9090:vuln-prometheus 3000:vuln-grafana; do
        port="${spec%%:*}"; name="${spec#*:}"
        if ! port_in_use "$port"; then
            ok "Port $port free"
        elif have docker && container_running "$name"; then
            ok "Port $port in use by $name (this project)"
        else
            bad "Port $port is used by something else; stop it first"; fail=1
        fi
    done

    if env_has "$JENKINS_ENV" DOCKER_GID; then ok "$JENKINS_ENV has DOCKER_GID"
    else warn "$JENKINS_ENV not set up yet (./deploy.sh jenkins creates it)"; fi

    local key missing=()
    for key in "${MON_KEYS[@]}"; do env_has "$MON_ENV" "$key" || missing+=("$key"); done
    if [ "${#missing[@]}" -eq 0 ]; then ok "$MON_ENV has all ${#MON_KEYS[@]} values"
    else warn "$MON_ENV missing: ${missing[*]} (./deploy.sh monitoring asks for them)"; fi

    echo
    if [ "$fail" -eq 0 ]; then
        echo "Prerequisites OK. WARN lines are things later commands will set up."
    else
        echo "Fix the FAIL lines above, then run ./deploy.sh check again."
    fi
    return "$fail"
}

# ---------------------------------------------------------------- setup
cmd_setup() {
    step "Python virtual environment"
    if [ -x .venv/bin/python ]; then ok ".venv already exists"
    else python3 -m venv .venv && ok "Created .venv"; fi
    .venv/bin/pip install --quiet --upgrade pip
    .venv/bin/pip install --quiet -r requirements.txt
    ok "Installed requirements.txt"

    step "PDF libraries (Pango)"
    if pango_present; then ok "Already installed"
    else
        echo "  Installing libpango (asks for your sudo password)..."
        sudo apt-get update -qq
        sudo apt-get install -y -qq libpango-1.0-0 libpangoft2-1.0-0
        ok "Installed"
    fi

    step "Trivy $TRIVY_VERSION"
    if have trivy && [ "$(trivy_version)" = "$TRIVY_VERSION" ]; then ok "Already installed"
    else
        echo "  Installing to /usr/local/bin (asks for your sudo password)..."
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
            | sudo sh -s -- -b /usr/local/bin "v$TRIVY_VERSION"
        [ "$(trivy_version)" = "$TRIVY_VERSION" ] || die "Trivy install did not give version $TRIVY_VERSION"
        ok "Installed Trivy $(trivy_version)"
    fi

    step "Unit tests"
    .venv/bin/python -m unittest discover -s tests
    ok "Unit tests passed"
}

# ---------------------------------------------------------------- jenkins
cmd_jenkins() {
    docker info >/dev/null 2>&1 || die "Docker is not running."

    step "Jenkins: Docker socket group"
    if env_has "$JENKINS_ENV" DOCKER_GID; then
        ok "$JENKINS_ENV already has DOCKER_GID (kept as is)"
    else
        echo "  Building the Jenkins image once to read the socket's group..."
        docker build -q -t "$JENKINS_IMAGE" ci/jenkins >/dev/null
        local gid
        gid="$(docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
               --entrypoint stat "$JENKINS_IMAGE" -c %g /var/run/docker.sock)"
        [[ "$gid" =~ ^[0-9]+$ ]] || die "Could not read the Docker socket group (got: $gid)"
        printf 'DOCKER_GID=%s\n' "$gid" > "$JENKINS_ENV"
        ok "Wrote $JENKINS_ENV (DOCKER_GID=$gid)"
    fi

    step "Jenkins: start"
    docker compose -f "$JENKINS_COMPOSE" up -d --build
    echo "  Waiting for Jenkins to answer on http://localhost:8080 (up to 3 minutes)..."
    # 200 = ready, 403 = ready but login/unlock needed. 503 = still starting.
    wait_http "http://localhost:8080/login" "200 403" 180 || die "Jenkins did not respond in time. See: docker logs vuln-scanner-jenkins"
    ok "Jenkins is up: http://localhost:8080"

    if docker exec vuln-scanner-jenkins test -f /var/jenkins_home/secrets/initialAdminPassword 2>/dev/null; then
        echo
        echo "  First start: Jenkins needs its one-time setup (see docs/setup.md)."
        echo "  Show the unlock password with:"
        echo "    docker exec vuln-scanner-jenkins cat /var/jenkins_home/secrets/initialAdminPassword"
    fi
}

# ---------------------------------------------------------------- monitoring
# owner/repo of this clone's GitHub remote, offered as the default.
repo_from_origin() {
    git remote get-url origin 2>/dev/null \
        | sed -E 's#^(https://[^/]*github\.com/|git@github\.com:)##; s#\.git$##' \
        | grep -E '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || true
}

ask_mon_env() {
    step "Monitoring: $MON_ENV"
    if [ ! -f "$MON_ENV" ]; then
        cp monitoring/.env.example "$MON_ENV"
        ok "Created $MON_ENV from .env.example"
    fi
    chmod 600 "$MON_ENV"

    local key val
    for key in "${MON_KEYS[@]}"; do
        if env_has "$MON_ENV" "$key"; then ok "$key already set (kept)"; continue; fi
        case "$key" in
            GITHUB_REPOSITORY) echo "  Your repository on GitHub as owner/repo (whose scan history the dashboard shows)." ;;
            GITHUB_TOKEN)  echo "  GitHub fine-grained token (this repo only, Actions: Read-only)." ;;
            JENKINS_USER)  echo "  Jenkins user ID: the part after /user/ in your Jenkins profile URL." ;;
            JENKINS_TOKEN) echo "  Jenkins API token: Jenkins > your name > Security > API Token." ;;
            GRAFANA_ADMIN_PASSWORD) echo "  Grafana admin password to set (only used on Grafana's first start)." ;;
        esac
        if [ "$key" = GITHUB_REPOSITORY ]; then
            local guess
            guess="$(repo_from_origin)"
            if [ -n "$guess" ]; then
                read -r -p "  $key [$guess]: " val
                val="${val:-$guess}"
            else
                read -r -p "  $key: " val
            fi
            [[ "$val" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
                || die "GITHUB_REPOSITORY must look like owner/repo (got: $val)."
        elif [ "$key" = JENKINS_USER ]; then
            read -r -p "  $key: " val
        else
            read -r -s -p "  $key (hidden): " val; echo
        fi
        [ -n "$val" ] || die "$key cannot be empty."
        # Docker Compose treats $ in .env values as a variable, and spaces
        # break the KEY=value format, so refuse both instead of failing later.
        case "$val" in
            *'$'*|*[[:space:]]*) die "$key must not contain \$ or spaces (choose another value)." ;;
        esac
        # Replace the KEY= line in place; awk reads the value from the
        # environment, so it never appears in a command line.
        # (appended if the file has no KEY= line, e.g. one made from an
        # older .env.example).
        KEY="$key" VAL="$val" awk 'BEGIN{k=ENVIRON["KEY"]; v=ENVIRON["VAL"]; f=0}
            $0 ~ "^"k"=" {print k"="v; f=1; next} {print}
            END{if (!f) print k"="v}' "$MON_ENV" > "$MON_ENV.tmp"
        mv "$MON_ENV.tmp" "$MON_ENV"; chmod 600 "$MON_ENV"
        unset val
        ok "$key saved"
    done
}

cmd_monitoring() {
    docker info >/dev/null 2>&1 || die "Docker is not running."
    docker network inspect jenkins_default >/dev/null 2>&1 \
        || die "Jenkins' network (jenkins_default) not found. Run ./deploy.sh jenkins first."

    ask_mon_env

    step "Monitoring: start"
    docker compose -f "$MON_COMPOSE" up -d --build
    echo "  Waiting for Prometheus and Grafana (up to 2 minutes)..."
    wait_http "http://localhost:9090/-/ready" "200" 120 || die "Prometheus did not become ready. See: docker logs vuln-prometheus"
    ok "Prometheus is up: http://localhost:9090"
    wait_http "http://localhost:3000/api/health" "200" 120 || die "Grafana did not become ready. See: docker logs vuln-grafana"
    ok "Grafana is up: http://localhost:3000 (user: admin)"

    echo "  Waiting for Prometheus' first scrape of the exporter (up to 2 minutes)..."
    local i up=""
    for ((i = 0; i < 120; i += 10)); do
        up="$(curl -s -G http://localhost:9090/api/v1/query \
              --data-urlencode 'query=up{job="vuln-exporter"}' \
              | python3 -c 'import sys,json; r=json.load(sys.stdin)["data"]["result"]; print(r[0]["value"][1] if r else "")' 2>/dev/null || true)"
        [ "$up" = "1" ] && break
        sleep 10
    done
    if [ "$up" = "1" ]; then ok "Exporter is being scraped (up=1)"
    else warn "Exporter not scraped yet (up='${up}'). Check: docker logs vuln-scanner-exporter"; fi
}

# ---------------------------------------------------------------- status / down
cmd_status() {
    step "Containers"
    local cname cstatus
    docker ps -a --filter name=vuln- --format '{{.Names}}\t{{.Status}}' \
        | while IFS=$'\t' read -r cname cstatus; do
              printf '  %-24s %s\n' "$cname" "$cstatus"
          done || true
    step "Endpoints"
    local spec name base path code
    for spec in "Jenkins|http://localhost:8080|/login" \
                "Prometheus|http://localhost:9090|/-/ready" \
                "Grafana|http://localhost:3000|/api/health"; do
        IFS='|' read -r name base path <<< "$spec"
        code="$(http_code "$base$path")"
        case "$code" in
            200|403) ok "$name responds ($code) $base" ;;
            000)     warn "$name not reachable" ;;
            *)       warn "$name answered HTTP $code" ;;
        esac
    done
}

cmd_down() {
    step "Stopping stacks (containers stopped, volumes kept)"
    docker compose -f "$MON_COMPOSE" stop
    docker compose -f "$JENKINS_COMPOSE" stop
    ok "Stopped. Start again with ./deploy.sh jenkins and ./deploy.sh monitoring"
}

cmd_all() {
    cmd_check || die "Prerequisite check failed; nothing was changed."
    cmd_setup
    cmd_jenkins
    cmd_monitoring
    cmd_status
    cat << 'TXT'

Done. One-time manual steps that the script can't do for you (see docs/setup.md):
  - Jenkins: finish the setup wizard, create the vuln-scanner Pipeline job,
    add the Slack webhook as a credential.
  - GitHub: add the SLACK_WEBHOOK_URL Actions secret and the branch ruleset.
TXT
}

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; }

case "${1:-}" in
    check)      cmd_check ;;
    setup)      cmd_setup ;;
    jenkins)    cmd_jenkins ;;
    monitoring) cmd_monitoring ;;
    status)     cmd_status ;;
    down)       cmd_down ;;
    all)        cmd_all ;;
    -h|--help|help|"") usage ;;
    *) usage; die "Unknown command: $1" ;;
esac
