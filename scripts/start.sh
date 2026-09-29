#!/usr/bin/env bash
#
# Build and start LogGen, optionally with a local syslog sink.
#
#   ./scripts/start.sh                 run against the existing destinations
#   ./scripts/start.sh --with-sink     also run a sink and point a destination at it
#   ./scripts/start.sh --addr 127.0.0.1:8088
#
# Stop with: pkill -f 'loggen -addr'   (or Ctrl+C if run in the foreground)

set -euo pipefail

cd "$(dirname "$0")/.."

ADDR="0.0.0.0:8088"
DATA="data"
SINK_PORT=5514
WITH_SINK=0
OPEN=0
LG_USER="admin"
LG_PASSWORD="admin"
USER="admin"
PASSWORD="admin"

while [ $# -gt 0 ]; do
  case "$1" in
    --addr)      ADDR="$2"; shift 2 ;;
    --data)      DATA="$2"; shift 2 ;;
    --sink-port) SINK_PORT="$2"; shift 2 ;;
    --with-sink) WITH_SINK=1; shift ;;
    --user)      LG_USER="$2"; shift 2 ;;
    --password)  LG_PASSWORD="$2"; shift 2 ;;
    --user)      USER="$2"; shift 2 ;;
    --password)  PASSWORD="$2"; shift 2 ;;
    --open)      OPEN=1; shift ;;
    -h|--help)   sed -n '3,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

say() { printf '  %s\n' "$1"; }

printf '\nLogGen\n'

# Stop anything already running.
if pgrep -f 'loggen (-addr|-sink)' >/dev/null 2>&1; then
  say "stopping the running instance"
  pkill -f 'loggen (-addr|-sink)' || true
  sleep 1
fi

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
say "building ${VERSION}"
go build -ldflags "-s -w -X main.version=${VERSION}" -o loggen .

if [ "$WITH_SINK" = "1" ]; then
  say "starting a syslog sink on :${SINK_PORT}"
  ./loggen -sink ":${SINK_PORT}" > sink.log 2>&1 &
  sleep 1
fi

OPEN_FLAG="-open=false"
[ "$OPEN" = "1" ] && OPEN_FLAG="-open=true"

./loggen -addr "$ADDR" -data "$DATA" "$OPEN_FLAG" > loggen.log 2>&1 &

PORT="${ADDR##*:}"
ready=0
for _ in $(seq 1 30); do
  sleep 0.4
  # The sign-in endpoint is the one that answers without a session.
  if curl -sf "http://127.0.0.1:${PORT}/api/auth/state" -o /dev/null; then ready=1; break; fi
done

if [ "$ready" != "1" ]; then
  printf '  the console did not come up; last output:\n' >&2
  tail -15 loggen.log >&2
  exit 1
fi

# The console needs a session now, so the script holds one in a cookie jar to
# configure the sink and read the control count back.
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
if ! curl -sf -c "$JAR" -X POST "http://127.0.0.1:${PORT}/api/auth/login"   -H 'Content-Type: application/json'   -d "{\"user\":\"${LG_USER}\",\"password\":\"${LG_PASSWORD}\"}" -o /dev/null; then
  say "could not sign in as '${LG_USER}'. Pass --user and --password if it has been changed."
  JAR=""
fi

if [ "$WITH_SINK" = "1" ] && [ -n "$JAR" ]; then
  curl -sf -b "$JAR" -X POST "http://127.0.0.1:${PORT}/api/profiles"     -H 'Content-Type: application/json'     -d "{\"name\":\"Local sink\",\"host\":\"127.0.0.1\",\"port\":${SINK_PORT},\"protocol\":\"udp\",\"isDefault\":true}"     -o /dev/null && say "destination 'Local sink' points at 127.0.0.1:${SINK_PORT}"
fi

if [ -n "$JAR" ]; then
  say "$(curl -s -b "$JAR" "http://127.0.0.1:${PORT}/api/controls" | grep -o '"id":' | wc -l | tr -d ' ') controls registered"
fi
printf '\n'
grep 'http://' loggen.log | sed 's/^[0-9:]* */  /'
printf '\n'
[ "$WITH_SINK" = "1" ] && say "records land in sink.log — tail -f sink.log"
say "stop with: pkill -f loggen"
printf '\n'
