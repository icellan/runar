#!/usr/bin/env bash
# mock-http.sh — start/stop the in-repo HTTP echo server (server.mjs, N-485).
#
#   ./mock-http.sh start   # background server on 127.0.0.1:$MOCK_HTTP_PORT (default 18481);
#                            # returns once GET /get answers, fails if it never does
#   ./mock-http.sh stop
#
# Point the Zig live-GET tests at it with
#   RUN_LIVE_HTTP=1 RUN_LIVE_HTTP_BASE=http://127.0.0.1:18481
set -euo pipefail
cd "$(dirname "$0")"

PORT="${MOCK_HTTP_PORT:-18481}"
PIDFILE="${TMPDIR:-/tmp}/runar-mock-http-${PORT}.pid"
LOGFILE="${TMPDIR:-/tmp}/runar-mock-http-${PORT}.log"

case "${1:-}" in
  start)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "mock http already running (pid $(cat "$PIDFILE"))"
      exit 0
    fi
    nohup node server.mjs --port "$PORT" >"$LOGFILE" 2>&1 &
    echo $! >"$PIDFILE"
    for _ in $(seq 1 50); do
      if curl -sf "http://127.0.0.1:${PORT}/get" >/dev/null 2>&1; then
        echo "mock http up on http://127.0.0.1:${PORT} (pid $(cat "$PIDFILE"))"
        exit 0
      fi
      if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then break; fi
      sleep 0.2
    done
    echo "mock http failed to start; log:" >&2
    cat "$LOGFILE" >&2 || true
    exit 1
    ;;
  stop)
    if [ -f "$PIDFILE" ]; then
      kill "$(cat "$PIDFILE")" 2>/dev/null || true
      rm -f "$PIDFILE"
    fi
    ;;
  *)
    echo "Usage: ./mock-http.sh start|stop" >&2
    exit 1
    ;;
esac
