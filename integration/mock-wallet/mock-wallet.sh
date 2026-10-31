#!/usr/bin/env bash
# mock-wallet.sh — start/stop the in-repo BRC-100 test wallet (server.mjs, N-480).
#
#   ./mock-wallet.sh start   # background server on 127.0.0.1:$MOCK_WALLET_PORT (default 18480);
#                            # returns once it answers a getPublicKey call, fails if it never does
#   ./mock-wallet.sh stop
#
# Point the wallet-client tests at it with
#   RUNAR_WALLET_ENDPOINT=http://127.0.0.1:18480
set -euo pipefail
cd "$(dirname "$0")"

PORT="${MOCK_WALLET_PORT:-18480}"
PIDFILE="${TMPDIR:-/tmp}/runar-mock-wallet-${PORT}.pid"
LOGFILE="${TMPDIR:-/tmp}/runar-mock-wallet-${PORT}.log"

case "${1:-}" in
  start)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "mock wallet already running (pid $(cat "$PIDFILE"))"
      exit 0
    fi
    nohup node server.mjs --port "$PORT" >"$LOGFILE" 2>&1 &
    echo $! >"$PIDFILE"
    for _ in $(seq 1 50); do
      if curl -sf -X POST -H 'Content-Type: application/json' \
        -d '{"protocolID":[2,"runar integration"],"keyID":"1"}' \
        "http://127.0.0.1:${PORT}/getPublicKey" >/dev/null 2>&1; then
        echo "mock wallet up on http://127.0.0.1:${PORT} (pid $(cat "$PIDFILE"))"
        exit 0
      fi
      if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then break; fi
      sleep 0.2
    done
    echo "mock wallet failed to start; log:" >&2
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
    echo "Usage: ./mock-wallet.sh start|stop" >&2
    exit 1
    ;;
esac
