#!/usr/bin/env bash
# run-all-parallel.sh — Win 6 — parallel-per-language regtest driver.
#
# Spawns one bitcoin-sv regtest container PER LANGUAGE on a unique RPC port,
# then runs all 7 language integration suites in parallel. Each language
# reads its dedicated RPC_URL via env var, so the suites don't race for UTXOs
# in a shared mempool/wallet.
#
# Within a language the tests stay serial (each test deploys → mines →
# spends; can't safely race against itself). The parallelism win is across
# languages.
#
# Architecture chosen: 7 regtest instances. Tried to share one node with
# isolated wallets first, but every language's helper layer assumes the
# default wallet (`getnewaddress`, `sendtoaddress`, `generatetoaddress`)
# which would race when called from 7 concurrent test runs. Spinning up 7
# containers is heavier on Docker but trivially correct.
#
# Usage:
#   ./run-all-parallel.sh [--start] [--stop]
#     --start  Start the 7 regtest containers before running tests
#     --stop   Stop and remove the 7 regtest containers after running tests
#
# Notes:
# - Each container uses ~1 CPU + ~50 MB RAM idle. Acceptable on CI hosts.
# - If `--start` is omitted, the script assumes the per-language containers
#   are already running and uses their port assignments (deterministic).

set -euo pipefail
cd "$(dirname "$0")"

START_NODE=false
STOP_NODE=false
FAILED=0

for arg in "$@"; do
  case "$arg" in
    --start) START_NODE=true ;;
    --stop)  STOP_NODE=true ;;
    *)       echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

# -----------------------------------------------------------------
# Per-language port assignments.
# Deterministic: ts=18342, go=18343, ... so artifacts and logs are
# predictable across runs. Each language's container also exposes a
# distinct P2P + ZMQ port.
# -----------------------------------------------------------------
declare -A RPC_PORT
RPC_PORT[ts]=18342
RPC_PORT[go]=18343
RPC_PORT[rust]=18344
RPC_PORT[python]=18345
RPC_PORT[ruby]=18346
RPC_PORT[zig]=18347
RPC_PORT[java]=18348

declare -A P2P_PORT
P2P_PORT[ts]=18352
P2P_PORT[go]=18353
P2P_PORT[rust]=18354
P2P_PORT[python]=18355
P2P_PORT[ruby]=18356
P2P_PORT[zig]=18357
P2P_PORT[java]=18358

declare -A ZMQ_PORT
ZMQ_PORT[ts]=28342
ZMQ_PORT[go]=28343
ZMQ_PORT[rust]=28344
ZMQ_PORT[python]=28345
ZMQ_PORT[ruby]=28346
ZMQ_PORT[zig]=28347
ZMQ_PORT[java]=28348

LANGUAGES=(ts go rust python ruby zig java)

start_one() {
  local lang=$1
  ./regtest.sh start "$lang" "${RPC_PORT[$lang]}" "${P2P_PORT[$lang]}" "${ZMQ_PORT[$lang]}" >/dev/null
}

stop_one() {
  local lang=$1
  ./regtest.sh stop "$lang" >/dev/null 2>&1 || true
}

if $START_NODE; then
  echo "=== Starting $((${#LANGUAGES[@]})) regtest containers in parallel ==="
  for lang in "${LANGUAGES[@]}"; do
    start_one "$lang" &
  done
  wait
  echo "All regtest containers ready."
fi

# -----------------------------------------------------------------
# Spawn each language's integration suite in parallel.
# Each task captures its output to a per-language log file; the
# trailing `wait` block aggregates exit codes for the final report.
# -----------------------------------------------------------------

LOGDIR="$(pwd)/.parallel-logs"
mkdir -p "$LOGDIR"
rm -f "$LOGDIR"/*.log "$LOGDIR"/*.exit

run_lang() {
  local lang=$1
  local rpc_url="http://localhost:${RPC_PORT[$lang]}"
  local log="$LOGDIR/$lang.log"
  local exitfile="$LOGDIR/$lang.exit"
  echo "[$lang] starting (RPC_URL=$rpc_url)"
  (
    case "$lang" in
      ts)
        cd ts && RPC_URL="$rpc_url" RPC_USER=bitcoin RPC_PASS=bitcoin npx vitest run
        ;;
      go)
        cd go && RPC_URL="$rpc_url" RPC_USER=bitcoin RPC_PASS=bitcoin go test -tags integration -v -timeout 1800s
        ;;
      rust)
        cd rust && RPC_URL="$rpc_url" RPC_USER=bitcoin RPC_PASS=bitcoin cargo test --release -- --ignored
        ;;
      python)
        cd python
        if [ ! -d .venv ]; then
          (python3.13 -m venv .venv 2>/dev/null || python3 -m venv .venv)
          .venv/bin/pip install -q -r requirements.txt
        fi
        RPC_URL="$rpc_url" RPC_USER=bitcoin RPC_PASS=bitcoin \
          PYTHONPATH=../../compilers/python:../../packages/runar-py \
          .venv/bin/python -m pytest -v
        ;;
      ruby)
        cd ruby
        # Find a usable Ruby ≥ 3.1
        RUBY_BIN=""
        for c in ruby /opt/homebrew/opt/ruby/bin/ruby /usr/local/opt/ruby/bin/ruby; do
          if $c -e 'exit(RUBY_VERSION >= "3.1" ? 0 : 1)' 2>/dev/null; then
            RUBY_BIN="$c"; break
          fi
        done
        if [ -z "$RUBY_BIN" ]; then
          echo "no ruby >= 3.1 found"; exit 1
        fi
        RUBY_DIR="$(dirname "$RUBY_BIN")"
        BUNDLE="$RUBY_DIR/bundle"
        [ -x "$BUNDLE" ] || BUNDLE=bundle
        $BUNDLE install --quiet >/dev/null 2>&1 || $BUNDLE install --quiet
        RPC_URL="$rpc_url" RPC_USER=bitcoin RPC_PASS=bitcoin $BUNDLE exec rspec --format documentation
        ;;
      zig)
        cd zig && RPC_URL="$rpc_url" RPC_USER=bitcoin RPC_PASS=bitcoin zig build test
        ;;
      java)
        cd java
        GRADLE_BIN=""
        for c in gradle /opt/homebrew/bin/gradle /usr/local/bin/gradle; do
          if command -v "$c" >/dev/null 2>&1; then GRADLE_BIN="$c"; break; fi
        done
        if [ -z "$GRADLE_BIN" ]; then
          echo "no gradle found"; exit 1
        fi
        RPC_URL="$rpc_url" RPC_USER=bitcoin RPC_PASS=bitcoin \
          $GRADLE_BIN test -Drunar.integration=true --no-daemon
        ;;
    esac
  ) >"$log" 2>&1 &
  echo $! > "$LOGDIR/$lang.pid"
}

echo ""
echo "=== Spawning ${#LANGUAGES[@]} integration suites in parallel ==="
for lang in "${LANGUAGES[@]}"; do
  run_lang "$lang"
done

# Wait on each PID and capture its exit status individually so we can report
# pass/fail per language rather than a single combined "wait" return.
for lang in "${LANGUAGES[@]}"; do
  pid=$(cat "$LOGDIR/$lang.pid")
  if wait "$pid"; then
    echo "$lang: PASS" > "$LOGDIR/$lang.exit"
  else
    echo "$lang: FAIL" > "$LOGDIR/$lang.exit"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "=== Per-language results ==="
for lang in "${LANGUAGES[@]}"; do
  cat "$LOGDIR/$lang.exit"
done

echo ""
echo "Per-language logs available under: $LOGDIR/"

if $STOP_NODE; then
  echo ""
  echo "=== Stopping regtest containers ==="
  for lang in "${LANGUAGES[@]}"; do
    stop_one "$lang" &
  done
  wait
fi

if [ $FAILED -eq 0 ]; then
  echo "All integration test suites passed."
else
  echo "$FAILED suite(s) failed."
  exit 1
fi
