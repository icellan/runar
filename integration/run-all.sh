#!/usr/bin/env bash
# Run all integration test suites against a running regtest node.
# Usage: ./run-all.sh [--start] [--stop]
#   --start  Start the regtest node before running tests
#   --stop   Stop the regtest node after running tests

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

if $START_NODE; then
  echo "=== Starting regtest node ==="
  ./regtest.sh start
fi

echo ""
echo "=== Go integration tests ==="
if (cd go && go test -tags integration -v -timeout 1800s); then
  echo "--- Go: PASSED ---"
else
  echo "--- Go: FAILED ---"
  FAILED=$((FAILED + 1))
fi

echo ""
echo "=== TypeScript integration tests ==="
if (cd ts && npx vitest run); then
  echo "--- TypeScript: PASSED ---"
else
  echo "--- TypeScript: FAILED ---"
  FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Rust integration tests ==="
if (cd rust && cargo test --release -- --ignored); then
  echo "--- Rust: PASSED ---"
else
  echo "--- Rust: FAILED ---"
  FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Python integration tests ==="
# Ensure venv exists with dependencies
if [ ! -d python/.venv ]; then
  echo "Creating Python venv..."
  (cd python && python3.13 -m venv .venv 2>/dev/null || python3 -m venv .venv)
  (cd python && .venv/bin/pip install -q -r requirements.txt)
fi
if (cd python && PYTHONPATH=../../compilers/python:../../packages/runar-py .venv/bin/python -m pytest -v); then
  echo "--- Python: PASSED ---"
else
  echo "--- Python: FAILED ---"
  FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Ruby integration tests ==="
# Find a Ruby >= 3.1 — Homebrew installs to /opt/homebrew/opt/ruby/bin on
# Apple Silicon and /usr/local/opt/ruby/bin on Intel, but macOS ships 2.6
# at /usr/bin/ruby which is too old.
RUBY_BIN=""
for candidate in ruby /opt/homebrew/opt/ruby/bin/ruby /usr/local/opt/ruby/bin/ruby; do
  if $candidate -e 'exit(RUBY_VERSION >= "3.1" ? 0 : 1)' 2>/dev/null; then
    RUBY_BIN="$candidate"
    break
  fi
done
if [ -z "$RUBY_BIN" ]; then
  echo "--- Ruby: FAILED (no Ruby >= 3.1 found) ---"
  FAILED=$((FAILED + 1))
else
  RUBY_DIR="$(dirname "$RUBY_BIN")"
  BUNDLE="$RUBY_DIR/bundle"
  [ -x "$BUNDLE" ] || BUNDLE=bundle  # fall back to PATH
  (cd ruby && "$BUNDLE" install --quiet 2>/dev/null || "$BUNDLE" install --quiet)
  if (cd ruby && "$BUNDLE" exec rspec --format documentation); then
    echo "--- Ruby: PASSED ---"
  else
    echo "--- Ruby: FAILED ---"
    FAILED=$((FAILED + 1))
  fi
fi

echo ""
echo "=== Zig integration tests ==="
if (cd zig && zig build test); then
  echo "--- Zig: PASSED ---"
else
  echo "--- Zig: FAILED ---"
  FAILED=$((FAILED + 1))
fi

if $STOP_NODE; then
  echo ""
  echo "=== Stopping regtest node ==="
  ./regtest.sh stop
fi

echo ""
if [ $FAILED -eq 0 ]; then
  echo "All integration test suites passed."
else
  echo "$FAILED suite(s) failed."
  exit 1
fi
