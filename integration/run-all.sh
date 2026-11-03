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

# N-480: mirrors the CI integration job — start the in-repo BRC-100 test
# wallet and point every tier's RUNAR_WALLET_ENDPOINT-gated wallet-client
# test at it (Ruby's runs inside the Ruby suite below; the other six in the
# wallet-client section at the end).
echo ""
echo "=== Starting mock BRC-100 wallet ==="
./mock-wallet/mock-wallet.sh start
trap './mock-wallet/mock-wallet.sh stop' EXIT
export RUNAR_WALLET_ENDPOINT="http://127.0.0.1:${MOCK_WALLET_PORT:-18480}"

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
echo "=== TypeScript SDK regtest test (assembleMultiContractCall) ==="
# Mirrors the CI integration step of the same name (N-474). Under
# RUNAR_INTEGRATION_STRICT=1 an unreachable node fails instead of skipping.
if (cd ../packages/runar-sdk && npx vitest run src/__tests__/multi-contract-call.regtest.test.ts); then
  echo "--- TypeScript SDK regtest: PASSED ---"
else
  echo "--- TypeScript SDK regtest: FAILED ---"
  FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Rust integration tests ==="
if (cd rust && cargo test --release -- --include-ignored); then
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

echo ""
echo "=== Java integration tests ==="
# Java integration uses Gradle + JUnit 5. Tests are gated behind the
# `-Drunar.integration=true` system property so a bare `gradle test`
# inside the examples/java build does not attempt to reach a node that
# is not running. Pass the flag through here so the full matrix driver
# actually exercises the deploy / call / broadcast path.
GRADLE_BIN=""
for candidate in gradle /opt/homebrew/bin/gradle /usr/local/bin/gradle; do
  if command -v "$candidate" >/dev/null 2>&1; then
    GRADLE_BIN="$candidate"
    break
  fi
done
if [ -z "$GRADLE_BIN" ]; then
  # CI sets RUNAR_INTEGRATION_STRICT=1 so a missing toolchain is a hard
  # failure rather than a silent green pass. Local devs can leave it
  # unset to skip Java integration when Gradle is not installed, but the
  # skip surfaces in the summary and never sets exit 0 in CI.
  if [ "${RUNAR_INTEGRATION_STRICT:-0}" = "1" ]; then
    echo "--- Java: FAILED (no gradle >= 8 on PATH; strict mode) ---"
    FAILED=$((FAILED + 1))
  else
    echo "--- Java: SKIPPED (no gradle >= 8 on PATH) ---"
  fi
else
  if (cd java && "$GRADLE_BIN" test -Drunar.integration=true --no-daemon); then
    echo "--- Java: PASSED ---"
  else
    echo "--- Java: FAILED ---"
    FAILED=$((FAILED + 1))
  fi
fi

echo ""
echo "=== BRC-100 wallet-client tests (mock wallet) ==="
# Same commands as the CI integration job's per-tier wallet-client steps.
run_wallet_client() {
  local tier="$1"; shift
  if (cd .. && eval "$*"); then
    echo "--- $tier wallet-client: PASSED ---"
  else
    echo "--- $tier wallet-client: FAILED ---"
    FAILED=$((FAILED + 1))
  fi
}
run_wallet_client TypeScript 'cd packages/runar-sdk && npx vitest run src/__tests__/wallet-client.spec.ts'
run_wallet_client Go 'cd packages/runar-go && go test -run TestWalletClient_LiveEndpoint_RoundTrip -v'
run_wallet_client Rust 'cd packages/runar-rs && cargo test --test wallet_client_integration -- --ignored'
run_wallet_client Python 'cd packages/runar-py && python3 -m pytest tests/test_wallet_client_integration.py -v'
run_wallet_client Zig 'cd packages/runar-zig && zig build test'
run_wallet_client Java 'cd packages/runar-java && ./gradlew test --tests runar.lang.sdk.WalletClientIntegrationTest --no-daemon'

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
