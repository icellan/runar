#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# cross-compiler-diff.sh — Tier 6.1 six-tier byte-exact cross-compiler CI
# ---------------------------------------------------------------------------
#
# For each conformance fixture under conformance/tests/<name>/, compile the
# fixture with every available compiler tier (TS, Go, Rust, Python, Zig,
# Ruby, Java) plus the Lean reference, and compare:
#
#   1. Each compiler's hex output vs. the on-disk expected-script.hex golden.
#   2. Each compiler's hex output vs. every other compiler that ran on the
#      same fixture (peer-mode parity).
#   3. The Lean reference verifier's verdict (via tests/PipelineGolden.lean's
#      built-in regression gate, see notes below).
#
# Per-fixture compiler allowlists in source.json are honored: when a fixture
# declares `"compilers": ["go"]` (or similar) the script SKIPS out-of-scope
# compilers for that fixture rather than counting them as a divergence. This
# matches the CLAUDE.md project policy on Go-only crypto codegen modules.
#
# A JSON matrix report is written to runar-verification/cross-compiler-report.json
# for downstream tooling. The script exits non-zero on any mismatch
# (compiler-vs-expected, compiler-vs-compiler, or compiler invocation failure).
#
# Usage:
#   bash runar-verification/scripts/cross-compiler-diff.sh
#       [--fixture NAME ...]            # restrict to one or more fixtures
#       [--compiler ID ...]             # restrict to one or more compilers
#       [--report PATH]                 # output JSON report path
#       [--fold-on]                     # run with constant folding ENABLED
#                                       # (defaults to fold-OFF, matching the
#                                       # checked-in goldens)
#       [--no-lean]                     # skip the Lean reference gate
#       [--quiet]                       # suppress per-fixture progress lines
#
# Compiler ids: ts, go, rust, python, zig, ruby, java, lean
#
# This script is intentionally idempotent and read-only with respect to the
# fixture corpus. It writes only to a temp dir + the report path. It does not
# modify any source.json, expected-ir.json, or expected-script.hex files. If
# a divergence is surfaced, the script's job is to report which compiler /
# fixture pair disagrees — not to "fix" the underlying compiler.
#
# Lean note: lake's `pipelineGolden` exe runs its own byte-exact regression
# gate against expected-script.hex (the reference hex file). This script
# therefore treats the Lean tier's verdict as PASS / FAIL based on the
# pipelineGolden process exit code (0 = all 49/49 byte-exact). Per-fixture
# Lean hex extraction is not exposed by the existing exe; the all-or-nothing
# verdict is recorded under the special pseudo-fixture `"_global"` in the
# JSON report. Use `--no-lean` to skip if Lean toolchain is unavailable.

set -u
set -o pipefail

# ---------------------------------------------------------------------------
# Config — paths and binary discovery.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFICATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${VERIFICATION_DIR}/.." && pwd)"
TESTS_DIR="${REPO_ROOT}/conformance/tests"

REPORT_PATH_DEFAULT="${VERIFICATION_DIR}/cross-compiler-report.json"
REPORT_PATH=""
FOLD_OFF=1
RUN_LEAN=1
QUIET=0
declare -a FIXTURE_FILTER=()
declare -a COMPILER_FILTER=()

ALL_COMPILERS=(ts go rust python zig ruby java)

# Format extensions matching source.json keys, in the priority order we'd
# pick when the fixture declares multiple sources. We stick with .runar.ts
# whenever it's listed because every compiler tier supports it; only fall
# back to other extensions if .runar.ts is absent.
PREFERRED_EXTS=(.runar.ts .runar.go .runar.rs .runar.py .runar.zig .runar.rb .runar.java .runar.sol .runar.move)

# ---------------------------------------------------------------------------
# Argument parsing.
# ---------------------------------------------------------------------------

usage() {
  cat <<USAGE
cross-compiler-diff.sh — six-tier byte-exact cross-compiler diff

Options:
  --fixture NAME     restrict to fixture NAME (repeatable)
  --compiler ID      restrict to compiler ID (repeatable; one of
                     ts go rust python zig ruby java lean)
  --report PATH      JSON report output path
                     (default: ${REPORT_PATH_DEFAULT})
  --fold-on          enable constant folding (default: fold-OFF)
  --no-lean          skip the Lean reference gate
  --quiet            suppress per-fixture progress output
  --help             show this message
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --fixture)   shift; FIXTURE_FILTER+=("$1") ;;
    --compiler)  shift; COMPILER_FILTER+=("$1") ;;
    --report)    shift; REPORT_PATH="$1" ;;
    --fold-on)   FOLD_OFF=0 ;;
    --no-lean)   RUN_LEAN=0 ;;
    --quiet)     QUIET=1 ;;
    --help|-h)   usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ -z "${REPORT_PATH}" ]; then
  REPORT_PATH="${REPORT_PATH_DEFAULT}"
fi

# Whether a compiler id is in the active filter (or always-on if no filter).
in_compiler_filter() {
  local id="$1"
  if [ "${#COMPILER_FILTER[@]}" -eq 0 ]; then
    return 0
  fi
  local x
  for x in "${COMPILER_FILTER[@]}"; do
    if [ "$x" = "$id" ]; then return 0; fi
  done
  return 1
}

# Whether a fixture name is in the active filter (or always-on if no filter).
in_fixture_filter() {
  local name="$1"
  if [ "${#FIXTURE_FILTER[@]}" -eq 0 ]; then
    return 0
  fi
  local x
  for x in "${FIXTURE_FILTER[@]}"; do
    if [ "$x" = "$name" ]; then return 0; fi
  done
  return 1
}

log() {
  if [ "$QUIET" -eq 0 ]; then
    echo "$@"
  fi
}

err() {
  echo "$@" >&2
}

# Require jq for source.json parsing.
if ! command -v jq >/dev/null 2>&1; then
  err "ERROR: jq is required. Install jq and retry."
  exit 2
fi

if [ ! -d "$TESTS_DIR" ]; then
  err "ERROR: conformance tests directory not found: $TESTS_DIR"
  exit 2
fi

# ---------------------------------------------------------------------------
# Compiler binary discovery.
#
# Each find_<id>_binary echoes the launch prefix (binary or wrapper command)
# on stdout, or stays silent + returns non-zero if the binary is missing.
# ---------------------------------------------------------------------------

GO_DIR="${REPO_ROOT}/compilers/go"
RUST_DIR="${REPO_ROOT}/compilers/rust"
PYTHON_DIR="${REPO_ROOT}/compilers/python"
ZIG_DIR="${REPO_ROOT}/compilers/zig"
RUBY_DIR="${REPO_ROOT}/compilers/ruby"
JAVA_DIR="${REPO_ROOT}/compilers/java"
TS_CLI_BIN="${REPO_ROOT}/packages/runar-cli/dist/bin.js"

TS_CLI_SRC="${REPO_ROOT}/packages/runar-cli/src/bin.ts"

# Locate the tsx loader: prefer the conformance-local pnpm path the existing
# runner uses, then the workspace root fallback. Returns a URL or empty.
resolve_tsx_loader() {
  local cand
  for cand in \
      "${REPO_ROOT}/conformance/node_modules/tsx/dist/loader.mjs" \
      "${REPO_ROOT}/node_modules/tsx/dist/loader.mjs" \
      "${REPO_ROOT}/integration/ts/node_modules/tsx/dist/loader.mjs"; do
    if [ -f "$cand" ]; then
      printf 'file://%s' "$cand"
      return 0
    fi
  done
  return 1
}

# TS launch prefix: prefer the source entry under tsx (matches the conformance
# runner's runTsCompiler so we exercise the same path that ships in CI). Falls
# back to the dist'd JS bin if tsx isn't installed AND the dist is present.
find_ts_binary() {
  if command -v node >/dev/null 2>&1 && [ -f "$TS_CLI_SRC" ]; then
    local loader
    if loader=$(resolve_tsx_loader); then
      printf '%s' "node --import $loader $TS_CLI_SRC"
      return 0
    fi
  fi
  if [ -f "$TS_CLI_BIN" ] && command -v node >/dev/null 2>&1; then
    printf '%s' "node $TS_CLI_BIN"
    return 0
  fi
  return 1
}

find_go_binary() {
  if [ -x "${GO_DIR}/runar-go" ]; then
    printf '%s' "${GO_DIR}/runar-go"; return 0
  fi
  if [ -x "${REPO_ROOT}/runar-go" ]; then
    printf '%s' "${REPO_ROOT}/runar-go"; return 0
  fi
  if command -v runar-go >/dev/null 2>&1; then
    printf '%s' "runar-go"; return 0
  fi
  return 1
}

find_rust_binary() {
  local cand
  for cand in "${RUST_DIR}/target/release/runar-compiler-rust" \
              "${RUST_DIR}/target/debug/runar-compiler-rust" \
              "${REPO_ROOT}/runar-compiler-rust"; do
    if [ -x "$cand" ]; then
      printf '%s' "$cand"; return 0
    fi
  done
  if command -v runar-compiler-rust >/dev/null 2>&1; then
    printf '%s' "runar-compiler-rust"; return 0
  fi
  return 1
}

find_python_binary() {
  if [ -f "${PYTHON_DIR}/runar_compiler/__main__.py" ] && command -v python3 >/dev/null 2>&1; then
    printf '%s' "python3 -m runar_compiler"
    return 0
  fi
  return 1
}

find_zig_binary() {
  local cand
  for cand in "${ZIG_DIR}/zig-out/bin/runar-zig" \
              "${ZIG_DIR}/runar-zig" \
              "${REPO_ROOT}/runar-zig"; do
    if [ -x "$cand" ]; then
      printf '%s' "$cand"; return 0
    fi
  done
  if command -v runar-zig >/dev/null 2>&1; then
    printf '%s' "runar-zig"; return 0
  fi
  return 1
}

find_ruby_binary() {
  local cand="${RUBY_DIR}/bin/runar-compiler-ruby"
  if [ -f "$cand" ] && command -v ruby >/dev/null 2>&1; then
    printf '%s' "ruby $cand"
    return 0
  fi
  return 1
}

find_java_binary() {
  local libsDir="${JAVA_DIR}/build/libs"
  local jar=""
  if [ -f "${libsDir}/runar-java.jar" ]; then
    jar="${libsDir}/runar-java.jar"
  elif [ -d "$libsDir" ]; then
    # Latest matching jar.
    local cand
    for cand in "${libsDir}"/runar-java-compiler-*.jar; do
      if [ -f "$cand" ]; then
        jar="$cand"
        break
      fi
    done
  fi
  # CI sometimes drops the jar at workflow root via download-artifact.
  if [ -z "$jar" ]; then
    local cand
    for cand in "${REPO_ROOT}"/runar-java*.jar; do
      if [ -f "$cand" ]; then jar="$cand"; break; fi
    done
  fi
  if [ -n "$jar" ] && command -v java >/dev/null 2>&1; then
    printf '%s' "java -jar $jar"
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Per-compiler source-to-hex invocation.
#
# Inputs: compiler id, source file path, fold-flag string ("" or
#         "--disable-constant-folding"), output capture file (hex), and
#         err capture file (stderr). Returns the exit code from the compiler.
# ---------------------------------------------------------------------------

compile_to_hex() {
  local id="$1" src="$2" fold="$3" hex_out="$4" err_out="$5"
  : > "$hex_out"
  : > "$err_out"
  local rc=0
  case "$id" in
    ts)
      # The TS CLI writes an artifact JSON; read .script from the artifact.
      # The compile command's `compile = await import(...)` block uses
      # process.cwd() to find packages/runar-compiler/src/index.ts, so we MUST
      # invoke from REPO_ROOT for the in-repo compiler import to resolve.
      local bin
      bin=$(find_ts_binary) || return 127
      local artifact_dir
      artifact_dir="$(mktemp -d)"
      # shellcheck disable=SC2086 # bin contains the wrapper "node /path/to/bin.js"
      if [ -n "$fold" ]; then
        ( cd "$REPO_ROOT" && $bin compile "$src" --ir "$fold" -o "$artifact_dir" ) >"$err_out" 2>&1 || rc=$?
      else
        ( cd "$REPO_ROOT" && $bin compile "$src" --ir -o "$artifact_dir" ) >"$err_out" 2>&1 || rc=$?
      fi
      if [ "$rc" -eq 0 ]; then
        local base
        base=$(basename "$src")
        # Strip last extension only (matches path.basename(file, extname)).
        base="${base%.*}"
        local artifact="${artifact_dir}/${base}.json"
        if [ -f "$artifact" ]; then
          jq -r '.script // ""' "$artifact" > "$hex_out" 2>>"$err_out" || rc=$?
        else
          rc=2
          echo "TS artifact not found: $artifact" >> "$err_out"
        fi
      fi
      rm -rf "$artifact_dir"
      ;;
    go)
      local bin
      bin=$(find_go_binary) || return 127
      # shellcheck disable=SC2086 # bin is a single token here
      if [ -n "$fold" ]; then
        $bin --source "$src" --hex $fold > "$hex_out" 2>"$err_out" || rc=$?
      else
        $bin --source "$src" --hex > "$hex_out" 2>"$err_out" || rc=$?
      fi
      ;;
    rust)
      local bin
      bin=$(find_rust_binary) || return 127
      if [ -n "$fold" ]; then
        "$bin" --source "$src" --hex $fold > "$hex_out" 2>"$err_out" || rc=$?
      else
        "$bin" --source "$src" --hex > "$hex_out" 2>"$err_out" || rc=$?
      fi
      ;;
    python)
      local bin
      bin=$(find_python_binary) || return 127
      ( cd "$PYTHON_DIR" && \
        if [ -n "$fold" ]; then
          $bin --source "$src" --hex $fold
        else
          $bin --source "$src" --hex
        fi ) > "$hex_out" 2>"$err_out" || rc=$?
      ;;
    zig)
      local bin
      bin=$(find_zig_binary) || return 127
      if [ -n "$fold" ]; then
        "$bin" --source "$src" --hex $fold > "$hex_out" 2>"$err_out" || rc=$?
      else
        "$bin" --source "$src" --hex > "$hex_out" 2>"$err_out" || rc=$?
      fi
      ;;
    ruby)
      local bin
      bin=$(find_ruby_binary) || return 127
      # shellcheck disable=SC2086 # bin is "ruby /path"
      if [ -n "$fold" ]; then
        $bin --source "$src" --hex $fold > "$hex_out" 2>"$err_out" || rc=$?
      else
        $bin --source "$src" --hex > "$hex_out" 2>"$err_out" || rc=$?
      fi
      ;;
    java)
      local bin
      bin=$(find_java_binary) || return 127
      # shellcheck disable=SC2086 # bin is "java -jar /path/jar"
      if [ -n "$fold" ]; then
        $bin --source "$src" --hex $fold > "$hex_out" 2>"$err_out" || rc=$?
      else
        $bin --source "$src" --hex > "$hex_out" 2>"$err_out" || rc=$?
      fi
      ;;
    *)
      err "compile_to_hex: unknown compiler id '$id'"
      return 2
      ;;
  esac
  return $rc
}

# Normalize hex: strip whitespace, lowercase. Operates on file in-place.
normalize_hex_file() {
  local f="$1"
  if [ -s "$f" ]; then
    local norm
    norm=$(tr -d '[:space:]' < "$f" | tr '[:upper:]' '[:lower:]')
    printf '%s' "$norm" > "$f"
  fi
}

# ---------------------------------------------------------------------------
# Lean reference: invoke pipelineGolden and capture verdict.
# ---------------------------------------------------------------------------

LEAN_VERDICT_PASS=0
LEAN_VERDICT_RAN=0
LEAN_BYTE_EXACT_LINE=""

run_lean_reference() {
  if [ "$RUN_LEAN" -eq 0 ]; then return 0; fi
  if ! in_compiler_filter "lean"; then return 0; fi
  local lean_bin="${VERIFICATION_DIR}/.lake/build/bin/pipelineGolden"
  if [ ! -x "$lean_bin" ]; then
    log "Lean: pipelineGolden binary not found ($lean_bin); skipping"
    return 0
  fi
  if ! command -v lake >/dev/null 2>&1; then
    log "Lean: lake not on PATH; skipping"
    return 0
  fi
  log "Lean: invoking pipelineGolden (49-fixture regression gate)..."
  LEAN_VERDICT_RAN=1
  local out
  if out=$( ( cd "$VERIFICATION_DIR" && lake env "$lean_bin" ) 2>&1 ); then
    LEAN_VERDICT_PASS=1
  else
    LEAN_VERDICT_PASS=0
  fi
  LEAN_BYTE_EXACT_LINE=$(printf '%s\n' "$out" | grep -E '^PIPELINE GOLDEN:' | tail -n 1 || true)
  if [ -n "$LEAN_BYTE_EXACT_LINE" ]; then
    log "Lean: $LEAN_BYTE_EXACT_LINE"
  else
    log "Lean: no PIPELINE GOLDEN line emitted"
  fi
}

# ---------------------------------------------------------------------------
# Main fixture loop.
# ---------------------------------------------------------------------------

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TMP_ROOT"' EXIT

FOLD_FLAG=""
if [ "$FOLD_OFF" -eq 1 ]; then
  FOLD_FLAG="--disable-constant-folding"
fi

# Discovery: list fixture directories and apply filter.
declare -a FIXTURES=()
for dir in "$TESTS_DIR"/*/; do
  name=$(basename "$dir")
  if in_fixture_filter "$name"; then
    if [ -f "${dir}/source.json" ]; then
      FIXTURES+=("$name")
    fi
  fi
done

if [ "${#FIXTURES[@]}" -eq 0 ]; then
  err "ERROR: no fixtures matched (filter=${FIXTURE_FILTER[*]:-<none>})"
  exit 2
fi

if [ "$FOLD_OFF" -eq 1 ]; then
  log "Discovered ${#FIXTURES[@]} fixtures (fold=OFF)"
else
  log "Discovered ${#FIXTURES[@]} fixtures (fold=ON)"
fi

# Discovery: which compilers are available right now?
# (Use a space-separated string for portability with bash 3.x on macOS.)
AVAILABLE_IDS=""
is_available() {
  case " $AVAILABLE_IDS " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}
for id in "${ALL_COMPILERS[@]}"; do
  ok=0
  case "$id" in
    ts)     find_ts_binary     >/dev/null 2>&1 && ok=1 ;;
    go)     find_go_binary     >/dev/null 2>&1 && ok=1 ;;
    rust)   find_rust_binary   >/dev/null 2>&1 && ok=1 ;;
    python) find_python_binary >/dev/null 2>&1 && ok=1 ;;
    zig)    find_zig_binary    >/dev/null 2>&1 && ok=1 ;;
    ruby)   find_ruby_binary   >/dev/null 2>&1 && ok=1 ;;
    java)   find_java_binary   >/dev/null 2>&1 && ok=1 ;;
  esac
  if [ "$ok" -eq 1 ]; then
    AVAILABLE_IDS="$AVAILABLE_IDS $id"
  fi
done
AVAILABLE_IDS="$(echo "$AVAILABLE_IDS" | awk '{$1=$1};1')"
log "Available compilers: ${AVAILABLE_IDS:-<none>}"

# Run Lean separately (whole-corpus regression gate) before per-fixture loop
# so its output stays at the top of the log.
run_lean_reference

# Build the JSON report incrementally.
REPORT_TMP="${TMP_ROOT}/report.json"
echo '{"fixtures":[],"summary":{}}' > "$REPORT_TMP"

# Counters.
fail=0
total_fixtures=0
total_compiler_runs=0
total_matches_expected=0
total_peer_mismatches=0

for name in "${FIXTURES[@]}"; do
  total_fixtures=$((total_fixtures + 1))
  dir="${TESTS_DIR}/${name}"
  source_json="${dir}/source.json"
  expected_hex_file="${dir}/expected-script.hex"

  expected_hex=""
  if [ -f "$expected_hex_file" ]; then
    expected_hex=$(tr -d '[:space:]' < "$expected_hex_file" | tr '[:upper:]' '[:lower:]')
  fi

  # Per-fixture compiler allowlist.
  allowlist=""
  if [ -f "$source_json" ]; then
    allowlist=$(jq -r '.compilers // [] | join(" ")' "$source_json")
  fi

  # Pick a source file that exists on disk. Prefer .runar.ts, fall back through
  # the priority list defined above.
  source_path=""
  source_ext=""
  for ext in "${PREFERRED_EXTS[@]}"; do
    rel=$(jq -r --arg ext "$ext" '.sources[$ext] // ""' "$source_json")
    if [ -n "$rel" ]; then
      abs="$(cd "$dir" && cd "$(dirname "$rel")" && pwd)/$(basename "$rel")"
      if [ -f "$abs" ]; then
        source_path="$abs"
        source_ext="$ext"
        break
      fi
    fi
  done

  if [ -z "$source_path" ]; then
    log "=== $name === SKIP (no on-disk source matched)"
    # Add a SKIP entry to the report.
    fixture_entry=$(jq -n --arg name "$name" --arg reason "no on-disk source" \
      '{name: $name, status: "skipped", reason: $reason}')
    REPORT_TMP_NEXT="${TMP_ROOT}/report-next.json"
    jq --argjson entry "$fixture_entry" '.fixtures += [$entry]' "$REPORT_TMP" > "$REPORT_TMP_NEXT"
    mv "$REPORT_TMP_NEXT" "$REPORT_TMP"
    continue
  fi

  # Determine the active compiler set for this fixture (space-separated).
  active_ids=""
  for id in "${ALL_COMPILERS[@]}"; do
    is_available "$id" || continue
    if ! in_compiler_filter "$id"; then continue; fi
    if [ -n "$allowlist" ]; then
      hit=0
      for a in $allowlist; do
        if [ "$a" = "$id" ]; then hit=1; break; fi
      done
      [ "$hit" -eq 1 ] || continue
    fi
    active_ids="$active_ids $id"
  done
  active_ids=$(echo "$active_ids" | awk '{$1=$1};1')

  if [ -z "$active_ids" ]; then
    log "=== $name === SKIP (no active compilers; allowlist=[${allowlist}])"
    fixture_entry=$(jq -n --arg name "$name" --arg reason "no active compilers in scope" \
                          --arg allowlist "$allowlist" \
      '{name: $name, status: "skipped", reason: $reason, allowlist: $allowlist}')
    REPORT_TMP_NEXT="${TMP_ROOT}/report-next.json"
    jq --argjson entry "$fixture_entry" '.fixtures += [$entry]' "$REPORT_TMP" > "$REPORT_TMP_NEXT"
    mv "$REPORT_TMP_NEXT" "$REPORT_TMP"
    continue
  fi

  active_csv=$(echo "$active_ids" | tr ' ' ',')
  if [ "$QUIET" -eq 0 ]; then
    printf '=== %s === src=%s active=[%s]' "$name" "$source_ext" "$active_csv"
  fi

  # Per-fixture state lives in TMP_ROOT under per-id files (portable, no
  # bash 4 associative arrays needed). Each compiler writes its raw stdout
  # to .hex / stderr to .err; we then write parallel .meta files (rc,
  # matches_expected, error_message) used by the comparison + report
  # phases below.
  fixture_failed=0
  for id in $active_ids; do
    out_file="${TMP_ROOT}/${name}.${id}.hex"
    err_file="${TMP_ROOT}/${name}.${id}.err"
    rc_file="${TMP_ROOT}/${name}.${id}.rc"
    msg_file="${TMP_ROOT}/${name}.${id}.msg"
    : > "$msg_file"
    rc=0
    compile_to_hex "$id" "$source_path" "$FOLD_FLAG" "$out_file" "$err_file" || rc=$?
    echo "$rc" > "$rc_file"
    if [ "$rc" -eq 127 ]; then
      # Compiler binary disappeared between scan and call. Treat as
      # not-applicable rather than failure (very unlikely after the
      # availability scan above; defensive only).
      : > "$out_file"
      echo "compiler binary missing at call time" > "$msg_file"
      continue
    fi
    total_compiler_runs=$((total_compiler_runs + 1))
    if [ "$rc" -ne 0 ]; then
      fixture_failed=1
      fail=1
      : > "$out_file"
      echo "exit code $rc" > "$msg_file"
      log ""
      err "::error::cross-compiler-diff: $name/$id failed (exit=$rc)"
      err "----- last 30 lines of $id stderr for $name -----"
      tail -n 30 "$err_file" >&2 2>/dev/null || true
      err "----- end stderr -----"
      continue
    fi
    normalize_hex_file "$out_file"
    if [ ! -s "$out_file" ]; then
      fixture_failed=1
      fail=1
      echo "empty hex output" > "$msg_file"
      log ""
      err "::error::cross-compiler-diff: $name/$id produced empty hex"
    fi
  done

  # Compare each compiler's hex vs. expected and vs. peers.
  for id in $active_ids; do
    out_file="${TMP_ROOT}/${name}.${id}.hex"
    me_file="${TMP_ROOT}/${name}.${id}.matches"
    if [ ! -s "$out_file" ]; then
      echo "false" > "$me_file"
      continue
    fi
    hex_val=$(cat "$out_file")
    if [ -n "$expected_hex" ] && [ "$hex_val" = "$expected_hex" ]; then
      echo "true" > "$me_file"
      total_matches_expected=$((total_matches_expected + 1))
    else
      echo "false" > "$me_file"
      if [ -n "$expected_hex" ]; then
        fail=1
        log ""
        err "::error::cross-compiler-diff: $name/$id hex differs from expected golden"
        err "  $id:        $(printf '%.80s' "$hex_val")..."
        err "  expected:   $(printf '%.80s' "$expected_hex")..."
      fi
    fi
  done

  # Peer-mode: every pair in `active_ids` should agree (only meaningful when
  # every active compiler successfully produced output).
  all_match=1
  active_count=$(echo "$active_ids" | wc -w | tr -d ' ')
  if [ "$active_count" -gt 1 ] && [ "$fixture_failed" -eq 0 ]; then
    ref_id=$(echo "$active_ids" | awk '{print $1}')
    ref_file="${TMP_ROOT}/${name}.${ref_id}.hex"
    ref_hex=$(cat "$ref_file" 2>/dev/null || true)
    for id in $active_ids; do
      [ "$id" = "$ref_id" ] && continue
      this_file="${TMP_ROOT}/${name}.${id}.hex"
      this_hex=$(cat "$this_file" 2>/dev/null || true)
      if [ "$this_hex" != "$ref_hex" ]; then
        all_match=0
        total_peer_mismatches=$((total_peer_mismatches + 1))
        fail=1
        log ""
        err "::error::cross-compiler-diff: $name — $ref_id hex differs from $id hex"
        err "  $ref_id (hex_len=${#ref_hex}):   $(printf '%.80s' "$ref_hex")..."
        err "  $id  (hex_len=${#this_hex}):     $(printf '%.80s' "$this_hex")..."
      fi
    done
  fi

  if [ "$QUIET" -eq 0 ]; then
    if [ "$fixture_failed" -eq 0 ] && [ "$all_match" -eq 1 ]; then
      ref_id=$(echo "$active_ids" | awk '{print $1}')
      ref_hex=$(cat "${TMP_ROOT}/${name}.${ref_id}.hex" 2>/dev/null || true)
      printf ' OK (%d hex chars, %d compilers)\n' "${#ref_hex}" "$active_count"
    else
      printf ' FAIL\n'
    fi
  fi

  # Build per-fixture JSON entry incrementally.
  if [ "$all_match" -eq 1 ] && [ "$fixture_failed" -eq 0 ]; then
    all_match_json=true
  else
    all_match_json=false
  fi
  fixture_entry=$(jq -n \
    --arg name "$name" \
    --arg src_ext "$source_ext" \
    --arg expected "$expected_hex" \
    --arg allowlist "$allowlist" \
    --argjson all_match "$all_match_json" \
    '{name: $name, source_ext: $src_ext, expected_hex: $expected, allowlist: $allowlist,
      compilers: {}, all_match: $all_match}')

  for id in $active_ids; do
    out_file="${TMP_ROOT}/${name}.${id}.hex"
    rc_file="${TMP_ROOT}/${name}.${id}.rc"
    msg_file="${TMP_ROOT}/${name}.${id}.msg"
    me_file="${TMP_ROOT}/${name}.${id}.matches"
    hex_val=$(cat "$out_file" 2>/dev/null || true)
    rc_val=$(cat "$rc_file" 2>/dev/null || echo 0)
    msg_val=$(cat "$msg_file" 2>/dev/null || true)
    me_val=$(cat "$me_file" 2>/dev/null || echo false)
    fixture_entry=$(printf '%s' "$fixture_entry" | jq \
      --arg id "$id" --arg hex "$hex_val" --arg err "$msg_val" \
      --argjson rc "$rc_val" \
      --argjson me "$me_val" \
      '.compilers[$id] = {hex: $hex, exit_code: $rc, error: $err, matches_expected: $me}')
  done

  REPORT_TMP_NEXT="${TMP_ROOT}/report-next.json"
  jq --argjson entry "$fixture_entry" '.fixtures += [$entry]' "$REPORT_TMP" > "$REPORT_TMP_NEXT"
  mv "$REPORT_TMP_NEXT" "$REPORT_TMP"
done

# ---------------------------------------------------------------------------
# Final summary.
# ---------------------------------------------------------------------------

REPORT_TMP_NEXT="${TMP_ROOT}/report-next.json"
jq --argjson total "$total_fixtures" \
   --argjson runs "$total_compiler_runs" \
   --argjson exp "$total_matches_expected" \
   --argjson peer "$total_peer_mismatches" \
   --argjson lean_ran "$LEAN_VERDICT_RAN" \
   --argjson lean_pass "$LEAN_VERDICT_PASS" \
   --arg lean_line "$LEAN_BYTE_EXACT_LINE" \
   '.summary = {
        total_fixtures: $total,
        total_compiler_runs: $runs,
        total_matches_expected: $exp,
        total_peer_mismatches: $peer,
        lean: {ran: ($lean_ran == 1), pass: ($lean_pass == 1), line: $lean_line}
   }' \
   "$REPORT_TMP" > "$REPORT_TMP_NEXT"
mv "$REPORT_TMP_NEXT" "$REPORT_TMP"

mkdir -p "$(dirname "$REPORT_PATH")"
cp "$REPORT_TMP" "$REPORT_PATH"

log ""
log "=========================================="
log "cross-compiler-diff summary"
log "=========================================="
log "  fixtures:                ${total_fixtures}"
log "  compiler runs:           ${total_compiler_runs}"
log "  matches-expected count:  ${total_matches_expected}"
log "  peer mismatches:         ${total_peer_mismatches}"
if [ "$LEAN_VERDICT_RAN" -eq 1 ]; then
  log "  lean reference:          $([ "$LEAN_VERDICT_PASS" -eq 1 ] && echo PASS || echo FAIL) (${LEAN_BYTE_EXACT_LINE})"
fi
log "  report:                  ${REPORT_PATH}"

# Lean reference is its own fail input.
if [ "$LEAN_VERDICT_RAN" -eq 1 ] && [ "$LEAN_VERDICT_PASS" -ne 1 ]; then
  err "::error::cross-compiler-diff: Lean reference (pipelineGolden) failed"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  err "cross-compiler-diff: FAILED — see ::error:: lines above and ${REPORT_PATH}"
  exit 1
fi

log "cross-compiler-diff: OK"
exit 0
