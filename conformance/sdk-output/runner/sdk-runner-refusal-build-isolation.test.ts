import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, delimiter } from 'node:path';
import { buildSdkTools, runSdkTool, evaluateRefusal } from './sdk-runner.js';

// N-091: the sdk-output runner matches an expected-refusal reason against a
// compiled driver's stderr. For the Rust tool, the pre-N-091 fallback (used
// whenever the pre-built `rs-sdk-tool` binary is missing — e.g. a cold
// checkout) ran `cargo run --release -- <input>`, which compiles AND runs
// the driver in ONE process invocation. Cargo's own build log
// ('Compiling ...', warnings, 'Finished ...') landed in the SAME stderr
// stream `evaluateRefusal` scans for the expected reason, so build noise
// could stand in for the driver's own diagnostic.
//
// This test replaces the real `cargo` binary (via PATH) with a stub that
// behaves exactly like the two cargo subcommands the runner can invoke:
//   - `cargo run ...`   (the old, buggy, build-and-run-in-one-call shape)
//   - `cargo build ...` (the fixed shape: build only, driver run separately)
// Both are made to emit a build-log line containing a marker phrase, and
// have the DRIVER's own refusal message deliberately NOT contain that
// phrase. A correct implementation must never let the marker (which only
// ever appears in build output) satisfy the refusal-reason match.
//
// `buildSdkTools()` is pointed at a scratch `tools/` directory (via its
// `toolsDirOverride` parameter) rather than the real
// `conformance/sdk-output/tools/`. This keeps the test deterministic
// regardless of whether a real `rs-sdk-tool` binary happens to already be
// built in this worktree, and means cleanup only ever touches scratch
// files — never a real (possibly multi-minute) cargo build artifact.

const BUILD_NOISE_MARKER = 'N091_BUILD_NOISE_MARKER_NEVER_THE_REAL_REASON';
const DRIVER_REAL_REFUSAL = 'driver-refusal: artifact-missing-required-field';

let scratchDir: string | undefined;
let savedPath: string | undefined;

afterEach(() => {
  if (savedPath !== undefined) {
    process.env.PATH = savedPath;
    savedPath = undefined;
  }
  if (scratchDir) {
    rmSync(scratchDir, { recursive: true, force: true });
    scratchDir = undefined;
  }
});

/** A fake `cargo` that emits build noise containing BUILD_NOISE_MARKER for
 * both subcommands, and a driver refusal that does NOT contain it. Writes
 * its "compiled" driver binary wherever `--manifest-path` points, so it
 * works against whatever scratch `tools/` directory the test passes in. */
function installFakeCargo(binDir: string): void {
  const script = `#!/usr/bin/env bash
set -e
if [ "$1" == "run" ]; then
  # Old, buggy shape: build and run share one process/one stderr stream.
  echo "   Compiling rs-sdk-tool v0.1.0" >&2
  echo "   ${BUILD_NOISE_MARKER} (unused import warning etc.)" >&2
  echo "    Finished release profile [optimized] target(s) in 0.02s" >&2
  echo "${DRIVER_REAL_REFUSAL}" >&2
  exit 1
elif [ "$1" == "build" ]; then
  # Fixed shape: build only. Writes the "compiled" driver binary, which
  # itself prints ONLY the driver's own message when later run directly.
  manifest=""
  prev=""
  for arg in "$@"; do
    if [ "$prev" == "--manifest-path" ]; then manifest="$arg"; fi
    prev="$arg"
  done
  outdir="$(dirname "$manifest")/target/release"
  mkdir -p "$outdir"
  cat > "$outdir/rs-sdk-tool" <<DRIVER
#!/usr/bin/env bash
echo "${DRIVER_REAL_REFUSAL}" >&2
exit 1
DRIVER
  chmod +x "$outdir/rs-sdk-tool"
  echo "   Compiling rs-sdk-tool v0.1.0" >&2
  echo "   ${BUILD_NOISE_MARKER} (unused import warning etc.)" >&2
  echo "    Finished release profile [optimized] target(s) in 0.02s" >&2
  exit 0
else
  echo "fake cargo: unsupported subcommand $1" >&2
  exit 2
fi
`;
  const cargoPath = join(binDir, 'cargo');
  writeFileSync(cargoPath, script);
  chmodSync(cargoPath, 0o755);
  savedPath = process.env.PATH;
  process.env.PATH = `${binDir}${delimiter}${savedPath}`;
}

describe('N-091: sdk-output runner must not match a refusal reason against the Rust build log', () => {
  it('does not treat a marker that only appears in cargo build output as the driver\'s refusal reason', () => {
    scratchDir = mkdtempSync(join(tmpdir(), 'n091-'));
    const scratchToolsDir = join(scratchDir, 'tools');
    const binDir = join(scratchDir, 'bin');
    mkdirSync(scratchToolsDir, { recursive: true });
    mkdirSync(binDir, { recursive: true });
    installFakeCargo(binDir);

    // No `rs-sdk-tool/target/release/rs-sdk-tool` exists under the fresh
    // scratch toolsDir, so buildSdkTools() is guaranteed to take the "not
    // pre-built" fallback branch under test — deterministic by construction,
    // not by depending on this worktree's real build state.
    const rustTool = buildSdkTools(scratchToolsDir).find((t) => t.name === 'rust');
    expect(rustTool).toBeDefined();

    const inputPath = join(scratchDir, 'input.json');
    writeFileSync(inputPath, '{}');

    const result = runSdkTool(rustTool!, inputPath);

    // The driver must have actually refused (this is a negative/refusal
    // fixture) — that part of the behaviour is not in question here.
    expect(result.success).toBe(false);

    const errors: string[] = [];
    const ok = evaluateRefusal({ pattern: BUILD_NOISE_MARKER }, [result], errors);

    // What this proves: a reason phrase that appears ONLY in cargo's build
    // log, and NOT in the driver's own refusal message, must not satisfy
    // the match. Before N-091's fix, the fallback tool ran `cargo run`
    // (build + run combined), so `result.error` contained both the build
    // log and the driver's message concatenated, and this assertion failed
    // (the marker matched the build noise, not the driver). After the fix,
    // the fallback builds via a separate `cargo build` step first and runs
    // the resulting binary directly, so `result.error` is ONLY the
    // driver's own stderr and the marker is correctly absent from it.
    //
    // What this does NOT prove: that a REAL cargo build log can never
    // coincidentally contain a fixture's expected-reason text (a build log
    // and a driver message could still collide on ordinary English words);
    // it proves only that build output and driver output are no longer the
    // same captured stream, which is the actual defect this item reports.
    // It also does not exercise the Go tool's identical fix (same
    // mechanism, not covered by a dedicated test here) or a real cargo
    // toolchain, and it does not cover a `cargo build` FAILURE whose own
    // error text happens to match a fixture's expected-reason pattern
    // (pre-existing risk, shared by every compiled driver's preBuild, not
    // introduced or closed by this fix).
    expect(result.error).not.toContain(BUILD_NOISE_MARKER);
    expect(ok).toBe(false);
    expect(errors.some((e) => e.includes('not for the expected reason'))).toBe(true);
  });
});
