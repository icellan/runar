import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, delimiter } from 'node:path';
import { buildSdkTools, runSdkTool } from './sdk-tools.js';

// N-174 (sibling of N-091): conformance/sdk-vertical/runner/sdk-tools.ts ran
// the Go SDK tool with `go run ...` UNCONDITIONALLY (no pre-built-binary
// check at all) and fell back to `cargo run ...` for the Rust SDK tool
// whenever its pre-built binary was missing. Both forms compile AND run in
// ONE process invocation, so the build tool's own log ("go: downloading...",
// "Compiling ...", warnings, "Finished ...") lands in the SAME stderr stream
// that `vertical-runner.ts` reports as `result.error` and that a developer
// reading `[tier:<sdk>] driver failed: <error>` has to treat as the driver's
// own diagnostic (vertical-runner.ts:212). Build noise can stand in for, or
// drown out, the driver's own message.
//
// This test replaces the real `go` and `cargo` binaries (via PATH) with
// stubs that behave exactly like the subcommands the runner can invoke:
//   - `go run ...` / `cargo run ...`     (the old, buggy, build-and-run-in-
//                                          one-call shape)
//   - `go build -o ...` / `cargo build ...` (the fixed shape: build only,
//                                          driver run separately)
// Both are made to emit a build-log line containing a marker phrase, and the
// DRIVER's own output is deliberately made NOT to contain that phrase. A
// correct implementation must never let the marker (which only ever appears
// in build output) reach `result.error` / `result.hex`.
//
// `buildSdkTools()` is pointed at a scratch `tools/` directory (via a
// `toolsDirOverride` parameter, added by this change) rather than the real
// `conformance/sdk-output/tools/`. This keeps the test deterministic
// regardless of whether this worktree already has `go-sdk-tool-bin` or
// `rs-sdk-tool/target/release/rs-sdk-tool` built (both already exist in a
// dev worktree, which would otherwise make the "binary missing" fallback
// branch unreachable and the test pass for the wrong reason).

const BUILD_NOISE_MARKER = 'N174_BUILD_NOISE_MARKER_NEVER_THE_REAL_REASON';
const DRIVER_REAL_OUTPUT = 'driver-output-not-the-build-log';

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
 * both subcommands, and a "driver" (once built) that emits only
 * DRIVER_REAL_OUTPUT. Writes its "compiled" driver binary wherever
 * `--manifest-path` points, so it works against whatever scratch `tools/`
 * directory the test passes in. */
function installFakeCargo(binDir: string): void {
  const script = `#!/usr/bin/env bash
set -e
if [ "$1" == "run" ]; then
  # Old, buggy shape: build and run share one process/one stderr stream.
  echo "   Compiling rs-sdk-tool v0.1.0" >&2
  echo "   ${BUILD_NOISE_MARKER} (unused import warning etc.)" >&2
  echo "    Finished release profile [optimized] target(s) in 0.02s" >&2
  echo "${DRIVER_REAL_OUTPUT}" >&2
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
echo "${DRIVER_REAL_OUTPUT}" >&2
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

/** A fake `go` with the same two-subcommand shape as installFakeCargo. */
function installFakeGo(binDir: string): void {
  const script = `#!/usr/bin/env bash
set -e
if [ "$1" == "run" ]; then
  echo "go: downloading noop" >&2
  echo "   ${BUILD_NOISE_MARKER} (go run build noise)" >&2
  echo "${DRIVER_REAL_OUTPUT}" >&2
  exit 1
elif [ "$1" == "build" ]; then
  # args: build -o <outpath> <src.go>
  outpath=""
  prev=""
  for arg in "$@"; do
    if [ "$prev" == "-o" ]; then outpath="$arg"; fi
    prev="$arg"
  done
  mkdir -p "$(dirname "$outpath")"
  cat > "$outpath" <<DRIVER
#!/usr/bin/env bash
echo "${DRIVER_REAL_OUTPUT}" >&2
exit 1
DRIVER
  chmod +x "$outpath"
  echo "   ${BUILD_NOISE_MARKER} (go build noise)" >&2
  exit 0
else
  echo "fake go: unsupported subcommand $1" >&2
  exit 2
fi
`;
  const goPath = join(binDir, 'go');
  writeFileSync(goPath, script);
  chmodSync(goPath, 0o755);
  savedPath = process.env.PATH;
  process.env.PATH = `${binDir}${delimiter}${savedPath}`;
}

describe('N-174: sdk-vertical runner must not match tier output against the Rust/Go build log', () => {
  it('rust: a marker that only appears in cargo build output must not reach result.error', () => {
    scratchDir = mkdtempSync(join(tmpdir(), 'n174-rust-'));
    const scratchToolsDir = join(scratchDir, 'tools');
    const binDir = join(scratchDir, 'bin');
    mkdirSync(scratchToolsDir, { recursive: true });
    mkdirSync(binDir, { recursive: true });
    installFakeCargo(binDir);

    // No `rs-sdk-tool/target/release/rs-sdk-tool` exists under the fresh
    // scratch toolsDir, so buildSdkTools() is guaranteed to take the "not
    // pre-built" fallback branch under test — deterministic by construction.
    const rustTool = buildSdkTools(scratchToolsDir).find((t) => t.name === 'rust');
    expect(rustTool).toBeDefined();

    const inputPath = join(scratchDir, 'input.json');
    writeFileSync(inputPath, '{}');

    const result = runSdkTool(rustTool!, inputPath);

    expect(result.success).toBe(false);

    // What this proves: a phrase that appears ONLY in cargo's build log, and
    // NOT in the driver's own message, must not reach `result.error` — the
    // exact field `vertical-runner.ts` reports verbatim
    // (`[tier:${r.sdk}] driver failed: ${r.error}`) and compares tiers by.
    // Before the fix, the fallback ran `cargo run` (build + run combined),
    // so `result.error` contained the build log and the marker; this
    // assertion failed. After the fix, the fallback builds via a separate
    // `cargo build` step first (discarded unless it fails) and runs the
    // resulting binary directly, so `result.error` is only the driver's own
    // stderr.
    //
    // What this does NOT prove: that a REAL cargo build log can never
    // coincidentally contain a fixture-relevant phrase (a build log and a
    // driver message could still collide on ordinary English words); that a
    // `cargo build` FAILURE's own stderr (which legitimately IS build output
    // in that case) cannot contain this marker — that path is unchanged by
    // this fix and shared by every compiled driver's preBuild; or the Go
    // tool's identical fix, which is covered by the next test instead.
    expect(result.error).not.toContain(BUILD_NOISE_MARKER);
    expect(result.error).toContain(DRIVER_REAL_OUTPUT);
  });

  it('go: a marker that only appears in `go run` build output must not reach result.error', () => {
    scratchDir = mkdtempSync(join(tmpdir(), 'n174-go-'));
    const scratchToolsDir = join(scratchDir, 'tools');
    const binDir = join(scratchDir, 'bin');
    mkdirSync(scratchToolsDir, { recursive: true });
    mkdirSync(binDir, { recursive: true });
    installFakeGo(binDir);

    // No `go-sdk-tool-bin` exists under the fresh scratch toolsDir, so a
    // fixed buildSdkTools() must take its "not pre-built" fallback branch.
    // At HEAD (no such branch exists at all) the tool is unconditionally
    // `go run`, so this is red regardless of what is on disk.
    const goTool = buildSdkTools(scratchToolsDir).find((t) => t.name === 'go');
    expect(goTool).toBeDefined();

    const inputPath = join(scratchDir, 'input.json');
    writeFileSync(inputPath, '{}');

    const result = runSdkTool(goTool!, inputPath);

    expect(result.success).toBe(false);
    // See the rust test above for what this does and does not prove; same
    // mechanism, applied to `go run` instead of `cargo run`.
    expect(result.error).not.toContain(BUILD_NOISE_MARKER);
    expect(result.error).toContain(DRIVER_REAL_OUTPUT);
  });
});
