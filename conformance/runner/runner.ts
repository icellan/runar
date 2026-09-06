import { readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync, rmSync } from 'fs';
import { join, basename, resolve, dirname, extname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { execSync, spawn } from 'child_process';
import os from 'os';
import { JavaDaemon } from './java-daemon.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
/** Best-effort recursive remove. Silently swallows ENOENT and EBUSY so a
 *  cleanup pass on a never-created or already-deleted path is a no-op. */
function safeRm(p: string): void {
  try { rmSync(p, { recursive: true, force: true }); } catch { /* ignore */ }
}

const GO_COMPILER_DIR = resolve(__dirname, '../../compilers/go');
const RUST_COMPILER_DIR = resolve(__dirname, '../../compilers/rust');
const PYTHON_COMPILER_DIR = resolve(__dirname, '../../compilers/python');
const ZIG_COMPILER_DIR = resolve(__dirname, '../../compilers/zig');
const RUBY_COMPILER_DIR = resolve(__dirname, '../../compilers/ruby');
const JAVA_COMPILER_DIR = resolve(__dirname, '../../compilers/java');
const REPO_ROOT = resolve(__dirname, '../..');

// ---------------------------------------------------------------------------
// Async subprocess primitive
// ---------------------------------------------------------------------------
//
// Replaces the legacy `execSync` calls. Each compiler invocation now spawns
// directly (no shell, args passed as an array) so we can run many in parallel
// without blocking the event loop. Output is captured with a per-process
// buffer cap so a runaway compiler can't OOM the runner.

interface RunResult {
  stdout: string;
  stderr: string;
  /**
   * The child's exit status. `-1` means the child never exited normally —
   * it died from a signal, or the spawn itself failed. NEVER coalesce that
   * to 0: a killed child's captured stdout is truncated (often empty), and
   * reading it as a successful compile turns a dead subprocess into a fake
   * cross-tier divergence. See `abnormal` below.
   */
  code: number;
  timedOut: boolean;
  /** Signal that killed the child, or null if it exited on its own. */
  signal: NodeJS.Signals | null;
  /** True when output exceeded the capture cap and the child was killed. */
  truncated: boolean;
  /**
   * Human description of an ABNORMAL termination (timeout / signal / capture
   * overflow / spawn failure), or undefined when the child exited on its own
   * — whatever its status. Callers MUST treat a set value as a harness fault,
   * not as compiler output: the captured stdout is not a compile result.
   */
  abnormal?: string;
  error?: Error;
}

interface RunOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  maxBuffer?: number;
  /** Context (usually the fixture / source file) named in harness faults. */
  label?: string;
}

// ---------------------------------------------------------------------------
// Harness faults
// ---------------------------------------------------------------------------
//
// A HARNESS fault is the runner (or the host) failing to obtain a compiler's
// output — a timeout, a signal kill, an over-cap capture, a failed spawn. It
// is categorically NOT a conformance result: it says nothing about whether the
// tiers agree. Recording every one centrally means a resource problem can
// never be laundered into a cross-tier verdict, in either direction:
//
//   * it cannot masquerade as a DIVERGENCE — the fault is reported as a
//     harness error and exits with a dedicated status (see runner/index.ts);
//   * it cannot masquerade as AGREEMENT — a fixture whose tier died still
//     fails, because the fault list is non-empty even if every surviving
//     tier happened to match.
//
// Historically `runCmd` did `code: code ?? 0`, which mapped a SIGKILLed child
// (Node reports `code === null`, `signal === 'SIGKILL'`) onto exit status 0.
// The native driver then took the child's partially-drained stdout as the
// script hex and returned `success: true`. An empty pipe surfaced as
// "reported success but produced empty hex: [zig, ruby]" and a partly-drained
// one as "majority [6 tiers] vs [x] identical up to length" — both reported
// as cross-tier divergences of the compilers, which were in fact innocent.

export interface HarnessFault {
  /** Command basename, e.g. `ruby` / `runar-zig`. */
  cmd: string;
  kind: 'timeout' | 'signal' | 'output-truncated' | 'spawn-error';
  /** Human description, including the source file when known. */
  detail: string;
  durationMs: number;
}

const harnessFaults: HarnessFault[] = [];

/** Every abnormal subprocess termination recorded since `resetHarnessFaults()`. */
export function getHarnessFaults(): HarnessFault[] {
  return harnessFaults.slice();
}

export function resetHarnessFaults(): void {
  harnessFaults.length = 0;
}

function recordHarnessFault(f: HarnessFault): void {
  harnessFaults.push(f);
}

// ---------------------------------------------------------------------------
// Subprocess accounting
// ---------------------------------------------------------------------------
//
// Every compiler invocation goes through `runCmd`, so counting here gives an
// exact process-spawn tally for a run. Used by
// `runner/__tests__/single-spawn.test.ts` to keep the "one spawn per
// (fixture, format, tier)" invariant from regressing back to the old
// `--emit-ir` + `--hex` double-spawn.

let spawnTotal = 0;
const spawnByCommand = new Map<string, number>();

export interface SpawnStats {
  /** Total child processes spawned since the last `resetSpawnStats()`. */
  total: number;
  /** Per-command tally, keyed by the command's basename. */
  byCommand: Record<string, number>;
}

export function getSpawnStats(): SpawnStats {
  return { total: spawnTotal, byCommand: Object.fromEntries(spawnByCommand) };
}

export function resetSpawnStats(): void {
  spawnTotal = 0;
  spawnByCommand.clear();
}

function runCmd(cmd: string, args: string[], opts: RunOptions = {}): Promise<RunResult> {
  spawnTotal++;
  const key = basename(cmd);
  spawnByCommand.set(key, (spawnByCommand.get(key) ?? 0) + 1);
  const t0 = performance.now();
  const label = opts.label;
  return new Promise((resolvePromise) => {
    const proc = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const cap = opts.maxBuffer ?? 10 * 1024 * 1024;
    let outLen = 0;
    let errLen = 0;
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    let timedOut = false;
    let settled = false;

    const timer = opts.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          try {
            proc.kill('SIGKILL');
          } catch {
            // ignore
          }
        }, opts.timeoutMs)
      : null;

    proc.stdout.on('data', (chunk: Buffer) => {
      outLen += chunk.length;
      if (outLen > cap) {
        try { proc.kill('SIGKILL'); } catch { /* ignore */ }
        return;
      }
      outChunks.push(chunk);
    });
    proc.stderr.on('data', (chunk: Buffer) => {
      errLen += chunk.length;
      if (errLen > cap) {
        try { proc.kill('SIGKILL'); } catch { /* ignore */ }
        return;
      }
      errChunks.push(chunk);
    });

    proc.on('error', (err) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      const abnormal = `failed to spawn ${basename(cmd)}: ${err.message}`;
      recordHarnessFault({
        cmd: basename(cmd),
        kind: 'spawn-error',
        detail: `${abnormal}${label ? ` (${label})` : ''}`,
        durationMs: Math.round(performance.now() - t0),
      });
      resolvePromise({
        stdout: Buffer.concat(outChunks).toString('utf-8'),
        stderr: Buffer.concat(errChunks).toString('utf-8'),
        code: -1,
        timedOut,
        signal: null,
        truncated: false,
        abnormal,
        error: err,
      });
    });

    proc.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      const durationMs = Math.round(performance.now() - t0);
      const truncated = outLen > cap || errLen > cap;

      // Classify an abnormal death. Order matters: the capture-overflow and
      // timeout kills are OUR SIGKILLs, so they must be named before the
      // generic "killed by <signal>" fallback (which covers an OS memory-
      // pressure kill, a crashed compiler, or an operator's ^C).
      let abnormal: string | undefined;
      let kind: HarnessFault['kind'] | undefined;
      if (truncated) {
        abnormal =
          `output exceeded the ${cap}-byte capture cap after ${durationMs}ms ` +
          `(killed; stdout ${outLen}B, stderr ${errLen}B — captured output is TRUNCATED)`;
        kind = 'output-truncated';
      } else if (timedOut) {
        abnormal =
          `timed out after ${opts.timeoutMs}ms and was SIGKILLed ` +
          `(captured stdout ${outLen}B is TRUNCATED, not a compile result)`;
        kind = 'timeout';
      } else if (code === null) {
        abnormal =
          `killed by ${signal ?? 'an unknown signal'} after ${durationMs}ms ` +
          `(captured stdout ${outLen}B is TRUNCATED, not a compile result)`;
        kind = 'signal';
      }
      if (abnormal && kind) {
        recordHarnessFault({
          cmd: basename(cmd),
          kind,
          detail: `${basename(cmd)} ${abnormal}${label ? ` (${label})` : ''}`,
          durationMs,
        });
      }

      resolvePromise({
        stdout: Buffer.concat(outChunks).toString('utf-8'),
        stderr: Buffer.concat(errChunks).toString('utf-8'),
        // `code ?? -1`, NOT `code ?? 0`: a signal death has a null status and
        // must never be readable as a clean exit.
        code: code ?? -1,
        timedOut,
        signal: signal ?? null,
        truncated,
        abnormal,
      });
    });
  });
}

/**
 * One-line description of how a child process ended, for error messages.
 * Prefers the abnormal-termination reason over the bare status, so a message
 * can never read "exit -1" when what actually happened was "SIGKILLed after
 * the 180s timeout".
 */
function describeExit(res: RunResult): string {
  return res.abnormal ?? `exit ${res.code}`;
}

/**
 * Per-invocation wall-clock budget for a native compiler.
 *
 * This is a HANG detector, not a performance budget, and it must not fire on
 * a merely-slow host: a timeout kill destroys the child's output mid-pipe.
 * Before the harness-fault work below, that truncation was silently read as a
 * compile result and surfaced as a fake cross-tier divergence. The budget is
 * now generous (matching `JavaDaemon`'s 180s per-request deadline, which was
 * raised for the same reason) so that saturating the host produces slow runs
 * rather than dead children. Worst observed single invocation on an 8-core
 * host: 5.6s at the default concurrency, 33s at 10x oversubscription.
 */
function compileTimeoutMs(): number {
  const env = process.env.RUNAR_CONFORMANCE_COMPILE_TIMEOUT_MS;
  if (env) {
    const n = parseInt(env, 10);
    if (Number.isFinite(n) && n >= 1000) return n;
  }
  return 180_000;
}

/**
 * Locate the tsx loader entry as a `file://` URL so we can pass it to
 * `node --import`. tsx is hoisted under `conformance/node_modules` (pnpm
 * doesn't dedupe it to repo root). We try a small list of well-known
 * locations and fall back to literal `'tsx'` (which only resolves when run
 * from a directory whose node_modules contains tsx).
 *
 * Replaces the legacy `npx tsx <args>` shell invocation: each `npx tsx`
 * paid ~50–200ms of package-manager resolution per call, which adds up
 * quickly across an N×M conformance matrix.
 */
let cachedTsxLoader: string | null = null;
function resolveTsxLoader(): string {
  if (cachedTsxLoader) return cachedTsxLoader;
  const candidates = [
    join(REPO_ROOT, 'conformance/node_modules/tsx/dist/loader.mjs'),
    join(REPO_ROOT, 'node_modules/tsx/dist/loader.mjs'),
    join(REPO_ROOT, 'integration/ts/node_modules/tsx/dist/loader.mjs'),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      cachedTsxLoader = pathToFileURL(p).href;
      return cachedTsxLoader;
    }
  }
  // Fall through: rely on Node's package resolution with cwd-driven lookup.
  // Callers pass cwd=REPO_ROOT by default, so this will only succeed if tsx
  // is symlinked under <repo>/node_modules.
  cachedTsxLoader = 'tsx';
  return cachedTsxLoader;
}

function cargoAwareEnv(): NodeJS.ProcessEnv {
  const home = process.env.HOME ?? '';
  const cargoBin = home ? `${home}/.cargo/bin` : '';
  const currentPath = process.env.PATH ?? '';
  return {
    ...process.env,
    PATH: cargoBin ? `${cargoBin}:${currentPath}` : currentPath,
  };
}

// ---------------------------------------------------------------------------
// Constant-folding mode toggle
// ---------------------------------------------------------------------------
//
// Historically the conformance runner always passed `--disable-constant-folding`
// to every compiler so that ANF + hex golden comparisons stay byte-stable.
// That left fold-on cross-tier parity uncovered in CI: a latent fold bug in
// any one of the 7 compilers could land unnoticed because the runner never
// exercised the fold path.
//
// `RUNAR_DISABLE_CONSTANT_FOLDING=0` flips the toggle off — every compiler
// then runs with its default (folding ON), and the runner skips the
// golden-hex / golden-IR file comparison (the goldens were checked in
// fold-OFF). Cross-tier parity (every compiler produces the same hex / IR
// for a given fixture) is still strictly enforced.
//
// Default is `1` (folding off) for backward compatibility with the existing
// fold-off CI step + every previously-stamped golden file.
function constantFoldingDisabled(): boolean {
  const v = process.env.RUNAR_DISABLE_CONSTANT_FOLDING;
  if (v === undefined) return true;
  return v !== '0';
}
function foldFlag(): string[] {
  return constantFoldingDisabled() ? ['--disable-constant-folding'] : [];
}

// ---------------------------------------------------------------------------
// Fold-ON allowlist
// ---------------------------------------------------------------------------
//
// `conformance/fold-on-allowlist.json` lists fixtures (and optionally specific
// format variants) that are known to fail the fold-ON cross-tier check but
// pass fold-OFF. Each entry MUST carry a per-fixture `reason` string — a
// bare list is rejected at load time. The fold-OFF run still exercises
// every entry, so allowlisting here only relaxes the dual-mode check, not
// the canonical golden coverage.

interface FoldOnSkipEntry {
  fixture: string;
  formats?: string[];
  reason: string;
  tracking?: string;
}

let cachedFoldOnSkip: FoldOnSkipEntry[] | null = null;
function loadFoldOnAllowlist(): FoldOnSkipEntry[] {
  if (cachedFoldOnSkip !== null) return cachedFoldOnSkip;
  const path = resolve(__dirname, '../fold-on-allowlist.json');
  if (!existsSync(path)) {
    cachedFoldOnSkip = [];
    return cachedFoldOnSkip;
  }
  try {
    const raw = JSON.parse(readFileSync(path, 'utf-8')) as { skip?: unknown };
    const list: FoldOnSkipEntry[] = [];
    if (Array.isArray(raw.skip)) {
      for (const ent of raw.skip) {
        if (
          ent &&
          typeof ent === 'object' &&
          typeof (ent as Record<string, unknown>).fixture === 'string' &&
          typeof (ent as Record<string, unknown>).reason === 'string' &&
          ((ent as Record<string, unknown>).reason as string).trim().length > 0
        ) {
          const e = ent as Record<string, unknown>;
          list.push({
            fixture: e.fixture as string,
            formats: Array.isArray(e.formats) ? (e.formats as string[]) : undefined,
            reason: e.reason as string,
            tracking: typeof e.tracking === 'string' ? e.tracking : undefined,
          });
        } else {
          throw new Error(
            'fold-on-allowlist.json entry rejected: every entry must be ' +
            '{ fixture: string, reason: string (non-empty), formats?: string[], tracking?: string }',
          );
        }
      }
    }
    cachedFoldOnSkip = list;
    return cachedFoldOnSkip;
  } catch (err) {
    throw new Error(
      `fold-on-allowlist.json parse error: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Return the matching allowlist reason if (fixture, format) is allowlisted
 * under fold-ON, or null otherwise. When constant folding is disabled
 * (default fold-OFF mode), the allowlist is ignored — every fixture must
 * pass the canonical golden-stamped check.
 */
function foldOnSkipReason(fixture: string, format: string): string | null {
  if (constantFoldingDisabled()) return null;
  const list = loadFoldOnAllowlist();
  for (const entry of list) {
    if (entry.fixture !== fixture) continue;
    if (!entry.formats || entry.formats.includes(format)) {
      return entry.reason;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ConformanceResult {
  testName: string;
  /** Source format used (e.g. '.runar.ts', '.runar.sol', '.runar.move', '.runar.py', '.runar.go', '.runar.rs', '.runar.rb', '.runar.zig') */
  format?: string;
  tsCompiler: CompilerOutput;
  goCompiler?: CompilerOutput;
  rustCompiler?: CompilerOutput;
  pythonCompiler?: CompilerOutput;
  zigCompiler?: CompilerOutput;
  rubyCompiler?: CompilerOutput;
  javaCompiler?: CompilerOutput;
  irMatch: boolean;
  scriptMatch: boolean;
  errors: string[];
}

/**
 * Known input format extensions and which compilers support them.
 */
export const INPUT_FORMATS = [
  { ext: '.runar.ts',   compilers: ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const },
  { ext: '.runar.sol',  compilers: ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const },
  { ext: '.runar.move', compilers: ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const },
  { ext: '.runar.py',   compilers: ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const },
  { ext: '.runar.go',   compilers: ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const },
  { ext: '.runar.rs',   compilers: ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const },
  { ext: '.runar.rb',   compilers: ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const },
  { ext: '.runar.zig',  compilers: ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const },
  { ext: '.runar.java', compilers: ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const },
] as const;

type CompilerId = (typeof INPUT_FORMATS)[number]['compilers'][number];
const EMPTY_COMPILERS: readonly CompilerId[] = [];

export interface CompilerOutput {
  irJson: string;        // canonical JSON of ANF IR
  scriptHex: string;     // compiled Bitcoin Script
  scriptAsm: string;     // human-readable asm
  success: boolean;
  error?: string;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Compiler detection
// ---------------------------------------------------------------------------

/** Check whether the Go compiler binary is available, falling back to `go run`. */
//
// NOTE on search-path strategy: GitHub Actions jobs that consume cross-job
// artifacts (`actions/download-artifact`) drop the binary into the workflow
// checkout root by default — i.e. `process.cwd()`. We therefore include
// `process.cwd()` (and an explicit `<cwd>/runar-go` candidate) so a CI step
// like `chmod +x runar-go && pnpm run conformance` works without having to
// teach every workflow about the runner's internal layout. This is
// forward-compatible: future workflows can keep dropping artifacts at the
// repo root and the runner will pick them up.
export function findGoBinary(): string | null {
  const candidates = [
    join(GO_COMPILER_DIR, 'runar-go'),
    join(GO_COMPILER_DIR, 'runar-go.exe'),
    join(process.cwd(), 'runar-go'),
    join(process.cwd(), 'runar-go.exe'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  // Try PATH
  try {
    execSync('which runar-go', { stdio: 'pipe' });
    return 'runar-go';
  } catch {
    // Fallback: run module from its own working directory.
    if (existsSync(join(GO_COMPILER_DIR, 'main.go'))) {
      try {
        execSync('go version', { stdio: 'pipe' });
        return 'go run .';
      } catch {
        // Go toolchain not available
      }
    }
    return null;
  }
}

/** Check whether the Rust compiler binary is available, falling back to `cargo run`. */
// See findGoBinary above for the rationale on `process.cwd()` candidates: CI
// jobs that download the `runar-rust` artifact land it at the workflow root.
export function findRustBinary(): string | null {
  const candidates = [
    join(RUST_COMPILER_DIR, 'target/release/runar-compiler-rust'),
    join(RUST_COMPILER_DIR, 'target/debug/runar-compiler-rust'),
    join(RUST_COMPILER_DIR, 'runar-compiler-rust'),
    join(process.cwd(), 'runar-compiler-rust'),
    join(process.cwd(), 'runar-compiler-rust.exe'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  // Try PATH
  try {
    execSync('which runar-compiler-rust', { stdio: 'pipe', env: cargoAwareEnv() });
    return 'runar-compiler-rust';
  } catch {
    // Fallback: try `cargo run` from the compiler directory
    if (existsSync(join(RUST_COMPILER_DIR, 'Cargo.toml'))) {
      try {
        execSync('cargo --version', { stdio: 'pipe', env: cargoAwareEnv() });
        return `cargo run --release --manifest-path ${join(RUST_COMPILER_DIR, 'Cargo.toml')} --`;
      } catch {
        // Cargo not available
      }
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Argv splitting for find* helpers that may return a multi-token shell phrase.
// ---------------------------------------------------------------------------
//
// `findGoBinary()` etc. return strings like `"go run ."` or
// `"cargo run --release --manifest-path /path/Cargo.toml --"`. The legacy
// runner happily concatenated these into a shell command; the new spawn-based
// runner wants `[cmd, ...args]`. We split on whitespace — paths with spaces
// would be a problem, but the strings emitted by find* helpers never contain
// such paths.
function splitCmd(s: string): { cmd: string; args: string[] } {
  const parts = s.split(/\s+/).filter(Boolean);
  if (parts.length === 0) {
    return { cmd: '', args: [] };
  }
  return { cmd: parts[0]!, args: parts.slice(1) };
}

// ---------------------------------------------------------------------------
// Compiler invocations
// ---------------------------------------------------------------------------

/**
 * Run the TypeScript reference compiler on the given source.
 *
 * Invokes runar-cli to emit an artifact JSON, then reads script/IR from the
 * generated artifact instead of parsing human-readable CLI stdout.
 *
 * Uses `node --import tsx` instead of `npx tsx` to avoid the package-manager
 * resolution overhead that `npx` pays on every invocation.
 */
async function runTsCompiler(source: string, sourceFile: string): Promise<CompilerOutput> {
  const start = performance.now();
  let tmpFile = '';
  let artifactDir = '';
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    // Unique per invocation. The runner compiles fixtures CONCURRENTLY, and this
    // path was the only one in the file keyed on the bare basename — every other
    // temp path (the native driver, and all nine parse-only drivers) already
    // carries a `pid-timestamp-random` stem. Two concurrent compiles that resolve
    // to the same basename therefore raced on one file: whichever wrote last won,
    // and the other tier compiled the wrong source, surfacing as a spurious
    // "IR mismatch between compilers". Observed intermittently on add-raw-output /
    // add-data-output — a flaky gate is a gate that can be re-run until green.
    tmpFile = join(
      tmpDir,
      `ts-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`,
    );
    writeFileSync(tmpFile, source, 'utf-8');

    artifactDir = join(tmpDir, `artifacts-ts-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    if (!existsSync(artifactDir)) mkdirSync(artifactDir, { recursive: true });

    const cliEntry = resolve(__dirname, '../../packages/runar-cli/src/bin.ts');
    const tsxLoader = resolveTsxLoader();
    const result = await runCmd(
      'node',
      ['--import', tsxLoader, cliEntry, 'compile', tmpFile, '--ir', ...foldFlag(), '-o', artifactDir],
      // 180_000ms: tsx pays a cold-start cost per invocation; the prior 30s
      // budget tripped on arithmetic / blake3 / convergence-proof on slower
      // hosts.
      { timeoutMs: 180_000, cwd: REPO_ROOT, label: `ts on ${basename(sourceFile)}` },
    );
    if (result.code !== 0) {
      throw new Error(
        `TS compiler ${describeExit(result)}: ${result.stderr || result.stdout}`,
      );
    }

    const baseName = basename(tmpFile, extname(tmpFile));
    const artifactPath = join(artifactDir, `${baseName}.json`);
    if (!existsSync(artifactPath)) {
      throw new Error(`TS artifact not found: ${artifactPath}`);
    }

    const artifact = JSON.parse(readFileSync(artifactPath, 'utf-8'), (_k, v) => {
      if (typeof v === 'string' && /^-?\d+n$/.test(v)) {
        const asBigInt = BigInt(v.slice(0, -1));
        if (asBigInt >= BigInt(Number.MIN_SAFE_INTEGER) && asBigInt <= BigInt(Number.MAX_SAFE_INTEGER)) {
          return Number(asBigInt);
        }
        // Oversize bigints — keep the canonical JS BigInt `n` suffix so
        // downstream IR consumers can distinguish a decimal-encoded big
        // integer from a hex-encoded ByteString literal (which never
        // carries the suffix). Stripping the suffix would silently make
        // the two indistinguishable; see BUG-001.
        return asBigInt.toString() + 'n';
      }
      return v;
    }) as {
      ir?: { anf?: unknown };
      script?: string;
      asm?: string;
    };

    const irOutput = artifact.ir?.anf ? JSON.stringify(artifact.ir.anf) : '';
    const scriptHex = artifact.script ?? '';
    const scriptAsm = artifact.asm ?? '';
    // Same contract as the native tiers' `requireHex`: no fixture compiles to
    // the empty script, so an artifact without one is a broken emit or a torn
    // write — fail the TS tier by name rather than feeding `''` into the
    // parity comparison as if it were this tier's opinion.
    if (scriptHex.trim() === '') {
      throw new Error(`TS artifact ${artifactPath} carries no script hex`);
    }

    const durationMs = performance.now() - start;
    return {
      irJson: canonicalizeJson(irOutput),
      scriptHex,
      scriptAsm,
      success: true,
      durationMs,
    };
  } catch (err) {
    const durationMs = performance.now() - start;
    return {
      irJson: '',
      scriptHex: '',
      scriptAsm: '',
      success: false,
      error: err instanceof Error ? err.message : String(err),
      durationMs,
    };
  } finally {
    if (tmpFile) safeRm(tmpFile);
    if (artifactDir) safeRm(artifactDir);
  }
}

// ---------------------------------------------------------------------------
// Native (non-TS) compiler driver — ONE implementation for all six tiers
// ---------------------------------------------------------------------------
//
// Go / Rust / Python / Zig / Ruby / Java previously each carried their own
// copy of "write temp source, run `--emit-ir`, run `--hex`, canonicalize".
// That was six places to keep in sync AND two process spawns per (fixture,
// format, tier) — the dominant cost of the conformance job.
//
// Single-spawn mode: tiers whose CLI accepts `--emit-ir-to <path>` get
// `--source X --hex --emit-ir-to Y` in ONE invocation; the IR lands in the
// file (byte-identical to what `--emit-ir` prints — the CLIs share the
// serializer) while the hex comes back on stdout. Tiers without the flag,
// and tiers whose on-disk binary predates it, fall back to the historical
// two-spawn path with no loss of coverage.

interface NativeCompilerSpec {
  id: Exclude<CompilerId, 'ts'>;
  /** Locate the binary (or interpreter invocation phrase); null = unavailable. */
  find: () => string | null;
  /** Working directory for the child process. */
  cwd: string;
  /** Optional environment override (Rust needs ~/.cargo/bin on PATH). */
  env?: () => NodeJS.ProcessEnv;
  /**
   * Whether this tier's CLI supports `--emit-ir-to <path>` (write the IR to a
   * file, keep compiling). `false` pins the tier to the two-spawn path.
   */
  combined: boolean;
  timeoutMs: number;
  /**
   * When true, a non-zero exit is tolerated AS LONG AS the IR was produced;
   * scriptHex is then left empty. Preserves the Java one-shot path's historical
   * leniency (`compareScript` still treats success-with-empty-hex as a
   * mismatch, so nothing is silently swallowed).
   */
  tolerateHexFailure?: boolean;
}

const NATIVE_COMPILERS: Record<Exclude<CompilerId, 'ts'>, NativeCompilerSpec> = {
  go: { id: 'go', find: findGoBinary, cwd: GO_COMPILER_DIR, combined: true, timeoutMs: compileTimeoutMs() },
  rust: { id: 'rust', find: findRustBinary, cwd: RUST_COMPILER_DIR, env: cargoAwareEnv, combined: true, timeoutMs: compileTimeoutMs() },
  python: { id: 'python', find: () => findPythonCompiler(), cwd: PYTHON_COMPILER_DIR, combined: true, timeoutMs: compileTimeoutMs() },
  zig: { id: 'zig', find: findZigBinary, cwd: ZIG_COMPILER_DIR, combined: true, timeoutMs: compileTimeoutMs() },
  ruby: { id: 'ruby', find: findRubyBinary, cwd: RUBY_COMPILER_DIR, combined: true, timeoutMs: compileTimeoutMs() },
  java: { id: 'java', find: findJavaBinary, cwd: JAVA_COMPILER_DIR, combined: true, timeoutMs: compileTimeoutMs(), tolerateHexFailure: true },
};

/**
 * Stderr signatures every CLI framework we drive emits for an unrecognized
 * flag (Go `flag`, clap, argparse, Ruby OptionParser, the Java hand-rolled
 * parser). Used to distinguish "this binary predates --emit-ir-to" from a
 * genuine compile failure.
 */
const UNKNOWN_FLAG_RE =
  /flag provided but not defined|unexpected argument|unrecognized argument|invalid option|unknown flag|unknown option|no such option/i;

/** Tiers whose on-disk binary turned out NOT to support `--emit-ir-to`. */
const combinedModeUnsupported = new Set<CompilerId>();

/**
 * Reject any result whose child did not exit under its own control.
 *
 * Every caller below branches on `res.code`, and several are deliberately
 * lenient about a non-zero status (`tolerateHexFailure`, the stale-binary
 * probe). That leniency is only ever sound for a compiler that RAN and
 * decided to fail. A SIGKILLed child has no verdict at all — it has a
 * half-drained pipe — so it must be rejected before any of that logic runs.
 */
function requireCleanExit(spec: NativeCompilerSpec, res: RunResult, phase: string): void {
  if (!res.abnormal) return;
  // The `HARNESS:` prefix carries the classification into the per-fixture
  // error line, so the board never shows a dead subprocess as if the tier had
  // an opinion about the script.
  throw new Error(`HARNESS: ${spec.id} ${phase}: ${res.abnormal}`);
}

/**
 * `--hex` is contracted to print the locking script on stdout. A zero exit
 * with nothing on stdout is therefore never a legitimate "this contract
 * compiles to the empty script" — it is a broken tier or a lost pipe. Fail
 * the tier by name (with its stderr) instead of handing `''` to the parity
 * comparison, where it would surface as a cross-tier divergence and put the
 * blame on the six honest tiers.
 */
function requireHex(spec: NativeCompilerSpec, res: RunResult, phase: string): string {
  const hex = res.stdout.trim();
  if (hex === '') {
    throw new Error(
      `${spec.id} ${phase} exited 0 but wrote NOTHING to stdout ` +
      `(stderr: ${res.stderr.trim() || '<empty>'})`,
    );
  }
  return hex;
}

/**
 * Compile `source` with a native tier and return both its ANF IR and its
 * script hex. Returns undefined when the tier's binary is not on disk.
 */
async function runNativeCompiler(
  spec: NativeCompilerSpec,
  source: string,
  sourceFile: string,
): Promise<CompilerOutput | undefined> {
  const binary = spec.find();
  if (!binary) return undefined;
  const { cmd, args: binArgs } = splitCmd(binary);
  const env = spec.env?.();
  const runOpts: RunOptions = {
    timeoutMs: spec.timeoutMs,
    cwd: spec.cwd,
    env,
    label: `${spec.id} on ${basename(sourceFile)}`,
  };

  const start = performance.now();
  const tmpDir = join(__dirname, '..', '.tmp');
  const stem = `${spec.id}-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const tmpFile = join(tmpDir, `${stem}-${basename(sourceFile)}`);
  const irFile = join(tmpDir, `${stem}.ir.json`);

  try {
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    writeFileSync(tmpFile, source, 'utf-8');

    let irOutput: string | null = null;
    let scriptHexOutput = '';

    // --- single-spawn path -------------------------------------------------
    if (spec.combined && !combinedModeUnsupported.has(spec.id)) {
      const res = await runCmd(
        cmd,
        [...binArgs, '--source', tmpFile, '--hex', '--emit-ir-to', irFile, ...foldFlag()],
        runOpts,
      );
      // An abnormal death (timeout / signal / over-cap capture) short-circuits
      // EVERY branch below, `tolerateHexFailure` included. Whatever landed in
      // stdout or in the IR file is a torn half-write, not compiler output, and
      // must never reach the parity comparison as this tier's script.
      requireCleanExit(spec, res, '--hex --emit-ir-to');
      if (existsSync(irFile)) {
        // The CLI writes the IR file BEFORE emitting hex, so an IR file plus a
        // non-zero exit means the hex stage failed — a real compile error.
        if (res.code === 0) {
          irOutput = readFileSync(irFile, 'utf-8').trim();
          scriptHexOutput = requireHex(spec, res, '--hex --emit-ir-to');
        } else if (spec.tolerateHexFailure) {
          irOutput = readFileSync(irFile, 'utf-8').trim();
          scriptHexOutput = '';
        } else {
          throw new Error(
            `${spec.id} --hex --emit-ir-to ${describeExit(res)}: ${res.stderr || res.stdout}`,
          );
        }
      } else if (res.code !== 0 && UNKNOWN_FLAG_RE.test(res.stderr)) {
        // Stale binary built before --emit-ir-to landed. Remember it and use
        // the two-spawn path for the rest of this process.
        combinedModeUnsupported.add(spec.id);
      } else if (res.code === 0) {
        // Flag silently ignored (should not happen) — degrade rather than
        // report an empty IR as a parity mismatch.
        combinedModeUnsupported.add(spec.id);
      } else {
        throw new Error(
          `${spec.id} --hex --emit-ir-to ${describeExit(res)}: ${res.stderr || res.stdout}`,
        );
      }
    }

    // --- two-spawn fallback ------------------------------------------------
    if (irOutput === null) {
      const irRes = await runCmd(
        cmd,
        [...binArgs, '--source', tmpFile, '--emit-ir', ...foldFlag()],
        runOpts,
      );
      requireCleanExit(spec, irRes, '--emit-ir');
      if (irRes.code !== 0) {
        throw new Error(`${spec.id} --emit-ir ${describeExit(irRes)}: ${irRes.stderr || irRes.stdout}`);
      }
      irOutput = irRes.stdout.trim();

      const hexRes = await runCmd(
        cmd,
        [...binArgs, '--source', tmpFile, '--hex', ...foldFlag()],
        runOpts,
      );
      requireCleanExit(spec, hexRes, '--hex');
      if (hexRes.code === 0) {
        scriptHexOutput = requireHex(spec, hexRes, '--hex');
      } else if (spec.tolerateHexFailure) {
        scriptHexOutput = '';
      } else {
        throw new Error(`${spec.id} --hex ${describeExit(hexRes)}: ${hexRes.stderr || hexRes.stdout}`);
      }
    }

    return {
      irJson: canonicalizeJson(irOutput),
      scriptHex: scriptHexOutput,
      scriptAsm: '',
      success: true,
      durationMs: performance.now() - start,
    };
  } catch (err) {
    return {
      irJson: '',
      scriptHex: '',
      scriptAsm: '',
      success: false,
      error: err instanceof Error ? err.message : String(err),
      durationMs: performance.now() - start,
    };
  } finally {
    safeRm(tmpFile);
    safeRm(irFile);
  }
}

/**
 * Run the Go compiler on the given source. Returns undefined if the Go
 * compiler is not available.
 */
function runGoCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  return runNativeCompiler(NATIVE_COMPILERS.go, source, sourceFile);
}

/**
 * Run the Rust compiler on the given source. Returns undefined if the Rust
 * compiler is not available.
 */
function runRustCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  return runNativeCompiler(NATIVE_COMPILERS.rust, source, sourceFile);
}

/**
 * Check whether the Python compiler is available (`python3 -m runar_compiler`).
 */
export function findPythonBinary(): string | null {
  return findPythonCompiler();
}
function findPythonCompiler(): string | null {
  if (!existsSync(join(PYTHON_COMPILER_DIR, 'runar_compiler', '__main__.py'))) {
    return null;
  }
  try {
    execSync('python3 --version', { stdio: 'pipe' });
    return `python3 -m runar_compiler`;
  } catch {
    return null;
  }
}

/**
 * Run the Python compiler on the given source. Returns undefined if the Python
 * compiler is not available.
 */
function runPythonCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  return runNativeCompiler(NATIVE_COMPILERS.python, source, sourceFile);
}

/**
 * Check whether the Zig compiler binary is available.
 */
// See findGoBinary above for the rationale on `process.cwd()` candidates: the
// CI conformance job downloads the `runar-zig` artifact directly into the
// workflow checkout root via `actions/download-artifact`. Without these
// entries the runner silently fell back to `undefined` and Zig got skipped
// entirely while CI still claimed "all 7 compilers tested".
export function findZigBinary(): string | null {
  const candidates = [
    join(ZIG_COMPILER_DIR, 'zig-out/bin/runar-zig'),
    join(ZIG_COMPILER_DIR, 'runar-zig'),
    join(process.cwd(), 'runar-zig'),
    join(process.cwd(), 'runar-zig.exe'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  // Try PATH
  try {
    execSync('which runar-zig', { stdio: 'pipe' });
    return 'runar-zig';
  } catch {
    return null;
  }
}

/**
 * Run the Zig compiler on the given source. Returns undefined if the Zig
 * compiler is not available.
 */
function runZigCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  return runNativeCompiler(NATIVE_COMPILERS.zig, source, sourceFile);
}

/**
 * Check whether the Ruby compiler is available.
 */
export function findRubyBinary(): string | null {
  const script = join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby');
  if (!existsSync(script)) return null;
  try {
    execSync('ruby --version', { stdio: 'pipe' });
    return `ruby ${script}`;
  } catch {
    return null;
  }
}

/**
 * Run the Ruby compiler on the given source. Returns undefined if the Ruby
 * compiler is not available.
 */
function runRubyCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  return runNativeCompiler(NATIVE_COMPILERS.ruby, source, sourceFile);
}

/**
 * Check whether the Java compiler jar is available. Mirrors the binary-
 * discovery pattern used for Go / Rust: prefer a distributable artifact
 * over spawning a build system. The Java compiler ships full IR + hex.
 */
export function findJavaBinary(): string | null {
  const jarPath = findJavaJarPath();
  if (jarPath === null) return null;
  try {
    execSync('java -version', { stdio: 'pipe' });
  } catch {
    return null;
  }
  return `java -jar ${jarPath}`;
}

/** Locate the built runar-java jar, or null if no jar is on disk. */
export function findJavaJarPath(): string | null {
  const libsDir = join(JAVA_COMPILER_DIR, 'build/libs');
  const preferred = join(libsDir, 'runar-java.jar');
  const candidates: string[] = [];
  if (existsSync(preferred)) {
    candidates.push(preferred);
  }
  if (existsSync(libsDir)) {
    try {
      const entries = readdirSync(libsDir);
      for (const entry of entries) {
        if (entry.startsWith('runar-java-compiler-') && entry.endsWith('.jar')) {
          candidates.push(join(libsDir, entry));
        }
      }
    } catch {
      // ignore
    }
  }
  try {
    const cwdEntries = readdirSync(process.cwd());
    for (const entry of cwdEntries) {
      if (
        (entry === 'runar-java.jar') ||
        (entry.startsWith('runar-java-compiler-') && entry.endsWith('.jar'))
      ) {
        candidates.push(join(process.cwd(), entry));
      }
    }
  } catch {
    // ignore
  }
  return candidates.length > 0 ? candidates[0]! : null;
}

// ---------------------------------------------------------------------------
// Java compile daemon (Win 4)
// ---------------------------------------------------------------------------
//
// Per-invocation `java -jar runar-java.jar` pays ~1.5s of JVM cold-start.
// In a 49-test × 9-format × 7-compiler matrix that's ~9 minutes of pure
// JVM startup. The daemon keeps a single JVM alive for the entire run and
// dispatches each compile request as a JSON-RPC line on stdin / stdout.
//
// Enabled by default when:
//   - the runar-java jar is on disk, AND
//   - `RUNAR_JAVA_DAEMON=0` is NOT set in the env.
// Disable explicitly with `RUNAR_JAVA_DAEMON=0` to fall back to one-shot
// `java -jar` for parity testing.

let javaDaemonInstance: JavaDaemon | null = null;
let javaDaemonAttempted = false;

function shouldUseJavaDaemon(): boolean {
  if (process.env.RUNAR_JAVA_DAEMON === '0') return false;
  return true;
}

function getOrStartJavaDaemon(): JavaDaemon | null {
  if (!shouldUseJavaDaemon()) return null;
  if (javaDaemonInstance) return javaDaemonInstance;
  if (javaDaemonAttempted) return null;
  javaDaemonAttempted = true;
  const jar = findJavaJarPath();
  if (!jar) return null;
  try {
    javaDaemonInstance = JavaDaemon.start(jar);
    return javaDaemonInstance;
  } catch (err) {
    // Daemon failed to start — fall back to one-shot.
    if (process.env.RUNAR_DEBUG) {
      console.error('[conformance/runner] Java daemon startup failed:', err);
    }
    return null;
  }
}

/** Stop the Java daemon (call once at the end of the test run). */
export async function shutdownJavaDaemon(): Promise<void> {
  if (javaDaemonInstance) {
    await javaDaemonInstance.stop();
    javaDaemonInstance = null;
  }
}

/**
 * Reject an "empty success": a Java invocation that reported OK but handed
 * back no IR and/or no script hex. Returns an error message, or null when
 * both artifacts are non-empty.
 *
 * Empty-but-successful is a defect, never a legitimate result — and it is
 * WORSE than an outright failure downstream, because the golden-file gate is
 * written as `javaResult?.success && javaResult.scriptHex` (runner.ts:1940):
 * an empty hex makes that condition falsy, so Java silently drops out of the
 * golden comparison while the tier still counts as "tested". `compareScript`
 * / `compareIR` do fail closed on it, but only with an anonymous "a compiler
 * reported success but produced empty hex" warning that never names Java.
 */
function javaEmptyOutputError(irOutput: string, scriptHex: string): string | null {
  const irEmpty = irOutput.trim() === '';
  const hexEmpty = scriptHex.replace(/\s/g, '') === '';
  if (irEmpty && hexEmpty) return 'java compiler reported success but produced no IR and no script hex';
  if (irEmpty) return 'java compiler reported success but produced empty IR';
  if (hexEmpty) return 'java compiler reported success but produced empty script hex';
  return null;
}

/**
 * Java daemon errors that mean "the JVM never answered" rather than "the Java
 * compiler rejected this program". Kept in sync with the messages thrown in
 * `java-daemon.ts`. The daemon does not go through `runCmd`, so its
 * infrastructure failures have to be classified by hand.
 */
const JAVA_DAEMON_HARNESS_RE =
  /daemon timeout after|daemon exited unexpectedly|daemon banner timeout|daemon already stopped/i;

/**
 * Assemble the one-shot Java `CompilerOutput` from the raw `--emit-ir` and
 * `--hex` process results. This is exactly what `runJavaCompiler` returns in
 * one-shot mode (`RUNAR_JAVA_DAEMON=0`); it is exported so the failure ladder
 * can be unit-tested without a JVM.
 *
 * Fails closed on three cases the previous inline code let through:
 *   1. a non-zero `--hex` exit (was silently downgraded to `scriptHex = ''`
 *      while still reporting `success: true`),
 *   2. exit 0 with empty `--hex` stdout,
 *   3. exit 0 with empty `--emit-ir` stdout.
 * The Go / Rust / Python / Zig / Ruby one-shot paths already throw on (1).
 */
export function buildJavaOneShotOutput(
  irRes: { stdout: string; stderr: string; code: number },
  hexRes: { stdout: string; stderr: string; code: number },
  durationMs: number,
): CompilerOutput {
  const fail = (error: string): CompilerOutput => ({
    irJson: '',
    scriptHex: '',
    scriptAsm: '',
    success: false,
    error,
    durationMs,
  });

  if (irRes.code !== 0) {
    return fail(`java --emit-ir exit ${irRes.code}: ${irRes.stderr || irRes.stdout}`);
  }
  if (hexRes.code !== 0) {
    return fail(`java --hex exit ${hexRes.code}: ${hexRes.stderr || hexRes.stdout}`);
  }

  const irOutput = irRes.stdout.trim();
  const scriptHex = hexRes.stdout.trim();
  const emptyErr = javaEmptyOutputError(irOutput, scriptHex);
  if (emptyErr) {
    return fail(`${emptyErr} (exit 0, empty stdout)`);
  }

  return {
    irJson: canonicalizeJson(irOutput),
    scriptHex,
    scriptAsm: '',
    success: true,
    durationMs,
  };
}

/**
 * Run the Java compiler on the given source. Returns undefined if the
 * Java compiler jar is not available. Both the daemon and one-shot paths
 * fail closed on an empty-but-"successful" result (see
 * `javaEmptyOutputError` / `buildJavaOneShotOutput`).
 */
async function runJavaCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  const start = performance.now();

  // Daemon mode: send a single JSON-RPC request, get IR + hex back in one shot.
  const daemon = getOrStartJavaDaemon();
  if (daemon) {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `java-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    try {
      writeFileSync(tmpFile, source, 'utf-8');
      const resp = await daemon.compile(tmpFile);
      const durationMs = performance.now() - start;
      if (!resp.ok) {
        return {
          irJson: '',
          scriptHex: '',
          scriptAsm: '',
          success: false,
          error: resp.error ?? 'Java daemon error',
          durationMs,
        };
      }
      const daemonIr = resp.ir ?? '';
      const daemonHex = resp.hex ?? '';
      const emptyErr = javaEmptyOutputError(daemonIr, daemonHex);
      if (emptyErr) {
        return {
          irJson: '',
          scriptHex: '',
          scriptAsm: '',
          success: false,
          error: `${emptyErr} (daemon replied ok)`,
          durationMs,
        };
      }
      return {
        irJson: canonicalizeJson(daemonIr),
        scriptHex: daemonHex,
        scriptAsm: '',
        success: true,
        durationMs,
      };
    } catch (err) {
      const durationMs = performance.now() - start;
      const message = err instanceof Error ? err.message : String(err);
      // The daemon does not go through `runCmd`, so its infrastructure
      // failures need the same classification by hand — otherwise a JVM that
      // died of resource exhaustion is filed as a Java conformance failure
      // and the operator goes looking for a codegen bug that isn't there.
      const harness = JAVA_DAEMON_HARNESS_RE.test(message);
      if (harness) {
        recordHarnessFault({
          cmd: 'java-daemon',
          kind: /timeout/i.test(message) ? 'timeout' : 'signal',
          detail: `java daemon ${message} (java on ${basename(sourceFile)})`,
          durationMs: Math.round(durationMs),
        });
      }
      return {
        irJson: '',
        scriptHex: '',
        scriptAsm: '',
        success: false,
        error: harness ? `HARNESS: ${message}` : message,
        durationMs,
      };
    } finally {
      safeRm(tmpFile);
    }
  }

  // One-shot mode (original behaviour, for `RUNAR_JAVA_DAEMON=0`). Uses the
  // shared native driver, which prefers the single-spawn `--emit-ir-to` form.
  return runNativeCompiler(NATIVE_COMPILERS.java, source, sourceFile);
}

// ---------------------------------------------------------------------------
// Universal parser-only coverage
// ---------------------------------------------------------------------------
//
// Runs `--parse-only` on every available compiler for every (fixture, format)
// pair, ignoring the per-fixture `compilers` allowlist. The allowlist is for
// Stack-IR / hex parity ONLY; the parser layer is universal — every tier MUST
// accept every format for every fixture. See conformance/README.md ("Per-tier
// universal parser coverage") and runConformanceTestForFormat above (which
// honours the allowlist for the codegen layer).
//
// Each compiler exposes a `--parse-only` flag that runs parse + validate and
// exits zero on success ("parser ok" on stdout). The Java compiler accepts a
// `parseOnly: true` JSON-RPC request via the daemon (preferred) or the
// `--parse-only` CLI flag in one-shot mode.
//
// Each per-compiler invoker returns a `ParseOnlyResult`. Failures are
// tabulated by `runAllParserOnlyChecks` and surfaced as a coverage matrix.

export interface ParseOnlyResult {
  compiler: CompilerId;
  success: boolean;
  error?: string;
  durationMs: number;
}

interface ParseOnlyDeps {
  source: string;
  sourceFile: string;
}

async function runTsParseOnly({ source, sourceFile }: ParseOnlyDeps): Promise<ParseOnlyResult | undefined> {
  const start = performance.now();
  let tmpFile = '';
  let driverFile = '';
  try {
    // Invoke the in-process compiler with `parseOnly: true`. Reusing the same
    // tsx loader / CLI process layout the runner already uses for `runTsCompiler`.
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    tmpFile = join(tmpDir, `parseonly-ts-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    const tsxLoader = resolveTsxLoader();
    // Inline a tiny driver script that loads the compiler and runs parseOnly.
    const driverInline =
      `import { compile } from '${pathToFileURL(resolve(REPO_ROOT, 'packages/runar-compiler/src/index.ts')).href}';` +
      `import { readFileSync } from 'fs';` +
      `const src = readFileSync(${JSON.stringify(tmpFile)}, 'utf-8');` +
      `const r = compile(src, { fileName: ${JSON.stringify(tmpFile)}, parseOnly: true });` +
      `if (!r.success) { for (const d of r.diagnostics) { if (d.severity === 'error') process.stderr.write('parse error: ' + (d.message||'') + '\\n'); } process.exit(1); }` +
      `process.stdout.write('parser ok\\n');`;
    driverFile = join(tmpDir, `driver-ts-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.mjs`);
    writeFileSync(driverFile, driverInline, 'utf-8');
    const result = await runCmd(
      'node',
      ['--import', tsxLoader, driverFile],
      { timeoutMs: 90_000, cwd: REPO_ROOT, label: `ts --parse-only on ${basename(sourceFile)}` },
    );
    const durationMs = performance.now() - start;
    if (result.code !== 0) {
      return {
        compiler: 'ts',
        success: false,
        error: (result.stderr || result.stdout || '').slice(-2000) || `exit ${result.code}`,
        durationMs,
      };
    }
    return { compiler: 'ts', success: true, durationMs };
  } catch (err) {
    return {
      compiler: 'ts',
      success: false,
      error: err instanceof Error ? err.message : String(err),
      durationMs: performance.now() - start,
    };
  } finally {
    if (tmpFile) safeRm(tmpFile);
    if (driverFile) safeRm(driverFile);
  }
}

async function runGoParseOnly({ source, sourceFile }: ParseOnlyDeps): Promise<ParseOnlyResult | undefined> {
  const binary = findGoBinary();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);
  const start = performance.now();
  let tmpFile = '';
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    tmpFile = join(tmpDir, `parseonly-go-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');
    const res = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--parse-only'],
      { timeoutMs: compileTimeoutMs(), cwd: GO_COMPILER_DIR, label: `go --parse-only on ${basename(sourceFile)}` },
    );
    const durationMs = performance.now() - start;
    if (res.code !== 0) {
      return { compiler: 'go', success: false, error: (res.stderr || res.stdout || '').slice(-2000) || `exit ${res.code}`, durationMs };
    }
    return { compiler: 'go', success: true, durationMs };
  } catch (err) {
    return { compiler: 'go', success: false, error: err instanceof Error ? err.message : String(err), durationMs: performance.now() - start };
  } finally {
    if (tmpFile) safeRm(tmpFile);
  }
}

async function runRustParseOnly({ source, sourceFile }: ParseOnlyDeps): Promise<ParseOnlyResult | undefined> {
  const binary = findRustBinary();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);
  const start = performance.now();
  let tmpFile = '';
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    tmpFile = join(tmpDir, `parseonly-rust-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');
    const res = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--parse-only'],
      { timeoutMs: compileTimeoutMs(), cwd: RUST_COMPILER_DIR, env: cargoAwareEnv(), label: `rust --parse-only on ${basename(sourceFile)}` },
    );
    const durationMs = performance.now() - start;
    if (res.code !== 0) {
      return { compiler: 'rust', success: false, error: (res.stderr || res.stdout || '').slice(-2000) || `exit ${res.code}`, durationMs };
    }
    return { compiler: 'rust', success: true, durationMs };
  } catch (err) {
    return { compiler: 'rust', success: false, error: err instanceof Error ? err.message : String(err), durationMs: performance.now() - start };
  } finally {
    if (tmpFile) safeRm(tmpFile);
  }
}

async function runPythonParseOnly({ source, sourceFile }: ParseOnlyDeps): Promise<ParseOnlyResult | undefined> {
  const binary = findPythonCompiler();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);
  const start = performance.now();
  let tmpFile = '';
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    tmpFile = join(tmpDir, `parseonly-python-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');
    const res = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--parse-only'],
      { timeoutMs: compileTimeoutMs(), cwd: PYTHON_COMPILER_DIR, label: `python --parse-only on ${basename(sourceFile)}` },
    );
    const durationMs = performance.now() - start;
    if (res.code !== 0) {
      return { compiler: 'python', success: false, error: (res.stderr || res.stdout || '').slice(-2000) || `exit ${res.code}`, durationMs };
    }
    return { compiler: 'python', success: true, durationMs };
  } catch (err) {
    return { compiler: 'python', success: false, error: err instanceof Error ? err.message : String(err), durationMs: performance.now() - start };
  } finally {
    if (tmpFile) safeRm(tmpFile);
  }
}

async function runZigParseOnly({ source, sourceFile }: ParseOnlyDeps): Promise<ParseOnlyResult | undefined> {
  const binary = findZigBinary();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);
  const start = performance.now();
  let tmpFile = '';
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    tmpFile = join(tmpDir, `parseonly-zig-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');
    const res = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--parse-only'],
      { timeoutMs: compileTimeoutMs(), cwd: ZIG_COMPILER_DIR, label: `zig --parse-only on ${basename(sourceFile)}` },
    );
    const durationMs = performance.now() - start;
    if (res.code !== 0) {
      return { compiler: 'zig', success: false, error: (res.stderr || res.stdout || '').slice(-2000) || `exit ${res.code}`, durationMs };
    }
    return { compiler: 'zig', success: true, durationMs };
  } catch (err) {
    return { compiler: 'zig', success: false, error: err instanceof Error ? err.message : String(err), durationMs: performance.now() - start };
  } finally {
    if (tmpFile) safeRm(tmpFile);
  }
}

async function runRubyParseOnly({ source, sourceFile }: ParseOnlyDeps): Promise<ParseOnlyResult | undefined> {
  const binary = findRubyBinary();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);
  const start = performance.now();
  let tmpFile = '';
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    tmpFile = join(tmpDir, `parseonly-ruby-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');
    const res = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--parse-only'],
      { timeoutMs: compileTimeoutMs(), cwd: RUBY_COMPILER_DIR, label: `ruby --parse-only on ${basename(sourceFile)}` },
    );
    const durationMs = performance.now() - start;
    if (res.code !== 0) {
      return { compiler: 'ruby', success: false, error: (res.stderr || res.stdout || '').slice(-2000) || `exit ${res.code}`, durationMs };
    }
    return { compiler: 'ruby', success: true, durationMs };
  } catch (err) {
    return { compiler: 'ruby', success: false, error: err instanceof Error ? err.message : String(err), durationMs: performance.now() - start };
  } finally {
    if (tmpFile) safeRm(tmpFile);
  }
}

async function runJavaParseOnly({ source, sourceFile }: ParseOnlyDeps): Promise<ParseOnlyResult | undefined> {
  const start = performance.now();
  // Daemon-first: a single round-trip per (fixture, format), no JVM cold-start.
  const daemon = getOrStartJavaDaemon();
  if (daemon) {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `parseonly-java-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    try {
      writeFileSync(tmpFile, source, 'utf-8');
      const resp = await daemon.compile(tmpFile, { parseOnly: true });
      const durationMs = performance.now() - start;
      if (!resp.ok) {
        return { compiler: 'java', success: false, error: resp.error ?? 'Java daemon error', durationMs };
      }
      return { compiler: 'java', success: true, durationMs };
    } catch (err) {
      return { compiler: 'java', success: false, error: err instanceof Error ? err.message : String(err), durationMs: performance.now() - start };
    } finally {
      safeRm(tmpFile);
    }
  }
  // One-shot fallback (RUNAR_JAVA_DAEMON=0).
  const binary = findJavaBinary();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);
  let tmpFile = '';
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    tmpFile = join(tmpDir, `parseonly-java-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');
    const res = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--parse-only'],
      { timeoutMs: compileTimeoutMs(), cwd: JAVA_COMPILER_DIR, label: `java --parse-only on ${basename(sourceFile)}` },
    );
    const durationMs = performance.now() - start;
    if (res.code !== 0) {
      return { compiler: 'java', success: false, error: (res.stderr || res.stdout || '').slice(-2000) || `exit ${res.code}`, durationMs };
    }
    return { compiler: 'java', success: true, durationMs };
  } catch (err) {
    return { compiler: 'java', success: false, error: err instanceof Error ? err.message : String(err), durationMs: performance.now() - start };
  } finally {
    if (tmpFile) safeRm(tmpFile);
  }
}

export interface ParserCoverageEntry {
  fixture: string;
  format: string;
  results: ParseOnlyResult[];
}

export interface ParserCoverageReport {
  entries: ParserCoverageEntry[];
  /** True if every (compiler, fixture, format) triple parsed cleanly. */
  allOk: boolean;
  /** All failures, flattened for easy printing. */
  failures: Array<{ fixture: string; format: string; compiler: CompilerId; error: string }>;
  /** Available compilers (the ones that returned a non-undefined ParseOnlyResult at least once). */
  availableCompilers: CompilerId[];
  /** Per-compiler aggregate counts. */
  perCompiler: Record<string, { passed: number; failed: number; skipped: number }>;
  /**
   * Fixtures whose formats could not be discovered (`discoverFormats` threw —
   * e.g. a parser-coverage gap or an orphan source file). These contribute ZERO
   * (fixture, format) pairs to the matrix, so without this list a fixture could
   * silently drop out of parser coverage entirely and the report would still
   * read "all ok". Callers MUST treat a non-empty list as a failure.
   */
  skippedFixtures: Array<{ fixture: string; error: string }>;
}

/**
 * Universal parser-coverage check: runs every available compiler's
 * `--parse-only` mode against every declared (fixture, format) pair. The
 * per-fixture `compilers` allowlist in source.json is INTENTIONALLY ignored
 * here — that allowlist scopes Stack-IR / hex parity, not the frontend.
 * Concurrency mirrors `runAllMultiFormatConformanceTests`.
 */
export async function runAllParserOnlyChecks(
  testsDir: string,
  options?: { filter?: string },
): Promise<ParserCoverageReport> {
  // CI safety net: fail loudly (once per process) if any compiler binary is
  // missing while CI=true. Mirrors runConformanceTest above.
  assertAllCompilersAvailableInCi();

  const entries = readdirSync(testsDir, { withFileTypes: true });
  let testDirs = entries
    .filter((e) => e.isDirectory())
    .map((e) => join(testsDir, e.name))
    .sort();
  if (options?.filter) {
    const filterLower = options.filter.toLowerCase();
    testDirs = testDirs.filter((d) => basename(d).toLowerCase().includes(filterLower));
  }

  const limit = makeLimiter(defaultConcurrency());
  const allTasks: Promise<ParserCoverageEntry>[] = [];
  const skippedFixtures: Array<{ fixture: string; error: string }> = [];
  for (const testDir of testDirs) {
    const fixture = basename(testDir);
    let formats: { ext: string; sourceFile: string }[] = [];
    try {
      formats = discoverFormats(testDir, fixture);
    } catch (err) {
      // discoverFormats throws on parser-coverage gaps / orphan sources. Such a
      // fixture contributes NO (fixture, format) pairs, so swallowing this
      // silently would drop it from the coverage matrix while the report still
      // said "all ok". Record it — the CLI fails on a non-empty list.
      skippedFixtures.push({
        fixture,
        error: err instanceof Error ? err.message : String(err),
      });
      continue;
    }
    for (const format of formats) {
      const formatDef = INPUT_FORMATS.find(f => f.ext === format.ext);
      if (!formatDef) continue;
      const compilers = formatDef.compilers;
      allTasks.push(limit(async () => {
        const source = readFileSync(format.sourceFile, 'utf-8');
        const deps: ParseOnlyDeps = { source, sourceFile: format.sourceFile };
        // Run all 7 compilers in parallel for this (fixture, format) pair.
        const results = await Promise.all(compilers.map(async (c) => {
          switch (c) {
            case 'ts':     return runTsParseOnly(deps);
            case 'go':     return runGoParseOnly(deps);
            case 'rust':   return runRustParseOnly(deps);
            case 'python': return runPythonParseOnly(deps);
            case 'zig':    return runZigParseOnly(deps);
            case 'ruby':   return runRubyParseOnly(deps);
            case 'java':   return runJavaParseOnly(deps);
          }
          return undefined;
        }));
        return {
          fixture,
          format: format.ext,
          results: results.filter((r): r is ParseOnlyResult => r !== undefined),
        };
      }));
    }
  }
  const coverage = await Promise.all(allTasks);

  // Aggregate.
  const failures: ParserCoverageReport['failures'] = [];
  const availableSet = new Set<CompilerId>();
  const perCompiler: Record<string, { passed: number; failed: number; skipped: number }> = {
    ts: { passed: 0, failed: 0, skipped: 0 },
    go: { passed: 0, failed: 0, skipped: 0 },
    rust: { passed: 0, failed: 0, skipped: 0 },
    python: { passed: 0, failed: 0, skipped: 0 },
    zig: { passed: 0, failed: 0, skipped: 0 },
    ruby: { passed: 0, failed: 0, skipped: 0 },
    java: { passed: 0, failed: 0, skipped: 0 },
  };
  for (const entry of coverage) {
    const seen = new Set<CompilerId>();
    for (const r of entry.results) {
      seen.add(r.compiler);
      availableSet.add(r.compiler);
      if (r.success) {
        perCompiler[r.compiler]!.passed++;
      } else {
        perCompiler[r.compiler]!.failed++;
        failures.push({ fixture: entry.fixture, format: entry.format, compiler: r.compiler, error: r.error ?? 'unknown error' });
      }
    }
    // Anything supported-by-format but absent from results is "skipped"
    // (binary not available locally).
    const formatDef = INPUT_FORMATS.find(f => f.ext === entry.format);
    if (formatDef) {
      for (const c of formatDef.compilers) {
        if (!seen.has(c)) perCompiler[c]!.skipped++;
      }
    }
  }
  return {
    entries: coverage,
    allOk: failures.length === 0 && skippedFixtures.length === 0,
    failures,
    availableCompilers: Array.from(availableSet),
    perCompiler,
    skippedFixtures,
  };
}

/** Pretty-print a parser-coverage report to stdout. */
export function printParserCoverageReport(report: ParserCoverageReport): void {
  const compilers: CompilerId[] = ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'];
  console.log('');
  console.log('Per-tier parser-only coverage (every compiler × every fixture × every declared format):');
  console.log('');
  const header = `  compiler  ${'pass'.padStart(6)}  ${'fail'.padStart(6)}  ${'skip'.padStart(6)}`;
  console.log(header);
  console.log('  ' + '-'.repeat(header.length - 2));
  for (const c of compilers) {
    const counts = report.perCompiler[c] ?? { passed: 0, failed: 0, skipped: 0 };
    console.log(`  ${c.padEnd(8)}  ${String(counts.passed).padStart(6)}  ${String(counts.failed).padStart(6)}  ${String(counts.skipped).padStart(6)}`);
  }
  console.log('');
  if (report.failures.length === 0) {
    console.log('  All available tiers parsed every fixture × every declared format cleanly.');
  } else {
    console.log(`  ${report.failures.length} parser failure(s):`);
    for (const f of report.failures) {
      const oneLineError = (f.error || '').split('\n').slice(0, 3).join(' | ').slice(0, 400);
      console.log(`    [${f.compiler}] ${f.fixture} ${f.format}: ${oneLineError}`);
    }
  }
  if (report.skippedFixtures.length > 0) {
    console.log('');
    console.log(
      `  ${report.skippedFixtures.length} fixture(s) contributed NO (fixture, format) pairs — ` +
      `they are absent from the coverage matrix entirely:`,
    );
    for (const s of report.skippedFixtures) {
      const oneLineError = (s.error || '').split('\n').slice(0, 2).join(' | ').slice(0, 400);
      console.log(`    ${s.fixture}: ${oneLineError}`);
    }
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// IR -> hex cross-tier parity (the `--ir-parity` mode)
// ---------------------------------------------------------------------------
//
// THIS FILE IS THE SINGLE SOURCE OF TRUTH for "do all tiers agree
// byte-for-byte". The rule used to be written three times — here, inline in
// `.github/workflows/ci.yml`, and in
// `runar-verification/scripts/cross-compiler-diff.sh` — each with its own
// allowlist handling, so a fix to one silently left the others wrong. The
// ci.yml copy has been deleted; that workflow step now shells out to
// `runner/index.ts --ir-parity`. (The runar-verification script remains a
// separate implementation: it is the Tier-6.1 verification gate and also
// drives the Lean reference tier, which this runner does not know about. If
// you change parity or allowlist semantics here, mirror it there.)
//
// Semantics, preserved exactly from the ci.yml loop this replaces:
//   * Input is the checked-in `expected-ir.json`, NOT source — this gates
//     each tier's `--ir` loader + Stack-IR/emit path, complementing the
//     source-driven multi-format mode.
//   * Only the six NON-TS tiers participate. TS is covered by the
//     multi-format runner (which compiles from source).
//   * The per-fixture `compilers` allowlist in source.json SCOPES this gate
//     (unlike `--parser-only`, where it is intentionally ignored). A fixture
//     whose allowlist has no overlap with the six tiers is skipped.
//   * Always fold-OFF: the goldens were stamped fold-OFF, so this mode pins
//     `--disable-constant-folding` regardless of
//     RUNAR_DISABLE_CONSTANT_FOLDING. Fold-ON parity is the multi-format
//     runner's job.
//   * Reference tier is Go when active, else the first active tier. Every
//     other active tier must match it, and the reference must match
//     `expected-script.hex` when that golden exists.

/** The tiers driven by `--ir-parity`, in the ci.yml loop's original order. */
const IR_PARITY_COMPILERS: readonly Exclude<CompilerId, 'ts'>[] = [
  'go', 'rust', 'zig', 'ruby', 'python', 'java',
] as const;

export interface IrParityFixtureResult {
  fixture: string;
  status: 'ok' | 'skipped' | 'failed';
  /** Tiers actually driven for this fixture (allowlist ∩ available). */
  activeCompilers: CompilerId[];
  /** Tiers excluded by the fixture's `compilers` allowlist. */
  allowlistExcluded: CompilerId[];
  /** Tiers skipped because their binary is not on disk (local dev only). */
  unavailable: CompilerId[];
  reference?: CompilerId;
  hexByCompiler: Record<string, string>;
  skipReason?: string;
  errors: string[];
}

export interface IrParityReport {
  results: IrParityFixtureResult[];
  allOk: boolean;
  /** Flattened failures for easy printing. */
  failures: Array<{ fixture: string; error: string }>;
}

/**
 * Compile a fixture's `expected-ir.json` to hex with one native tier.
 * Returns null when the tier's binary is not on disk.
 */
async function runIrToHex(
  id: Exclude<CompilerId, 'ts'>,
  irPath: string,
): Promise<{ code: number; hex: string; stderr: string } | null> {
  const spec = NATIVE_COMPILERS[id];
  const binary = spec.find();
  if (!binary) return null;
  const { cmd, args: binArgs } = splitCmd(binary);
  // Zig's IR consumer is a positional subcommand (`compile-ir <file>`) and
  // takes no fold flag — matching the ci.yml loop this replaces.
  const args = id === 'zig'
    ? [...binArgs, 'compile-ir', irPath, '--hex']
    : [...binArgs, '--ir', irPath, '--hex', '--disable-constant-folding'];
  const res = await runCmd(cmd, args, {
    timeoutMs: spec.timeoutMs,
    cwd: spec.cwd,
    env: spec.env?.(),
    label: `${id} --ir on ${basename(dirname(irPath))}`,
  });
  // Zig interleaves allocator diagnostics with its output; keep only the
  // first line, exactly as the ci.yml loop's `head -1` did.
  const raw = id === 'zig' ? (res.stdout.split('\n')[0] ?? '') : res.stdout;
  return {
    code: res.code,
    hex: raw.replace(/\s/g, '').toLowerCase(),
    // Lead with the abnormal-termination reason: a SIGKILLed child's stderr is
    // usually empty, and `exit -1` alone reads like a compiler error.
    stderr: res.abnormal ? `${res.abnormal}\n${res.stderr}` : res.stderr,
  };
}

/**
 * Cross-tier IR -> hex parity over every fixture that ships an
 * `expected-ir.json`. See the block comment above for the exact semantics.
 */
export async function runAllIrParityChecks(
  testsDir: string,
  options?: { filter?: string },
): Promise<IrParityReport> {
  // CI safety net: a missing binary must not silently shrink the tier set.
  assertAllCompilersAvailableInCi();

  const entries = readdirSync(testsDir, { withFileTypes: true });
  let testDirs = entries
    .filter((e) => e.isDirectory())
    .map((e) => join(testsDir, e.name))
    .sort();
  if (options?.filter) {
    const filterLower = options.filter.toLowerCase();
    testDirs = testDirs.filter((d) => basename(d).toLowerCase().includes(filterLower));
  }
  testDirs = testDirs.filter((d) => existsSync(join(d, 'expected-ir.json')));

  const limit = makeLimiter(defaultConcurrency());
  const results = await Promise.all(testDirs.map((testDir) => limit(async (): Promise<IrParityFixtureResult> => {
    const fixture = basename(testDir);
    const irPath = join(testDir, 'expected-ir.json');
    const allowlist = readFixtureCompilerAllowlist(testDir);

    const inScope = IR_PARITY_COMPILERS.filter((c) => !allowlist || allowlist.has(c));
    const allowlistExcluded = IR_PARITY_COMPILERS.filter((c) => allowlist !== null && !allowlist.has(c));

    if (inScope.length === 0) {
      // Allowlist had no overlap with the six non-TS tiers (e.g. a ts-only
      // fixture). Covered by the TS-side multi-format runner.
      return {
        fixture,
        status: 'skipped',
        activeCompilers: [],
        allowlistExcluded,
        unavailable: [],
        hexByCompiler: {},
        skipReason: 'no non-TS compilers in allowlist',
        errors: [],
      };
    }

    const errors: string[] = [];
    const hexByCompiler: Record<string, string> = {};
    const unavailable: CompilerId[] = [];
    const active: CompilerId[] = [];

    const runs = await Promise.all(inScope.map(async (id) => ({ id, res: await runIrToHex(id, irPath) })));
    for (const { id, res } of runs) {
      if (res === null) {
        unavailable.push(id);
        continue;
      }
      active.push(id);
      if (res.code !== 0) {
        errors.push(`${id}: non-zero exit ${res.code}: ${(res.stderr || '').split('\n').slice(0, 5).join(' | ')}`);
        continue;
      }
      if (res.hex === '') {
        errors.push(`${id}: empty hex output`);
        continue;
      }
      hexByCompiler[id] = res.hex;
    }

    if (errors.length > 0) {
      return { fixture, status: 'failed', activeCompilers: active, allowlistExcluded, unavailable, hexByCompiler, errors };
    }

    if (active.length === 0) {
      return {
        fixture,
        status: 'skipped',
        activeCompilers: [],
        allowlistExcluded,
        unavailable,
        hexByCompiler,
        skipReason: 'no compiler binaries available locally',
        errors: [],
      };
    }

    // Reference tier: Go when in scope, else the first active tier.
    const reference = (active.includes('go') ? 'go' : active[0]!) as CompilerId;
    const refHex = hexByCompiler[reference]!;

    for (const id of active) {
      if (id === reference) continue;
      if (hexByCompiler[id] !== refHex) {
        errors.push(
          `${reference} hex differs from ${id} hex\n` +
          `    ${reference}: ${refHex}\n` +
          `    ${id}: ${hexByCompiler[id]}`,
        );
      }
    }

    // Golden comparison against expected-script.hex (fold-OFF stamped).
    const goldenPath = join(testDir, 'expected-script.hex');
    if (existsSync(goldenPath)) {
      const expected = readFileSync(goldenPath, 'utf-8').replace(/\s/g, '').toLowerCase();
      if (expected !== '' && refHex !== expected) {
        errors.push(
          `${reference} output does not match golden file\n` +
          `    ${reference}: ${refHex}\n` +
          `    expected:  ${expected}`,
        );
      }
    }

    return {
      fixture,
      status: errors.length === 0 ? 'ok' : 'failed',
      activeCompilers: active,
      allowlistExcluded,
      unavailable,
      reference,
      hexByCompiler,
      errors,
    };
  })));

  const failures = results.flatMap((r) => r.errors.map((error) => ({ fixture: r.fixture, error })));
  return { results, allOk: failures.length === 0, failures };
}

/** Pretty-print an IR -> hex parity report to stdout. */
export function printIrParityReport(report: IrParityReport): void {
  console.log('');
  console.log('Cross-tier IR -> hex parity (expected-ir.json compiled by every non-TS tier):');
  console.log('');
  for (const r of report.results) {
    if (r.status === 'skipped') {
      console.log(`  === ${r.fixture} === SKIP (${r.skipReason})`);
      continue;
    }
    const activeCsv = r.activeCompilers.join(',');
    if (r.status === 'ok') {
      const refHex = r.reference ? r.hexByCompiler[r.reference] ?? '' : '';
      console.log(`  === ${r.fixture} === active=[${activeCsv}] OK (${refHex.length} hex chars, ref=${r.reference})`);
    } else {
      console.log(`  === ${r.fixture} === active=[${activeCsv}] FAIL`);
      for (const e of r.errors) {
        console.log(`    ${e}`);
      }
    }
  }
  console.log('');
  const ok = report.results.filter((r) => r.status === 'ok').length;
  const skipped = report.results.filter((r) => r.status === 'skipped').length;
  const failed = report.results.filter((r) => r.status === 'failed').length;
  console.log(`  ${ok} ok, ${failed} failed, ${skipped} skipped (${report.results.length} fixtures with expected-ir.json)`);
  console.log('');
}

// ---------------------------------------------------------------------------
// CI strict-mode: fail loudly if any compiler binary is missing in CI.
// ---------------------------------------------------------------------------
//
// The runner historically treated a missing compiler binary as `undefined`
// and silently skipped it. That's the right default for local devs (who
// rarely have all 7 toolchains installed) but it's a footgun in CI: the job
// happily reports "PASS — all 7 compilers tested" even when one of them
// never ran. We now gate that skip behind `!process.env.CI` and bail out
// early if any binary is missing in CI.
let strictModeChecked = false;
function assertAllCompilersAvailableInCi(): void {
  if (strictModeChecked) return;
  strictModeChecked = true;
  if (process.env.CI !== 'true') return;

  const probes: Array<{ name: string; path: string | null }> = [
    { name: 'go',     path: findGoBinary() },
    { name: 'rust',   path: findRustBinary() },
    { name: 'python', path: findPythonCompiler() },
    { name: 'zig',    path: findZigBinary() },
    { name: 'ruby',   path: findRubyBinary() },
    { name: 'java',   path: findJavaBinary() },
  ];
  const missing = probes.filter(p => p.path === null).map(p => p.name);
  if (missing.length > 0) {
    const cwd = process.cwd();
    const msg =
      `[conformance/runner] CI=true but ${missing.length} compiler binary` +
      (missing.length === 1 ? '' : ' binaries') +
      ` could not be located: ${missing.join(', ')}.\n` +
      `  cwd: ${cwd}\n` +
      `  Searched (per compiler):\n` +
      `    go:     compilers/go/runar-go[.exe], <cwd>/runar-go[.exe], $PATH\n` +
      `    rust:   compilers/rust/target/{release,debug}/runar-compiler-rust, compilers/rust/runar-compiler-rust, <cwd>/runar-compiler-rust[.exe], $PATH\n` +
      `    python: compilers/python/runar_compiler/__main__.py + python3\n` +
      `    zig:    compilers/zig/zig-out/bin/runar-zig, compilers/zig/runar-zig, <cwd>/runar-zig[.exe], $PATH\n` +
      `    ruby:   compilers/ruby/bin/runar-compiler-ruby + ruby\n` +
      `    java:   compilers/java/build/libs/runar-java*.jar, <cwd>/runar-java*.jar + java\n` +
      `Either install/build the missing toolchain(s) or drop the prebuilt binary at one of the searched paths.`;
    console.error(msg);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Output parsing & canonicalization
// ---------------------------------------------------------------------------

/**
 * Canonicalize a JSON string so that equivalent IR from different compilers
 * compares byte-for-byte identical.
 *
 * - Parses the JSON.
 * - Sorts all object keys recursively.
 * - Serializes with 2-space indentation.
 * - Normalizes bigint representations (number vs string).
 */
function canonicalizeJson(json: string): string {
  if (!json) return '';
  try {
    const parsed = JSON.parse(json, canonicalizeBigIntReviver);
    return JSON.stringify(sortKeys(parsed), null, 2);
  } catch {
    return json; // Return as-is if not valid JSON
  }
}

const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * `JSON.parse` reviver that makes the comparison LOSSLESS across the two
 * spellings of an integer the IR uses, and picks the SAME spelling the golden
 * stamper picks (see the TS-tier artifact reviver above):
 *
 *   - magnitude <= Number.MAX_SAFE_INTEGER → bare JSON number
 *   - anything larger                      → `"<decimal>n"` string
 *
 * Without it a plain `JSON.parse` forced every tier's IR through an IEEE-754
 * double before the comparison, so `9007199254740993` silently became
 * `9007199254740992` and the gate reported the two tiers that got it RIGHT as
 * the outliers (NEW-009). `context.source` carries the verbatim number token,
 * which is the only way to see the digits JS has already rounded away.
 *
 * The `n` suffix is unambiguous: ANF ByteString literals are hex, and `n` is
 * not a hex digit, so `^-?\d+n$` can only be a decimal bigint.
 */
function canonicalizeBigIntReviver(
  this: unknown,
  _key: string,
  value: unknown,
  context?: { source?: string },
): unknown {
  if (typeof value === 'number' && typeof context?.source === 'string') {
    const src = context.source;
    if (/^-?\d+$/.test(src)) {
      const asBigInt = BigInt(src);
      if (asBigInt > MAX_SAFE_BIGINT || asBigInt < -MAX_SAFE_BIGINT) {
        return `${asBigInt}n`;
      }
      // Re-derive from the source text: `value` itself may already be rounded.
      return Number(asBigInt);
    }
    return value;
  }
  if (typeof value === 'string' && /^-?\d+n$/.test(value)) {
    const asBigInt = BigInt(value.slice(0, -1));
    if (asBigInt >= -MAX_SAFE_BIGINT && asBigInt <= MAX_SAFE_BIGINT) {
      return Number(asBigInt);
    }
    return `${asBigInt}n`;
  }
  return value;
}

/** Recursively sort object keys for deterministic serialization.
 *  Strips `sourceLoc` fields — they are debug-only and not part of conformance
 *  (source locations differ across parser implementations). */
function sortKeys(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      if (key === 'sourceLoc') continue; // debug-only, not part of conformance
      sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

// ---------------------------------------------------------------------------
// IR & Script comparison
// ---------------------------------------------------------------------------

/**
 * Slot order of the `outputs` array both parity call sites build. Kept next to
 * the comparison functions so a diagnostic can name the tier that diverged
 * instead of reporting an anonymous "IR mismatch between compilers".
 */
const PARITY_TIER_ORDER = ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const;

/**
 * Result of a cross-tier parity comparison. `detail`, when present, names the
 * divergent tier(s) and where they diverge — a bare boolean forces the operator
 * to re-run the suite per tier by hand to learn anything actionable.
 */
export interface ParityComparison {
  ok: boolean;
  detail?: string;
}

function tierName(index: number): string {
  return PARITY_TIER_ORDER[index] ?? `slot${index}`;
}

/** Group slot indices by the value they produced, largest group first. */
function groupByValue(
  entries: { tier: string; value: string }[],
): { value: string; tiers: string[] }[] {
  const groups = new Map<string, string[]>();
  for (const { tier, value } of entries) {
    const bucket = groups.get(value);
    if (bucket) bucket.push(tier);
    else groups.set(value, [tier]);
  }
  return [...groups.entries()]
    .map(([value, tiers]) => ({ value, tiers }))
    .sort((a, b) => b.tiers.length - a.tiers.length);
}

/** Index of the first differing character, or -1 when one string prefixes the other. */
function firstDiffIndex(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i;
  return -1;
}

/**
 * Build a human-readable divergence report: which tiers formed which group, and
 * the position at which the minority groups first depart from the majority.
 */
function describeDivergence(
  groups: { value: string; tiers: string[] }[],
  unit: 'char' | 'byte',
): string {
  const [majority, ...rest] = groups;
  if (!majority) return 'no output to compare';

  const parts = rest.map((g) => {
    const at = firstDiffIndex(majority.value, g.value);
    let where: string;
    if (at === -1) {
      const scale = unit === 'byte' ? 2 : 1;
      where = `identical up to length; ${unit === 'byte' ? 'byte length' : 'length'} ` +
        `${Math.floor(g.value.length / scale)} vs ${Math.floor(majority.value.length / scale)}`;
    } else if (unit === 'byte') {
      where = `first differs at byte ${Math.floor(at / 2)} ` +
        `(${g.value.slice(at - (at % 2), at - (at % 2) + 2)} vs ` +
        `${majority.value.slice(at - (at % 2), at - (at % 2) + 2)})`;
    } else {
      where = `first differs at offset ${at} ` +
        `(${JSON.stringify(g.value.slice(at, at + 24))} vs ` +
        `${JSON.stringify(majority.value.slice(at, at + 24))})`;
    }
    return `[${g.tiers.join(', ')}] ${where}`;
  });

  return `majority [${majority.tiers.join(', ')}] vs ${parts.join('; ')}`;
}

/**
 * Compare IR output across all available compilers. `ok` is true when every
 * pair of successful compilers produced the same canonical IR JSON.
 *
 * When the caller restricted the compiler set (e.g. via the per-fixture
 * `compilers` allowlist in source.json, used for Go-only crypto modules),
 * pass `expectedCount` so a single successful compiler is treated as a
 * trivial match rather than a "cannot cross-validate" failure.
 */
export function compareIR(
  outputs: (CompilerOutput | undefined)[],
  expectedCount?: number,
): ParityComparison {
  // A tier reporting success but emitting EMPTY IR is a defect, not an absent
  // tier (absent tiers return `undefined`). Never silently drop it — otherwise
  // an emit regression degrades to <N-tier parity while still reporting green.
  const empty = outputs
    .map((o, i) => ({ o, i }))
    .filter(({ o }) => o !== undefined && o.success && o.irJson === '')
    .map(({ i }) => tierName(i));
  if (empty.length > 0) {
    return {
      ok: false,
      detail: `reported success but produced empty IR: [${empty.join(', ')}]`,
    };
  }

  const present = outputs
    .map((o, i) => ({ o, tier: tierName(i) }))
    .filter((e): e is { o: CompilerOutput; tier: string } =>
      e.o !== undefined && e.o.success && e.o.irJson !== '')
    .map(({ o, tier }) => ({ tier, value: o.irJson }));

  if (present.length < 2) {
    if (present.length === 0) return { ok: true }; // No compilers produced IR — not a mismatch
    if (expectedCount === 1) return { ok: true }; // Single-compiler fixture: trivial match
    return {
      ok: false,
      detail: `only 1 of ${expectedCount ?? PARITY_TIER_ORDER.length} expected tier(s) produced IR ` +
        `— cannot cross-validate (present: [${present[0]!.tier}])`,
    };
  }

  const groups = groupByValue(present);
  if (groups.length === 1) return { ok: true };
  return { ok: false, detail: describeDivergence(groups, 'char') };
}

/**
 * Compare compiled Bitcoin Script hex across all available compilers.
 * `ok` is true when every pair of successful compilers produced the same hex.
 *
 * See `compareIR` for `expectedCount` semantics.
 */
export function compareScript(
  outputs: (CompilerOutput | undefined)[],
  expectedCount?: number,
): ParityComparison {
  // A tier reporting success but emitting EMPTY hex is a defect, not an absent
  // tier (absent tiers return `undefined`). Never silently drop it — otherwise
  // an emit regression degrades to <N-tier parity while still reporting green.
  const empty = outputs
    .map((o, i) => ({ o, i }))
    .filter(({ o }) => o !== undefined && o.success && o.scriptHex.replace(/\s/g, '') === '')
    .map(({ i }) => tierName(i));
  if (empty.length > 0) {
    return {
      ok: false,
      detail: `reported success but produced empty hex: [${empty.join(', ')}]`,
    };
  }

  const present = outputs
    .map((o, i) => ({ o, tier: tierName(i) }))
    .filter((e): e is { o: CompilerOutput; tier: string } =>
      e.o !== undefined && e.o.success && e.o.scriptHex !== '')
    .map(({ o, tier }) => ({ tier, value: o.scriptHex.toLowerCase().replace(/\s/g, '') }));

  if (present.length < 2) {
    if (present.length === 0) return { ok: true }; // No compilers produced hex — not a mismatch
    if (expectedCount === 1) return { ok: true }; // Single-compiler fixture: trivial match
    return {
      ok: false,
      detail: `only 1 of ${expectedCount ?? PARITY_TIER_ORDER.length} expected tier(s) produced hex ` +
        `— cannot cross-validate (present: [${present[0]!.tier}])`,
    };
  }

  const groups = groupByValue(present);
  if (groups.length === 1) return { ok: true };
  return { ok: false, detail: describeDivergence(groups, 'byte') };
}

// ---------------------------------------------------------------------------
// Concurrency limiter
// ---------------------------------------------------------------------------

/** Hand-rolled p-limit replacement: caps concurrent async work at `n`. */
function makeLimiter(n: number): <T>(fn: () => Promise<T>) => Promise<T> {
  let inFlight = 0;
  const waiters: Array<() => void> = [];
  const release = () => {
    inFlight--;
    const next = waiters.shift();
    if (next) next();
  };
  return <T>(fn: () => Promise<T>): Promise<T> => {
    return new Promise<T>((resolveOuter, rejectOuter) => {
      const start = () => {
        inFlight++;
        fn().then(
          (v) => { release(); resolveOuter(v); },
          (e) => { release(); rejectOuter(e); },
        );
      };
      if (inFlight < n) start();
      else waiters.push(start);
    });
  };
}

/**
 * Concurrency cap for compiler subprocess invocations.
 *
 * Each task spawns up to 7 compilers in parallel internally (via Promise.all
 * inside `runConformanceTestForFormat`). We therefore size the outer limiter
 * at `cpus / 4` so the total burst is roughly `2 * cpus`, leaving headroom
 * for the JVM daemon, the parent runner, and disk I/O.
 *
 * Override with `RUNAR_CONFORMANCE_CONCURRENCY=<N>`.
 */
function defaultConcurrency(): number {
  const env = process.env.RUNAR_CONFORMANCE_CONCURRENCY;
  if (env) {
    const n = parseInt(env, 10);
    if (Number.isFinite(n) && n >= 1) return n;
  }
  const cpus = Math.max(1, os.cpus().length);
  return Math.max(2, Math.min(8, Math.floor(cpus / 4)));
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

/**
 * Resolve the source file for a conformance test directory.
 *
 * If `source.json` exists with a `path` field, resolve that path relative to
 * the test directory. Otherwise fall back to `<testName>.runar.ts` in the dir.
 */
function resolveSourceFile(testDir: string, testName: string): string {
  const configFile = join(testDir, 'source.json');
  if (existsSync(configFile)) {
    const config = JSON.parse(readFileSync(configFile, 'utf-8')) as {
      path?: string;
      sources?: Record<string, string>;
    };
    if (config.path) {
      return resolve(testDir, config.path);
    }
    if (config.sources?.['.runar.ts']) {
      return resolve(testDir, config.sources['.runar.ts']);
    }
  }
  return join(testDir, `${testName}.runar.ts`);
}

/**
 * Run the conformance test in a single test directory.
 *
 * The directory is expected to contain:
 * - `<name>.runar.ts` -- the contract source (or `source.json` pointing to one)
 * - `expected-ir.json` -- golden ANF IR (optional)
 * - `expected-script.hex` -- golden compiled script (optional)
 */
export async function runConformanceTest(testDir: string): Promise<ConformanceResult> {
  // CI safety net: fail loudly (once per process) if any compiler binary is
  // missing while CI=true. Local devs are unaffected — they may legitimately
  // run the suite with only a subset of toolchains installed.
  assertAllCompilersAvailableInCi();

  const testName = basename(testDir);
  const sourceFile = resolveSourceFile(testDir, testName);
  const expectedIrFile = join(testDir, 'expected-ir.json');
  const expectedScriptFile = join(testDir, 'expected-script.hex');

  if (!existsSync(sourceFile)) {
    return {
      testName,
      tsCompiler: { irJson: '', scriptHex: '', scriptAsm: '', success: false, error: `Source file not found: ${sourceFile}`, durationMs: 0 },
      irMatch: false,
      scriptMatch: false,
      errors: [`Source file not found: ${sourceFile}`],
    };
  }

  const source = readFileSync(sourceFile, 'utf-8');
  const errors: string[] = [];

  const allowlist = readFixtureCompilerAllowlist(testDir);

  const tsPromise = !allowlist || allowlist.has('ts')
    ? runTsCompiler(source, sourceFile)
    : Promise.resolve<CompilerOutput>({ irJson: '', scriptHex: '', scriptAsm: '', success: false, error: 'Format not supported by TS compiler', durationMs: 0 });

  const goPromise = !allowlist || allowlist.has('go')
    ? runGoCompiler(source, sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const rustPromise = !allowlist || allowlist.has('rust')
    ? runRustCompiler(source, sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const pythonPromise = !allowlist || allowlist.has('python')
    ? runPythonCompiler(source, sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const zigPromise = !allowlist || allowlist.has('zig')
    ? runZigCompiler(source, sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const rubyPromise = !allowlist || allowlist.has('ruby')
    ? runRubyCompiler(source, sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const javaPromise = !allowlist || allowlist.has('java')
    ? runJavaCompiler(source, sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  // Run all compilers in parallel — they're fully independent processes.
  const [tsResult, goResult, rustResult, pythonResult, zigResult, rubyResult, javaResult] = await Promise.all([
    tsPromise,
    goPromise,
    rustPromise,
    pythonPromise,
    zigPromise,
    rubyPromise,
    javaPromise,
  ]);

  const tsIncluded = !allowlist || allowlist.has('ts');

  if (tsIncluded && !tsResult.success) {
    errors.push(`TypeScript compiler failed: ${tsResult.error ?? 'unknown error'}`);
  }
  if (goResult && !goResult.success) {
    errors.push(`Go compiler failed: ${goResult.error ?? 'unknown error'}`);
  }
  if (rustResult && !rustResult.success) {
    errors.push(`Rust compiler failed: ${rustResult.error ?? 'unknown error'}`);
  }
  if (pythonResult && !pythonResult.success) {
    errors.push(`Python compiler failed: ${pythonResult.error ?? 'unknown error'}`);
  }
  if (zigResult && !zigResult.success) {
    errors.push(`Zig compiler failed: ${zigResult.error ?? 'unknown error'}`);
  }
  if (rubyResult && !rubyResult.success) {
    errors.push(`Ruby compiler failed: ${rubyResult.error ?? 'unknown error'}`);
  }
  if (javaResult && !javaResult.success) {
    errors.push(`Java compiler failed: ${javaResult.error ?? 'unknown error'}`);
  }

  const expectedCompilerCount = allowlist ? allowlist.size : 7;

  // Cross-compiler IR comparison
  const irMatch = compareIR(
    [tsIncluded ? tsResult : undefined, goResult, rustResult, pythonResult, zigResult, rubyResult, javaResult],
    expectedCompilerCount,
  );
  if (!irMatch.ok) {
    errors.push(`IR mismatch between compilers: ${irMatch.detail ?? 'no detail'}`);
  }

  // Cross-compiler script comparison
  const scriptMatch = compareScript(
    [tsIncluded ? tsResult : undefined, goResult, rustResult, pythonResult, zigResult, rubyResult, javaResult],
    expectedCompilerCount,
  );
  if (!scriptMatch.ok) {
    errors.push(`Script hex mismatch between compilers: ${scriptMatch.detail ?? 'no detail'}`);
  }

  // Golden file comparisons. Skipped under fold-on (RUNAR_DISABLE_CONSTANT_FOLDING=0)
  // because every existing expected-ir.json / expected-script.hex was stamped
  // with the fold-off compiler flag. Cross-tier parity (above) is still
  // strictly enforced in fold-on mode — the goldens are merely a reference
  // for the fold-off run.
  const skipGolden = !constantFoldingDisabled();
  const goldenGateOk = tsIncluded ? tsResult.success : true;
  if (!skipGolden && existsSync(expectedIrFile) && goldenGateOk) {
    const expectedIr = canonicalizeJson(readFileSync(expectedIrFile, 'utf-8'));
    if (tsIncluded && tsResult.irJson !== expectedIr) {
      errors.push(
        `TS compiler IR does not match golden file. ` +
        `Expected ${expectedIr.length} chars, got ${tsResult.irJson.length} chars.`,
      );
    }
    if (goResult?.success && goResult.irJson && goResult.irJson !== expectedIr) {
      errors.push('Go compiler IR does not match golden file');
    }
    if (rustResult?.success && rustResult.irJson && rustResult.irJson !== expectedIr) {
      errors.push('Rust compiler IR does not match golden file');
    }
    if (pythonResult?.success && pythonResult.irJson && pythonResult.irJson !== expectedIr) {
      errors.push('Python compiler IR does not match golden file');
    }
    if (zigResult?.success && zigResult.irJson && zigResult.irJson !== expectedIr) {
      errors.push('Zig compiler IR does not match golden file');
    }
    if (rubyResult?.success && rubyResult.irJson && rubyResult.irJson !== expectedIr) {
      errors.push('Ruby compiler IR does not match golden file');
    }
    if (javaResult?.success && javaResult.irJson && javaResult.irJson !== expectedIr) {
      errors.push('Java compiler IR does not match golden file');
    }
  }

  if (!skipGolden && existsSync(expectedScriptFile) && goldenGateOk) {
    const expectedScript = readFileSync(expectedScriptFile, 'utf-8').trim().toLowerCase();
    if (tsIncluded) {
      const tsScript = tsResult.scriptHex.toLowerCase().replace(/\s/g, '');
      if (tsScript && tsScript !== expectedScript) {
        errors.push(`TS compiler script does not match golden file`);
      }
    }
    if (goResult?.success && goResult.scriptHex) {
      const goScript = goResult.scriptHex.toLowerCase().replace(/\s/g, '');
      if (goScript !== expectedScript) {
        errors.push('Go compiler script does not match golden file');
      }
    }
    if (rustResult?.success && rustResult.scriptHex) {
      const rustScript = rustResult.scriptHex.toLowerCase().replace(/\s/g, '');
      if (rustScript !== expectedScript) {
        errors.push('Rust compiler script does not match golden file');
      }
    }
    if (pythonResult?.success && pythonResult.scriptHex) {
      const pythonScript = pythonResult.scriptHex.toLowerCase().replace(/\s/g, '');
      if (pythonScript !== expectedScript) {
        errors.push('Python compiler script does not match golden file');
      }
    }
    if (zigResult?.success && zigResult.scriptHex) {
      const zigScript = zigResult.scriptHex.toLowerCase().replace(/\s/g, '');
      if (zigScript !== expectedScript) {
        errors.push('Zig compiler script does not match golden file');
      }
    }
    if (rubyResult?.success && rubyResult.scriptHex) {
      const rubyScript = rubyResult.scriptHex.toLowerCase().replace(/\s/g, '');
      if (rubyScript !== expectedScript) {
        errors.push('Ruby compiler script does not match golden file');
      }
    }
    if (javaResult?.success && javaResult.scriptHex) {
      const javaScript = javaResult.scriptHex.toLowerCase().replace(/\s/g, '');
      if (javaScript !== expectedScript) {
        errors.push('Java compiler script does not match golden file');
      }
    }
  }

  return {
    testName,
    tsCompiler: tsResult,
    goCompiler: goResult,
    rustCompiler: rustResult,
    pythonCompiler: pythonResult,
    zigCompiler: zigResult,
    rubyCompiler: rubyResult,
    javaCompiler: javaResult,
    irMatch: irMatch.ok,
    scriptMatch: scriptMatch.ok,
    errors,
  };
}

/**
 * Discover and run all conformance tests in the given directory.
 *
 * Each subdirectory of `testsDir` is treated as a separate test case.
 * Returns results for all tests, sorted by test name.
 */
export async function runAllConformanceTests(
  testsDir: string,
  options?: { filter?: string },
): Promise<ConformanceResult[]> {
  const entries = readdirSync(testsDir, { withFileTypes: true });
  let testDirs = entries
    .filter((e) => e.isDirectory())
    .map((e) => join(testsDir, e.name))
    .sort();

  // Optional filter: only run tests whose name includes the filter string
  if (options?.filter) {
    const filterLower = options.filter.toLowerCase();
    testDirs = testDirs.filter((d) =>
      basename(d).toLowerCase().includes(filterLower),
    );
  }

  // Bounded-concurrency parallelism: each test fires 7 compilers simultaneously,
  // so we cap outer parallelism conservatively. See `defaultConcurrency`.
  const limit = makeLimiter(defaultConcurrency());
  const tasks = testDirs.map((testDir) => limit(() => runConformanceTest(testDir)));
  return Promise.all(tasks);
}

/**
 * Update the golden files for a given test case from the TypeScript compiler
 * output. This is used to establish the initial baseline.
 */
export async function updateGoldenFiles(testDir: string): Promise<void> {
  const testName = basename(testDir);
  const sourceFile = resolveSourceFile(testDir, testName);
  const source = readFileSync(sourceFile, 'utf-8');

  const tsResult = await runTsCompiler(source, sourceFile);
  if (!tsResult.success) {
    throw new Error(`Cannot update golden files: TS compiler failed: ${tsResult.error}`);
  }

  if (tsResult.irJson) {
    writeFileSync(join(testDir, 'expected-ir.json'), tsResult.irJson + '\n', 'utf-8');
  }
  if (tsResult.scriptHex) {
    writeFileSync(join(testDir, 'expected-script.hex'), tsResult.scriptHex + '\n', 'utf-8');
  }
}

// ---------------------------------------------------------------------------
// Multi-format conformance testing
// ---------------------------------------------------------------------------

/**
 * Discover all input format source files in a test directory.
 *
 * Sources MUST be declared in `source.json` via the `sources` map (or legacy
 * `path` field). Conformance test directories are not allowed to host their
 * own `*.runar.<ext>` source files — contracts live under `examples/` and
 * `source.json` references them by relative path. Any orphan source file
 * inside a case directory is a hard error so drift is caught immediately.
 *
 * Returns an array of { ext, sourceFile } for each format found.
 */
function discoverFormats(testDir: string, testName: string): { ext: string; sourceFile: string }[] {
  const found: { ext: string; sourceFile: string }[] = [];

  const configFile = join(testDir, 'source.json');
  let parserSkip: string[] = [];
  let parserSkipReason: string | undefined;
  if (existsSync(configFile)) {
    const config = JSON.parse(readFileSync(configFile, 'utf-8')) as {
      path?: string;
      sources?: Record<string, string>;
      parserSkip?: string[];
      parserSkipReason?: string;
    };
    // A fixture must declare its sources EXACTLY ONE way. Four independent
    // resolvers read source.json (this runner, witnesses/differential.test.ts,
    // witnesses/real-crypto-execution.test.ts, script_execution_test.go) and
    // they disagree on precedence when BOTH keys are present — this runner
    // prefers `path`, the other three prefer `sources`, so the same fixture
    // would silently be compiled from two different files depending on which
    // harness ran. Forbidding the overlap makes all four provably equivalent
    // without duplicating a precedence rule across three languages.
    if (config.path && config.sources) {
      throw new Error(
        `Conformance fixture '${testName}': source.json declares BOTH "path" and ` +
        `"sources". Use "sources" (the multi-format map) alone — harnesses disagree ` +
        `on which wins, so the fixture could be compiled from different files by ` +
        `different gates.`,
      );
    }
    parserSkip = Array.isArray(config.parserSkip) ? config.parserSkip : [];
    parserSkipReason = typeof config.parserSkipReason === 'string'
      ? config.parserSkipReason
      : undefined;
    if (config.sources) {
      for (const [ext, relPath] of Object.entries(config.sources)) {
        const sourceFile = resolve(testDir, relPath);
        if (existsSync(sourceFile)) {
          found.push({ ext, sourceFile });
        }
      }
    } else if (config.path) {
      const sourceFile = resolve(testDir, config.path);
      if (existsSync(sourceFile)) {
        const ext = INPUT_FORMATS.find(f => sourceFile.endsWith(f.ext))?.ext ?? '.runar.ts';
        found.push({ ext, sourceFile });
      }
    }
  }

  // Defensive: reject orphan *.runar.<ext> files inside the case dir that aren't
  // referenced by source.json. Forces contracts to live under examples/.
  // Skips *.runar.json artifact fixtures (e.g. basic-p2pkh.runar.json).
  try {
    const referenced = new Set(found.map(f => resolve(f.sourceFile)));
    for (const file of readdirSync(testDir)) {
      const lower = file.toLowerCase();
      if (!lower.includes('.runar.') || lower.endsWith('.runar.json')) continue;
      const abs = resolve(join(testDir, file));
      if (!referenced.has(abs)) {
        throw new Error(
          `Orphan source file in conformance test '${testName}': ${file}. ` +
          `Move it under examples/ and reference it from source.json.`,
        );
      }
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('Orphan source file')) throw err;
    // Directory read failed for non-orphan reason; ignore.
  }

  // Parser-coverage assertion: every fixture must ship every one of the nine
  // input formats unless source.json explicitly opts out via parserSkip[]
  // (with a non-empty parserSkipReason). The conformance allowlist
  // (`compilers`) is for Stack-IR/hex parity ONLY — the parser layer is
  // tier-agnostic, so a missing format is an unconditional bug. Failing
  // loud here keeps the bar from quietly slipping back to "TS-only" when a
  // new fixture lands. See spec/README.md ("Each compiler must parse every
  // fixture in every one of the nine source formats").
  const allExts = INPUT_FORMATS.map(f => f.ext);
  const presentExts = new Set(found.map(f => f.ext));
  const skipSet = new Set(parserSkip);
  const missing = allExts.filter(ext => !presentExts.has(ext) && !skipSet.has(ext));
  if (missing.length > 0) {
    throw new Error(
      `Parser-coverage gap in conformance fixture '${testName}': ` +
      `source.json is missing source(s) for ${missing.join(', ')}. ` +
      `Either add the missing format file(s), or — if the missing format is ` +
      `legitimately blocked — list it in source.json's "parserSkip" array ` +
      `with a non-empty "parserSkipReason" string explaining why.`,
    );
  }
  if (parserSkip.length > 0 && (!parserSkipReason || parserSkipReason.trim() === '')) {
    throw new Error(
      `Conformance fixture '${testName}': source.json carries "parserSkip" ` +
      `but no "parserSkipReason". Every parser opt-out requires a sharp ` +
      `justification — see CLAUDE.md and the parser-coverage rule above.`,
    );
  }
  for (const ext of parserSkip) {
    if (!(allExts as readonly string[]).includes(ext)) {
      throw new Error(
        `Conformance fixture '${testName}': source.json "parserSkip" lists ` +
        `unknown extension '${ext}'. Allowed values: ${allExts.join(', ')}.`,
      );
    }
  }

  return found;
}

/**
 * Read the optional per-fixture `compilers` allowlist from source.json.
 *
 * When present, conformance only runs the listed compilers for this fixture
 * (intersected with each format's natively supported compiler set). Used to
 * mark fixtures whose codegen is intentionally implemented in only a subset
 * of tiers — e.g. Go-only crypto modules (BabyBear / Merkle / Poseidon2 /
 * BN254 / KoalaBear / FiatShamirKb), or fixtures pending in a particular
 * tier (e.g. Java M6 variable-length state deserialization).
 *
 * Returns null when the field is absent (= "all compilers"), or a Set of
 * allowed compiler ids.
 */
function readFixtureCompilerAllowlist(testDir: string): Set<CompilerId> | null {
  const configFile = join(testDir, 'source.json');
  if (!existsSync(configFile)) return null;
  try {
    const config = JSON.parse(readFileSync(configFile, 'utf-8')) as {
      compilers?: string[];
    };
    if (!config.compilers || !Array.isArray(config.compilers)) return null;
    return new Set(config.compilers as CompilerId[]);
  } catch {
    return null;
  }
}

/**
 * Run a single conformance test for a specific format variant.
 *
 * Only runs compilers that support the given format. Results are compared
 * against the same golden files and against each other.
 */
export async function runConformanceTestForFormat(
  testDir: string,
  format: { ext: string; sourceFile: string },
): Promise<ConformanceResult> {
  // CI safety net: see runConformanceTest above.
  assertAllCompilersAvailableInCi();

  const testName = basename(testDir);
  const expectedIrFile = join(testDir, 'expected-ir.json');
  const expectedScriptFile = join(testDir, 'expected-script.hex');

  // Fold-ON allowlist: when running with constant folding enabled, optionally
  // skip a fixture+format combo that has a known fold-on cross-tier divergence.
  // The reason string is surfaced in the report so reviewers see exactly why
  // the test was skipped (no silent passes — see conformance/fold-on-allowlist.json).
  const foldSkip = foldOnSkipReason(testName, format.ext);
  if (foldSkip !== null) {
    console.log(`  fold-on SKIP ${testName} [${format.ext}]: ${foldSkip}`);
    return {
      testName: `${testName} [${format.ext}] (fold-on skipped)`,
      format: format.ext,
      tsCompiler: { irJson: '', scriptHex: '', scriptAsm: '', success: true, durationMs: 0 },
      irMatch: true,
      scriptMatch: true,
      errors: [],
    };
  }

  const source = readFileSync(format.sourceFile, 'utf-8');
  const errors: string[] = [];

  // Determine which compilers support this format
  const formatDef = INPUT_FORMATS.find(f => f.ext === format.ext);
  let supportedCompilers: readonly CompilerId[] = formatDef?.compilers ?? EMPTY_COMPILERS;

  // Per-fixture compiler allowlist (e.g. Go-only crypto fixtures, Java-deferred fixtures).
  const allowlist = readFixtureCompilerAllowlist(testDir);
  if (allowlist) {
    supportedCompilers = supportedCompilers.filter((c) => allowlist.has(c));
  }

  // Run compilers that support this format — in parallel.
  const tsPromise = supportedCompilers.includes('ts')
    ? runTsCompiler(source, format.sourceFile)
    : Promise.resolve<CompilerOutput>({ irJson: '', scriptHex: '', scriptAsm: '', success: false, error: 'Format not supported by TS compiler', durationMs: 0 });

  const goPromise = supportedCompilers.includes('go')
    ? runGoCompiler(source, format.sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const rustPromise = supportedCompilers.includes('rust')
    ? runRustCompiler(source, format.sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const pythonPromise = supportedCompilers.includes('python')
    ? runPythonCompiler(source, format.sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const zigPromise = supportedCompilers.includes('zig')
    ? runZigCompiler(source, format.sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const rubyPromise = supportedCompilers.includes('ruby')
    ? runRubyCompiler(source, format.sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const javaPromise = supportedCompilers.includes('java')
    ? runJavaCompiler(source, format.sourceFile)
    : Promise.resolve<CompilerOutput | undefined>(undefined);

  const [tsResult, goResult, rustResult, pythonResult, zigResult, rubyResult, javaResult] = await Promise.all([
    tsPromise,
    goPromise,
    rustPromise,
    pythonPromise,
    zigPromise,
    rubyPromise,
    javaPromise,
  ]);

  if (supportedCompilers.includes('ts') && !tsResult.success) {
    errors.push(`TypeScript compiler failed on ${format.ext}: ${tsResult.error ?? 'unknown error'}`);
  }
  if (goResult && !goResult.success) {
    errors.push(`Go compiler failed on ${format.ext}: ${goResult.error ?? 'unknown error'}`);
  }
  if (rustResult && !rustResult.success) {
    errors.push(`Rust compiler failed on ${format.ext}: ${rustResult.error ?? 'unknown error'}`);
  }
  if (pythonResult && !pythonResult.success) {
    errors.push(`Python compiler failed on ${format.ext}: ${pythonResult.error ?? 'unknown error'}`);
  }
  if (zigResult && !zigResult.success) {
    errors.push(`Zig compiler failed on ${format.ext}: ${zigResult.error ?? 'unknown error'}`);
  }
  if (rubyResult && !rubyResult.success) {
    errors.push(`Ruby compiler failed on ${format.ext}: ${rubyResult.error ?? 'unknown error'}`);
  }
  if (javaResult && !javaResult.success) {
    errors.push(`Java compiler failed on ${format.ext}: ${javaResult.error ?? 'unknown error'}`);
  }

  // Cross-compiler comparison within this format. When the fixture
  // restricts the compiler set to a single tier (e.g. Go-only crypto
  // modules), pass the expected count so a one-compiler success is
  // treated as a trivial match rather than "cannot cross-validate".
  const irMatch = compareIR(
    [
      supportedCompilers.includes('ts') ? tsResult : undefined,
      goResult,
      rustResult,
      pythonResult,
      zigResult,
      rubyResult,
      javaResult,
    ],
    supportedCompilers.length,
  );
  if (!irMatch.ok) {
    errors.push(`IR mismatch between compilers for ${format.ext}: ${irMatch.detail ?? 'no detail'}`);
  }

  const scriptMatch = compareScript(
    [
      supportedCompilers.includes('ts') ? tsResult : undefined,
      goResult,
      rustResult,
      pythonResult,
      zigResult,
      rubyResult,
      javaResult,
    ],
    supportedCompilers.length,
  );
  if (!scriptMatch.ok) {
    errors.push(`Script hex mismatch between compilers for ${format.ext}: ${scriptMatch.detail ?? 'no detail'}`);
  }

  // Golden file comparison (use any successful compiler output). Skipped
  // under fold-on (RUNAR_DISABLE_CONSTANT_FOLDING=0) — see runConformanceTest
  // above for the rationale.
  const skipGoldenMf = !constantFoldingDisabled();
  if (!skipGoldenMf && existsSync(expectedIrFile)) {
    const expectedIr = canonicalizeJson(readFileSync(expectedIrFile, 'utf-8'));
    const allOutputs = [
      supportedCompilers.includes('ts') ? tsResult : undefined,
      goResult,
      rustResult,
      pythonResult,
      zigResult,
      rubyResult,
      javaResult,
    ].filter((o): o is CompilerOutput => o !== undefined && o.success && o.irJson !== '');

    for (const output of allOutputs) {
      if (output.irJson !== expectedIr) {
        errors.push(`IR does not match golden file for ${format.ext}`);
        break;
      }
    }
  }

  if (!skipGoldenMf && existsSync(expectedScriptFile)) {
    const expectedScript = readFileSync(expectedScriptFile, 'utf-8').trim().toLowerCase();
    const allOutputs = [
      supportedCompilers.includes('ts') ? tsResult : undefined,
      goResult,
      rustResult,
      pythonResult,
      zigResult,
      rubyResult,
      javaResult,
    ].filter((o): o is CompilerOutput => o !== undefined && o.success && o.scriptHex !== '');

    for (const output of allOutputs) {
      const normalized = output.scriptHex.toLowerCase().replace(/\s/g, '');
      if (normalized !== expectedScript) {
        errors.push(`Script does not match golden file for ${format.ext}`);
        break;
      }
    }
  }

  return {
    testName: `${testName} [${format.ext}]`,
    format: format.ext,
    tsCompiler: tsResult,
    goCompiler: goResult,
    rustCompiler: rustResult,
    pythonCompiler: pythonResult,
    zigCompiler: zigResult,
    rubyCompiler: rubyResult,
    javaCompiler: javaResult,
    irMatch: irMatch.ok,
    scriptMatch: scriptMatch.ok,
    errors,
  };
}

/**
 * Run conformance tests for all discovered formats in a single test directory.
 *
 * For each format variant found (e.g., .runar.ts, .runar.yaml, .runar.sol),
 * run the test independently. Also checks cross-format consistency: all
 * formats must produce the same output.
 */
export async function runMultiFormatConformanceTest(
  testDir: string,
): Promise<ConformanceResult[]> {
  const testName = basename(testDir);
  const formats = discoverFormats(testDir, testName);

  if (formats.length === 0) {
    return [{
      testName,
      tsCompiler: { irJson: '', scriptHex: '', scriptAsm: '', success: false, error: 'No source files found', durationMs: 0 },
      irMatch: false,
      scriptMatch: false,
      errors: ['No source files found in test directory'],
    }];
  }

  // Within a single test dir, run formats in parallel — they're independent
  // (different source files, separate temp files).
  return Promise.all(formats.map((format) => runConformanceTestForFormat(testDir, format)));
}

/**
 * Discover and run multi-format conformance tests across all test directories.
 *
 * Concurrency model: a SINGLE shared limiter bounds (fixture × format) tasks
 * across the entire suite. Each task internally still fires 7 compilers in
 * parallel via Promise.all (cheap and disjoint), but the per-fixture
 * "9 formats simultaneously" fan-out is gone — formats walk through the same
 * limiter as fixtures. This caps peak subprocess concurrency at
 * `defaultConcurrency() × 7` instead of the prior
 * `defaultConcurrency() × 9 × 7`, which under load caused JVM/cargo
 * cold-start contention, pipe-buffer pressure, and flaky FAILs.
 */
export async function runAllMultiFormatConformanceTests(
  testsDir: string,
  options?: { filter?: string; format?: string },
): Promise<ConformanceResult[]> {
  const entries = readdirSync(testsDir, { withFileTypes: true });
  let testDirs = entries
    .filter((e) => e.isDirectory())
    .map((e) => join(testsDir, e.name))
    .sort();

  if (options?.filter) {
    const filterLower = options.filter.toLowerCase();
    testDirs = testDirs.filter((d) => basename(d).toLowerCase().includes(filterLower));
  }

  const limit = makeLimiter(defaultConcurrency());

  const allTasks: Promise<ConformanceResult>[] = [];
  for (const testDir of testDirs) {
    const formats = discoverFormats(testDir, basename(testDir));
    if (formats.length === 0) {
      allTasks.push(
        Promise.resolve<ConformanceResult>({
          testName: basename(testDir),
          tsCompiler: { irJson: '', scriptHex: '', scriptAsm: '', success: false, error: 'No source files found', durationMs: 0 },
          irMatch: false,
          scriptMatch: false,
          errors: ['No source files found in test directory'],
        }),
      );
      continue;
    }
    for (const format of formats) {
      allTasks.push(limit(() => runConformanceTestForFormat(testDir, format)));
    }
  }

  const results = await Promise.all(allTasks);
  if (options?.format) {
    return results.filter((r) => r.format === options.format);
  }
  return results;
}

// Re-export for tools that previously imported these helpers. `runCmd` is also
// a test seam: `runner/__tests__/subprocess-integrity.test.ts` pins the
// "a killed child is never a successful compile" invariant directly on this
// primitive, because every tier's output flows through it.
export { runCmd };
export type { RunResult, RunOptions };
