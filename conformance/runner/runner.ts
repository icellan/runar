import { readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { join, basename, resolve, dirname, extname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { execSync, spawn } from 'child_process';
import os from 'os';
import { JavaDaemon } from './java-daemon.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
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
  code: number;
  timedOut: boolean;
  error?: Error;
}

interface RunOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  maxBuffer?: number;
}

function runCmd(cmd: string, args: string[], opts: RunOptions = {}): Promise<RunResult> {
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
      resolvePromise({
        stdout: Buffer.concat(outChunks).toString('utf-8'),
        stderr: Buffer.concat(errChunks).toString('utf-8'),
        code: -1,
        timedOut,
        error: err,
      });
    });

    proc.on('close', (code) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolvePromise({
        stdout: Buffer.concat(outChunks).toString('utf-8'),
        stderr: Buffer.concat(errChunks).toString('utf-8'),
        code: code ?? 0,
        timedOut,
      });
    });
  });
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
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    const artifactDir = join(tmpDir, `artifacts-ts-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    if (!existsSync(artifactDir)) mkdirSync(artifactDir, { recursive: true });

    const cliEntry = resolve(__dirname, '../../packages/runar-cli/src/bin.ts');
    const tsxLoader = resolveTsxLoader();
    const result = await runCmd(
      'node',
      ['--import', tsxLoader, cliEntry, 'compile', tmpFile, '--ir', ...foldFlag(), '-o', artifactDir],
      // 180_000ms: tsx pays a cold-start cost per invocation; the prior 30s
      // budget tripped on arithmetic / blake3 / convergence-proof on slower
      // hosts.
      { timeoutMs: 180_000, cwd: REPO_ROOT },
    );
    if (result.code !== 0) {
      throw new Error(
        `TS compiler exited with code ${result.code}${result.timedOut ? ' (timeout)' : ''}: ${result.stderr || result.stdout}`,
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
        return asBigInt.toString();
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
  }
}

/**
 * Run the Go compiler on the given source. Returns undefined if the Go
 * compiler is not available.
 */
async function runGoCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  const binary = findGoBinary();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);

  const start = performance.now();
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `go-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    // Get IR output
    const irRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--emit-ir', ...foldFlag()],
      { timeoutMs: 30_000, cwd: GO_COMPILER_DIR },
    );
    if (irRes.code !== 0) {
      throw new Error(`go --emit-ir exit ${irRes.code}: ${irRes.stderr || irRes.stdout}`);
    }
    const irOutput = irRes.stdout.trim();

    // Get script hex output
    const hexRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--hex', ...foldFlag()],
      { timeoutMs: 30_000, cwd: GO_COMPILER_DIR },
    );
    if (hexRes.code !== 0) {
      throw new Error(`go --hex exit ${hexRes.code}: ${hexRes.stderr || hexRes.stdout}`);
    }
    const scriptHexOutput = hexRes.stdout.trim();

    const durationMs = performance.now() - start;
    return {
      irJson: canonicalizeJson(irOutput),
      scriptHex: scriptHexOutput,
      scriptAsm: '',
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
  }
}

/**
 * Run the Rust compiler on the given source. Returns undefined if the Rust
 * compiler is not available.
 */
async function runRustCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  const binary = findRustBinary();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);

  const start = performance.now();
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `rust-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    const irRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--emit-ir', ...foldFlag()],
      { timeoutMs: 30_000, cwd: RUST_COMPILER_DIR, env: cargoAwareEnv() },
    );
    if (irRes.code !== 0) {
      throw new Error(`rust --emit-ir exit ${irRes.code}: ${irRes.stderr || irRes.stdout}`);
    }
    const irOutput = irRes.stdout.trim();

    const hexRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--hex', ...foldFlag()],
      { timeoutMs: 30_000, cwd: RUST_COMPILER_DIR, env: cargoAwareEnv() },
    );
    if (hexRes.code !== 0) {
      throw new Error(`rust --hex exit ${hexRes.code}: ${hexRes.stderr || hexRes.stdout}`);
    }
    const scriptHexOutput = hexRes.stdout.trim();

    const durationMs = performance.now() - start;
    return {
      irJson: canonicalizeJson(irOutput),
      scriptHex: scriptHexOutput,
      scriptAsm: '',
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
  }
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
async function runPythonCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  const binary = findPythonCompiler();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);

  const start = performance.now();
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `python-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    const irRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--emit-ir', ...foldFlag()],
      { timeoutMs: 30_000, cwd: PYTHON_COMPILER_DIR },
    );
    if (irRes.code !== 0) {
      throw new Error(`python --emit-ir exit ${irRes.code}: ${irRes.stderr || irRes.stdout}`);
    }
    const irOutput = irRes.stdout.trim();

    const hexRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--hex', ...foldFlag()],
      { timeoutMs: 30_000, cwd: PYTHON_COMPILER_DIR },
    );
    if (hexRes.code !== 0) {
      throw new Error(`python --hex exit ${hexRes.code}: ${hexRes.stderr || hexRes.stdout}`);
    }
    const scriptHexOutput = hexRes.stdout.trim();

    const durationMs = performance.now() - start;
    return {
      irJson: canonicalizeJson(irOutput),
      scriptHex: scriptHexOutput,
      scriptAsm: '',
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
  }
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
async function runZigCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  const binary = findZigBinary();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);

  const start = performance.now();
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `zig-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    const irRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--emit-ir', ...foldFlag()],
      { timeoutMs: 30_000, cwd: ZIG_COMPILER_DIR },
    );
    if (irRes.code !== 0) {
      throw new Error(`zig --emit-ir exit ${irRes.code}: ${irRes.stderr || irRes.stdout}`);
    }
    const irOutput = irRes.stdout.trim();

    const hexRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--hex', ...foldFlag()],
      { timeoutMs: 30_000, cwd: ZIG_COMPILER_DIR },
    );
    if (hexRes.code !== 0) {
      throw new Error(`zig --hex exit ${hexRes.code}: ${hexRes.stderr || hexRes.stdout}`);
    }
    const scriptHexOutput = hexRes.stdout.trim();

    const durationMs = performance.now() - start;
    return {
      irJson: canonicalizeJson(irOutput),
      scriptHex: scriptHexOutput,
      scriptAsm: '',
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
  }
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
async function runRubyCompiler(source: string, sourceFile: string): Promise<CompilerOutput | undefined> {
  const binary = findRubyBinary();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);

  const start = performance.now();
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `ruby-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    const irRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--emit-ir', ...foldFlag()],
      { timeoutMs: 30_000, cwd: RUBY_COMPILER_DIR },
    );
    if (irRes.code !== 0) {
      throw new Error(`ruby --emit-ir exit ${irRes.code}: ${irRes.stderr || irRes.stdout}`);
    }
    const irOutput = irRes.stdout.trim();

    const hexRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--hex', ...foldFlag()],
      { timeoutMs: 30_000, cwd: RUBY_COMPILER_DIR },
    );
    if (hexRes.code !== 0) {
      throw new Error(`ruby --hex exit ${hexRes.code}: ${hexRes.stderr || hexRes.stdout}`);
    }
    const scriptHexOutput = hexRes.stdout.trim();

    const durationMs = performance.now() - start;
    return {
      irJson: canonicalizeJson(irOutput),
      scriptHex: scriptHexOutput,
      scriptAsm: '',
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
  }
}

/**
 * Check whether the Java compiler jar is available. Mirrors the binary-
 * discovery pattern used for Go / Rust: prefer a distributable artifact
 * over spawning a build system. M4 ships IR only; hex lands in M5.
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
 * Run the Java compiler on the given source. Returns undefined if the
 * Java compiler jar is not available. A failing --hex invocation is
 * captured gracefully with scriptHex = '' (stack lowering + emit land
 * in M5).
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
      return {
        irJson: canonicalizeJson(resp.ir ?? ''),
        scriptHex: resp.hex ?? '',
        scriptAsm: '',
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
    }
  }

  // One-shot mode (original behaviour, for `RUNAR_JAVA_DAEMON=0`).
  const binary = findJavaBinary();
  if (!binary) return undefined;
  const { cmd, args: bin_args } = splitCmd(binary);
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `java-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    const irRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--emit-ir', ...foldFlag()],
      { timeoutMs: 30_000, cwd: JAVA_COMPILER_DIR },
    );
    if (irRes.code !== 0) {
      throw new Error(`java --emit-ir exit ${irRes.code}: ${irRes.stderr || irRes.stdout}`);
    }
    const irOutput = irRes.stdout.trim();

    let scriptHex = '';
    const hexRes = await runCmd(
      cmd,
      [...bin_args, '--source', tmpFile, '--hex', ...foldFlag()],
      { timeoutMs: 30_000, cwd: JAVA_COMPILER_DIR },
    );
    if (hexRes.code === 0) {
      scriptHex = hexRes.stdout.trim();
    }

    const durationMs = performance.now() - start;
    return {
      irJson: canonicalizeJson(irOutput),
      scriptHex,
      scriptAsm: '',
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
  }
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
    const parsed = JSON.parse(json);
    return JSON.stringify(sortKeys(parsed), null, 2);
  } catch {
    return json; // Return as-is if not valid JSON
  }
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
 * Compare IR output across all available compilers. Returns true if every
 * pair of successful compilers produced the same canonical IR JSON.
 *
 * When the caller restricted the compiler set (e.g. via the per-fixture
 * `compilers` allowlist in source.json, used for Go-only crypto modules),
 * pass `expectedCount` so a single successful compiler is treated as a
 * trivial match rather than a "cannot cross-validate" failure.
 */
function compareIR(
  outputs: (CompilerOutput | undefined)[],
  expectedCount?: number,
): boolean {
  const successfulIRs = outputs
    .filter((o): o is CompilerOutput => o !== undefined && o.success && o.irJson !== '')
    .map((o) => o.irJson);

  if (successfulIRs.length < 2) {
    if (successfulIRs.length === 0) return true; // No compilers produced IR — not a mismatch
    if (expectedCount === 1) return true; // Single-compiler fixture: trivial match
    console.warn(`  WARNING: only ${successfulIRs.length} compiler(s) produced IR — cannot cross-validate`);
    return false;
  }
  return successfulIRs.every((ir) => ir === successfulIRs[0]);
}

/**
 * Compare compiled Bitcoin Script hex across all available compilers.
 * Returns true if every pair of successful compilers produced the same hex.
 *
 * See `compareIR` for `expectedCount` semantics.
 */
function compareScript(
  outputs: (CompilerOutput | undefined)[],
  expectedCount?: number,
): boolean {
  const successfulHexes = outputs
    .filter((o): o is CompilerOutput => o !== undefined && o.success && o.scriptHex !== '')
    .map((o) => o.scriptHex.toLowerCase().replace(/\s/g, ''));

  if (successfulHexes.length < 2) {
    if (successfulHexes.length === 0) return true; // No compilers produced hex — not a mismatch
    if (expectedCount === 1) return true; // Single-compiler fixture: trivial match
    console.warn(`  WARNING: only ${successfulHexes.length} compiler(s) produced hex — cannot cross-validate`);
    return false;
  }
  return successfulHexes.every((hex) => hex === successfulHexes[0]);
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

  // Run all compilers in parallel — they're fully independent processes.
  const [tsResult, goResult, rustResult, pythonResult, zigResult, rubyResult, javaResult] = await Promise.all([
    runTsCompiler(source, sourceFile),
    runGoCompiler(source, sourceFile),
    runRustCompiler(source, sourceFile),
    runPythonCompiler(source, sourceFile),
    runZigCompiler(source, sourceFile),
    runRubyCompiler(source, sourceFile),
    runJavaCompiler(source, sourceFile),
  ]);

  if (!tsResult.success) {
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

  // Cross-compiler IR comparison
  const irMatch = compareIR([tsResult, goResult, rustResult, pythonResult, zigResult, rubyResult, javaResult]);
  if (!irMatch) {
    errors.push('IR mismatch between compilers');
  }

  // Cross-compiler script comparison
  const scriptMatch = compareScript([tsResult, goResult, rustResult, pythonResult, zigResult, rubyResult, javaResult]);
  if (!scriptMatch) {
    errors.push('Script hex mismatch between compilers');
  }

  // Golden file comparisons. Skipped under fold-on (RUNAR_DISABLE_CONSTANT_FOLDING=0)
  // because every existing expected-ir.json / expected-script.hex was stamped
  // with the fold-off compiler flag. Cross-tier parity (above) is still
  // strictly enforced in fold-on mode — the goldens are merely a reference
  // for the fold-off run.
  const skipGolden = !constantFoldingDisabled();
  if (!skipGolden && existsSync(expectedIrFile) && tsResult.success) {
    const expectedIr = canonicalizeJson(readFileSync(expectedIrFile, 'utf-8'));
    if (tsResult.irJson !== expectedIr) {
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

  if (!skipGolden && existsSync(expectedScriptFile) && tsResult.success) {
    const expectedScript = readFileSync(expectedScriptFile, 'utf-8').trim().toLowerCase();
    const tsScript = tsResult.scriptHex.toLowerCase().replace(/\s/g, '');
    if (tsScript && tsScript !== expectedScript) {
      errors.push(`TS compiler script does not match golden file`);
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
    irMatch,
    scriptMatch,
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
    if (!allExts.includes(ext)) {
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
  if (!irMatch) {
    errors.push(`IR mismatch between compilers for ${format.ext}`);
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
  if (!scriptMatch) {
    errors.push(`Script hex mismatch between compilers for ${format.ext}`);
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
    irMatch,
    scriptMatch,
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

// Re-export for tools that previously imported these helpers.
export { runCmd };
