/**
 * IR-based differential fuzzer.
 *
 * Uses the language-neutral generator in `runar-testing/src/fuzzer/` to produce
 * richer contracts than the legacy string-based generator (multiple property
 * types, stateful contracts, built-in calls, if/else bodies, and so on) and
 * then feeds the rendered source through every available compiler.
 *
 * Two rendering strategies:
 *   - "ts"     — render to TypeScript once; every compiler parses the same .runar.ts
 *                (exercises the 6 compiler back-ends with the same front-end input).
 *   - "native" — render each compiler's native source format (.runar.ts, .runar.go,
 *                .runar.rs, .runar.py, etc.) — exercises each compiler's frontend too.
 */
import fc from 'fast-check';
import { writeFileSync, mkdirSync, existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';

import {
  arbGeneratedContract,
  arbGeneratedStatefulContract,
  renderTypeScript,
  renderGo,
  renderRust,
  renderPython,
  renderZig,
  renderRuby,
  renderJava,
} from '../../packages/runar-testing/src/fuzzer/index.js';
import type { GeneratedContract } from '../../packages/runar-testing/src/fuzzer/index.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CompilerName = 'ts' | 'go' | 'rust' | 'python' | 'zig' | 'ruby' | 'java';
export type RenderStrategy = 'ts' | 'native';

export interface IRFuzzerOptions {
  seed?: number;
  compilers?: CompilerName[];
  verbose?: boolean;
  /** Compare final hex script instead of IR. */
  compareHex?: boolean;
  /** Include stateful contracts in the generated distribution. */
  includeStateful?: boolean;
  /** How each compiler should receive its source — shared TS or per-language. */
  renderStrategy?: RenderStrategy;
  /** Directory to save failing cases. */
  findingsDir?: string;
}

export interface IRDifferentialResult {
  contractName: string;
  /** Rendered source(s) that were fed into each compiler (keyed by compiler name). */
  sources: Partial<Record<CompilerName, string>>;
  outputs: Partial<Record<CompilerName, string>>;
  match: boolean;
  mismatchDetails?: string;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = resolve(__dirname, '../..');

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const TS_EXT = '.runar.ts';

/** Per-compiler extension + renderer for the "native" strategy. */
const NATIVE_RENDERERS: Record<CompilerName, { ext: string; render: (c: GeneratedContract) => string }> = {
  ts: { ext: '.runar.ts', render: renderTypeScript },
  go: { ext: '.runar.go', render: renderGo },
  rust: { ext: '.runar.rs', render: renderRust },
  python: { ext: '.runar.py', render: renderPython },
  zig: { ext: '.runar.zig', render: renderZig },
  ruby: { ext: '.runar.rb', render: renderRuby },
  java: { ext: '.runar.java', render: renderJava },
};

/**
 * The Java compiler (compilers/java/) parses only `.runar.java` today — the
 * cross-language .runar.java parsers land in milestone 7. In the shared-TS
 * render strategy the generator emits a single .runar.ts that every compiler
 * parses, which Java cannot consume. Force Java onto its own rendered source
 * regardless of strategy so it always gets valid Java.
 */
function renderForCompiler(
  compiler: CompilerName,
  contract: GeneratedContract,
  strategy: RenderStrategy,
): { source: string; ext: string } {
  if (compiler === 'java') {
    return { source: renderJava(contract), ext: '.runar.java' };
  }
  if (strategy === 'ts') {
    return { source: renderTypeScript(contract), ext: TS_EXT };
  }
  const { ext, render } = NATIVE_RENDERERS[compiler];
  return { source: render(contract), ext };
}

// ---------------------------------------------------------------------------
// Compiler invocation
// ---------------------------------------------------------------------------

function runProcess(cmd: string, args: string[], opts: { cwd?: string; timeout?: number } = {}): string | null {
  try {
    return execFileSync(cmd, args, {
      timeout: opts.timeout ?? 20_000,
      encoding: 'utf-8',
      cwd: opts.cwd ?? ROOT,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch {
    return null;
  }
}

function findBinary(relative: string): string | null {
  const candidate = resolve(ROOT, relative);
  try {
    execFileSync(candidate, ['--help'], { stdio: 'pipe', timeout: 5000 });
    return candidate;
  } catch {
    return null;
  }
}

/**
 * Find the Java compiler shaded jar, mirroring the Go / Rust / Ruby
 * discovery pattern in `conformance/runner/runner.ts:findJavaBinary`.
 *
 * Accepts either the canonical `runar-java.jar` launcher or the versioned
 * `runar-java-compiler-<version>.jar` Gradle produces by default.
 *
 * Returns the absolute jar path (caller invokes `java -jar <path>`) or null
 * when no jar is on disk or no `java` executable is reachable.
 */
function findJavaJar(): string | null {
  const libsDir = resolve(ROOT, 'compilers/java/build/libs');
  if (!existsSync(libsDir)) return null;
  try {
    execFileSync('java', ['-version'], { stdio: 'pipe', timeout: 5000 });
  } catch {
    return null;
  }
  const preferred = join(libsDir, 'runar-java.jar');
  if (existsSync(preferred)) return preferred;
  try {
    const entries = readdirSync(libsDir);
    for (const entry of entries) {
      if (entry.startsWith('runar-java-compiler-') && entry.endsWith('.jar')) {
        return join(libsDir, entry);
      }
    }
  } catch { /* ignore */ }
  return null;
}

interface CompilerDispatch {
  name: CompilerName;
  /** Run the compiler on the file, returning hex/IR on stdout or null on failure. */
  run: (file: string, hex: boolean) => string | null;
}

function dispatch(): Record<CompilerName, CompilerDispatch> {
  const go = findBinary('compilers/go/runar-go');
  const rust = findBinary('compilers/rust/target/release/runar-compiler-rust');
  const zig = findBinary('compilers/zig/zig-out/bin/runar-zig');
  const rubyScript = resolve(ROOT, 'compilers/ruby/bin/runar-compiler-ruby');
  const hasRuby = existsSync(rubyScript) && (() => {
    try {
      execFileSync('ruby', ['--version'], { stdio: 'pipe', timeout: 5000 });
      return true;
    } catch { return false; }
  })();
  const javaJar = findJavaJar();

  return {
    ts: {
      name: 'ts',
      run: tsCompileRun,
    },
    go: {
      name: 'go',
      run: (file, hex) => {
        if (!go) return null;
        return runProcess(go, ['--source', file, hex ? '--hex' : '--emit-ir', '--disable-constant-folding']);
      },
    },
    rust: {
      name: 'rust',
      run: (file, hex) => {
        if (!rust) return null;
        return runProcess(rust, ['--source', file, hex ? '--hex' : '--emit-ir', '--disable-constant-folding']);
      },
    },
    python: {
      name: 'python',
      run: (file, hex) =>
        runProcess('python3', [
          '-m', 'runar_compiler',
          '--source', file,
          hex ? '--hex' : '--emit-ir',
          '--disable-constant-folding',
        ], { cwd: resolve(ROOT, 'compilers/python') }),
    },
    zig: {
      name: 'zig',
      run: (file, hex) => {
        if (!zig) return null;
        return runProcess(zig, ['--source', file, hex ? '--hex' : '--emit-ir', '--disable-constant-folding']);
      },
    },
    ruby: {
      name: 'ruby',
      run: (file, hex) => {
        if (!hasRuby) return null;
        return runProcess('ruby', [rubyScript, '--source', file, hex ? '--hex' : '--emit-ir', '--disable-constant-folding']);
      },
    },
    java: {
      name: 'java',
      run: (file, hex) => {
        if (!javaJar) return null;
        return runProcess('java', [
          '-jar', javaJar,
          '--source', file,
          hex ? '--hex' : '--emit-ir',
          '--disable-constant-folding',
        ]);
      },
    },
  };
}

// ---------------------------------------------------------------------------
// TypeScript compilation (via dynamic import of runar-compiler)
// ---------------------------------------------------------------------------

type RunarCompileFn = (
  source: string,
  options?: { fileName?: string; disableConstantFolding?: boolean },
) => {
  success: boolean;
  anf?: unknown;
  artifact?: { script?: string };
};

let _cachedCompile: RunarCompileFn | null | undefined;

async function loadTsCompile(): Promise<RunarCompileFn | null> {
  if (_cachedCompile !== undefined) return _cachedCompile;
  try {
    const srcEntry = resolve(ROOT, 'packages/runar-compiler/src/index.ts');
    const mod = (await import(pathToFileURL(srcEntry).href)) as Record<string, unknown>;
    if (typeof mod.compile === 'function') {
      _cachedCompile = mod.compile as RunarCompileFn;
      return _cachedCompile;
    }
  } catch {
    // fall through
  }
  _cachedCompile = null;
  return _cachedCompile;
}

function tsCompileRun(file: string, hex: boolean): string | null {
  // This path is sync-by-contract; use a cached loaded compile fn.
  const compile = _cachedCompile;
  if (!compile) return null;
  try {
    const source = readFileSync(file, 'utf-8');
    const result = compile(source, { fileName: file, disableConstantFolding: true });
    if (!result.success) return null;
    if (hex) return result.artifact?.script ?? null;
    // JSON.stringify can't serialise BigInt values directly (the TS ANF pass
    // emits bigint literal values as native BigInt). Match what the other
    // compilers emit on stdout — bigints as bare JSON numbers — so the
    // cross-compiler diff stays sensible.
    return result.anf ? stringifyWithBigint(result.anf) : null;
  } catch (e) {
    if (process.env.FUZZ_DEBUG) console.error('ts-compile throw:', (e as Error).message);
    return null;
  }
}


function stringifyWithBigint(value: unknown): string {
  return JSON.stringify(value, (_k, v) => {
    if (typeof v === 'bigint') {
      // Match Go/Rust/Python/Java JCS: bare integer when representable, else
      // a decimal string. Bitcoin-sized constants are well within safe
      // integer range for fuzzer-generated contracts, but keep the fallback.
      if (v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)) {
        return Number(v);
      }
      return v.toString();
    }
    return v;
  });
}

// ---------------------------------------------------------------------------
// Comparison helpers
// ---------------------------------------------------------------------------

function canonicalizeJson(s: string): string {
  try {
    const obj = JSON.parse(s);
    return JSON.stringify(obj, Object.keys(obj).sort(), 2);
  } catch {
    return s;
  }
}

function normalizeOutput(output: string, compareHex: boolean): string {
  return compareHex ? output.trim().toLowerCase() : canonicalizeJson(output);
}

// ---------------------------------------------------------------------------
// Findings persistence
// ---------------------------------------------------------------------------

function saveFinding(
  findingsDir: string,
  result: IRDifferentialResult,
): void {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = join(findingsDir, ts);
  mkdirSync(dir, { recursive: true });

  for (const [compiler, source] of Object.entries(result.sources)) {
    if (source) writeFileSync(join(dir, `source-${compiler}.txt`), source, 'utf-8');
  }
  for (const [compiler, output] of Object.entries(result.outputs)) {
    if (output !== undefined) writeFileSync(join(dir, `output-${compiler}.txt`), output, 'utf-8');
  }
  writeFileSync(
    join(dir, 'finding.json'),
    JSON.stringify(
      {
        timestamp: ts,
        contractName: result.contractName,
        mismatchDetails: result.mismatchDetails,
      },
      null,
      2,
    ),
    'utf-8',
  );
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

export async function runIRDifferentialFuzzing(
  numPrograms: number,
  options: IRFuzzerOptions = {},
): Promise<IRDifferentialResult[]> {
  const compilers = options.compilers ?? ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'];
  const strategy: RenderStrategy = options.renderStrategy ?? 'ts';
  const compareHex = options.compareHex ?? true;
  const verbose = options.verbose ?? false;
  const findingsDir = options.findingsDir ?? join(__dirname, '..', 'fuzz-findings-ir');

  const tmpDir = join(__dirname, '..', '.tmp', 'fuzz-ir');
  if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });

  // Load the TS compiler once; subsequent iterations reuse the cached fn.
  if (compilers.includes('ts')) await loadTsCompile();

  const arb = options.includeStateful
    ? fc.oneof(arbGeneratedContract, arbGeneratedStatefulContract)
    : arbGeneratedContract;

  const contracts = fc.sample(arb, { numRuns: numPrograms, seed: options.seed });
  const compilerMap = dispatch();
  const results: IRDifferentialResult[] = [];
  let mismatchCount = 0;

  // Track which compilers have produced output at least once, so we can
  // separate "this compiler is not installed" from "this compiler rejected
  // *this* program". A compiler we've never seen produce output is assumed
  // uninstalled and silently skipped; one that has produced output before
  // but fails now is flagged as a rejection-divergence.
  const everProduced = new Set<CompilerName>();

  for (let i = 0; i < contracts.length; i++) {
    const contract = contracts[i]!;
    const sources: Partial<Record<CompilerName, string>> = {};
    const outputs: Partial<Record<CompilerName, string>> = {};
    const failed: CompilerName[] = [];

    if (verbose) console.log(`\n--- IR Fuzz program ${i + 1}/${contracts.length}: ${contract.name} ---`);

    for (const compiler of compilers) {
      const { source, ext } = renderForCompiler(compiler, contract, strategy);
      sources[compiler] = source;

      const tmpFile = join(tmpDir, `fuzz-${compiler}${ext}`);
      writeFileSync(tmpFile, source, 'utf-8');

      const raw = compilerMap[compiler].run(tmpFile, compareHex);
      if (raw === null) {
        if (verbose) console.log(`    ${compiler}: (no output)`);
        failed.push(compiler);
        continue;
      }
      everProduced.add(compiler);
      outputs[compiler] = normalizeOutput(raw, compareHex);
      if (verbose) console.log(`    ${compiler}: ${outputs[compiler]!.slice(0, 60)}${outputs[compiler]!.length > 60 ? '...' : ''}`);
    }

    const received = Object.entries(outputs) as Array<[CompilerName, string]>;
    let match = true;
    let mismatchDetails: string | undefined;

    if (received.length >= 2) {
      // Emit every pairwise divergence (not just the first) so a multi-compiler
      // split — e.g. Java vs TS/Go/Rust — is immediately legible in the log.
      const [refName, refOutput] = received[0]!;
      const mismatches: string[] = [];
      for (let j = 1; j < received.length; j++) {
        const [otherName, otherOutput] = received[j]!;
        if (refOutput !== otherOutput) {
          mismatches.push(`${refName} vs ${otherName}`);
        }
      }
      if (mismatches.length > 0) {
        match = false;
        mismatchDetails = `Output mismatch: ${mismatches.join(', ')}`;
      }
    }

    // Separately surface "one compiler rejected the input while the rest
    // accepted it". This catches Java-specific failures that would otherwise
    // be silently dropped by the null check above, and is the primary signal
    // the task description calls out ("when Java rejects a contract that
    // others accept (or vice versa), surface that too").
    if (failed.length > 0 && failed.length < compilers.length) {
      const rejected = failed.filter((c) => everProduced.has(c));
      if (rejected.length > 0) {
        const already = mismatchDetails ? mismatchDetails + '; ' : '';
        mismatchDetails = already + `rejected by ${rejected.join(', ')} but accepted by ${received.map(([n]) => n).join(', ')}`;
        match = false;
      }
    }

    const result: IRDifferentialResult = {
      contractName: contract.name,
      sources,
      outputs,
      match,
      mismatchDetails,
    };

    if (!match) {
      mismatchCount++;
      if (verbose) console.log(`  MISMATCH: ${mismatchDetails}`);
      saveFinding(findingsDir, result);
    } else if (verbose) {
      console.log(`  OK (${received.map(([n]) => n).join(', ')})`);
    }

    results.push(result);
  }

  console.log('');
  console.log(`IR differential fuzzing complete: ${contracts.length} programs, ${mismatchCount} mismatches`);

  return results;
}
