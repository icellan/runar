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
import { writeFileSync, mkdirSync, existsSync, readFileSync } from 'node:fs';
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
} from '../../packages/runar-testing/src/fuzzer/index.js';
import type { GeneratedContract } from '../../packages/runar-testing/src/fuzzer/index.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CompilerName = 'ts' | 'go' | 'rust' | 'python' | 'zig' | 'ruby';
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
};

function renderForCompiler(
  compiler: CompilerName,
  contract: GeneratedContract,
  strategy: RenderStrategy,
): { source: string; ext: string } {
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
    return result.anf ? JSON.stringify(result.anf) : null;
  } catch {
    return null;
  }
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
  const compilers = options.compilers ?? ['ts', 'go', 'rust', 'python', 'zig', 'ruby'];
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

  for (let i = 0; i < contracts.length; i++) {
    const contract = contracts[i]!;
    const sources: Partial<Record<CompilerName, string>> = {};
    const outputs: Partial<Record<CompilerName, string>> = {};

    if (verbose) console.log(`\n--- IR Fuzz program ${i + 1}/${contracts.length}: ${contract.name} ---`);

    for (const compiler of compilers) {
      const { source, ext } = renderForCompiler(compiler, contract, strategy);
      sources[compiler] = source;

      const tmpFile = join(tmpDir, `fuzz-${compiler}${ext}`);
      writeFileSync(tmpFile, source, 'utf-8');

      const raw = compilerMap[compiler].run(tmpFile, compareHex);
      if (raw === null) {
        if (verbose) console.log(`    ${compiler}: (no output)`);
        continue;
      }
      outputs[compiler] = normalizeOutput(raw, compareHex);
      if (verbose) console.log(`    ${compiler}: ${outputs[compiler]!.slice(0, 60)}${outputs[compiler]!.length > 60 ? '...' : ''}`);
    }

    const received = Object.entries(outputs) as Array<[CompilerName, string]>;
    let match = true;
    let mismatchDetails: string | undefined;

    if (received.length >= 2) {
      const [refName, refOutput] = received[0]!;
      for (let j = 1; j < received.length; j++) {
        const [otherName, otherOutput] = received[j]!;
        if (refOutput !== otherOutput) {
          match = false;
          mismatchDetails = `Output mismatch between ${refName} and ${otherName}`;
          break;
        }
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
