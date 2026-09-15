/**
 * SCOPE (testing-gap remediation, plan design principle P8): this fuzzer is
 * HORIZONTAL — its oracle is TIER AGREEMENT, not correctness. Seven tiers that
 * share one bug agree with each other perfectly and this mode stays green;
 * both 2026-08 fund-safety bugs were of exactly that shape. It is necessary and
 * it is NOT fund-safety-complete on its own. The absolute oracles are
 * `--execute` / `--tri-modal` (stateless fragments) and `--spend-oracle`
 * (full deploy->call transaction context + an independent post-state pin).
 * See `conformance/fuzzer/README.md`.
 */

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
  /**
   * Tiers that MUST have compiled at least one program. A tier that produced
   * nothing for the whole run is a FAILURE, not a smaller run.
   *
   * Without this the harness degrades silently. `everProduced` exists to tell
   * "this compiler is not installed" from "this compiler rejected THIS
   * program", so a tier whose binary is present but which rejects or crashes
   * on ALL N generated programs never enters the set, is filtered out of every
   * divergence report, leaves `match` true, and the run prints
   * "N programs, 0 mismatches" and exits 0 — a seven-tier gate reporting
   * success having compared six. Same rule, same wording, as
   * `canonical-json-differential.ts`'s `requireTiers`.
   *
   * Defaults (in the CLI) to the requested `compilers`. Pass an empty array to
   * opt out for an exploratory local run.
   */
  requireTiers?: readonly CompilerName[];
}

/** What one program's run told us about tier PRESENCE (not about bytes). */
export interface IRProgramOutcome {
  /** Tiers that emitted output for this program. */
  received: readonly CompilerName[];
  /** Tiers that emitted nothing — rejected it, crashed, or are not installed. */
  failed: readonly CompilerName[];
}

export interface IRRunClassification {
  perProgram: { match: boolean; details?: string }[];
  /** Tiers that produced output for at least one program in the WHOLE run. */
  everProduced: CompilerName[];
  requiredTiers: CompilerName[];
  /** Required tiers that were never requested, or produced nothing all run. */
  missingRequiredTiers: CompilerName[];
  /** Programs every tier rejected — tiers agree, reported not failed. */
  allRejectedCount: number;
  /** Programs where a multi-tier run left a single survivor: no comparison. */
  noComparisonCount: number;
}

/**
 * Decide, ONCE and at the END of a run, what each program's tier presence
 * means. Doing this inside the program loop is what made `everProduced` a
 * prefix set: a tier that rejected program 0 and accepted program 1 was not
 * flagged on program 0, because at that instant nothing had yet proved the
 * tier was installed.
 */
export function classifyIRRun(args: {
  programs: readonly IRProgramOutcome[];
  compilers: readonly CompilerName[];
  requireTiers: readonly CompilerName[];
}): IRRunClassification {
  const { programs, compilers, requireTiers } = args;

  const everProducedSet = new Set<CompilerName>();
  for (const p of programs) for (const c of p.received) everProducedSet.add(c);

  // "Not compared" has two causes and both must fail: the tier was never
  // requested, or it was requested and never produced anything.
  const missingRequiredTiers = requireTiers.filter(
    (t) => !compilers.includes(t) || !everProducedSet.has(t),
  );

  let allRejectedCount = 0;
  let noComparisonCount = 0;
  const perProgram = programs.map((p) => {
    if (p.received.length === 0) {
      allRejectedCount++;
      return { match: true };
    }

    const reasons: string[] = [];
    const rejected = p.failed.filter((c) => everProducedSet.has(c));
    if (rejected.length > 0) {
      reasons.push(
        `rejected by ${rejected.join(', ')} but accepted by ${p.received.join(', ')}`,
      );
    }
    // A multi-tier run that left one survivor compared nothing.
    if (compilers.length >= 2 && p.received.length === 1) {
      noComparisonCount++;
      reasons.push(`only ${p.received[0]} compiled it — no cross-tier comparison was made`);
    }
    return reasons.length > 0 ? { match: false, details: reasons.join('; ') } : { match: true };
  });

  return {
    perProgram,
    everProduced: [...everProducedSet],
    requiredTiers: [...requireTiers],
    missingRequiredTiers: [...missingRequiredTiers],
    allRejectedCount,
    noComparisonCount,
  };
}

export interface IRDifferentialReport {
  results: IRDifferentialResult[];
  mismatchCount: number;
  allRejectedCount: number;
  noComparisonCount: number;
  everProduced: CompilerName[];
  requiredTiers: CompilerName[];
  /**
   * Required tiers that were never requested, or produced output on ZERO
   * programs. Non-empty means the run PROVED NOTHING about those tiers and the
   * caller must fail.
   */
  missingRequiredTiers: CompilerName[];
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
 * The Java compiler parses all 9 .runar.* formats (TS, Sol, Move, Go, Rust,
 * Python, Zig, Ruby, Java) just like the other 6 compilers. We could in
 * principle feed it the shared .runar.ts source under the 'ts' render
 * strategy, but routing Java through `renderJava` is simpler and more
 * reliable: the dedicated Java renderer produces .runar.java that exercises
 * the Java frontend's primary path and avoids any TS-parser quirks specific
 * to the Java tier. So Java always gets its own rendered source regardless
 * of the chosen strategy.
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
    // PIPELINE-DEPTH SYMMETRY (2026-08-06). The native tiers answer `--emit-ir`
    // straight out of the frontend: their ANF is produced and printed WITHOUT
    // ever running stack lowering or emit. `compile()` has no stop-at-ANF
    // option, so it always runs the full pipeline — and used to return null
    // here whenever a LATER pass failed. The result was a phantom finding:
    // any stack-lowering defect in a generated contract was reported as
    // "rejected by ts but accepted by go, rust, python, zig, ruby, java" even
    // though the other six had simply never reached the failing pass.
    // (The widened branch corpus hit this on its first run.) `compile()` does
    // return the ANF alongside the failure, so in ANF-compare mode we use it
    // and match the natives' depth exactly.
    //
    // The corollary is that ANF-compare mode gates FRONTEND parity only, in
    // every tier. Stack lowering and emit are gated by `--hex`, which drives
    // all seven tiers end to end.
    if (hex) {
      if (!result.success) return null;
      return result.artifact?.script ?? null;
    }
    if (!result.anf) return null;
    // JSON.stringify can't serialise BigInt values directly (the TS ANF pass
    // emits bigint literal values as native BigInt). Match what the other
    // compilers emit on stdout — bigints as bare JSON numbers — so the
    // cross-compiler diff stays sensible.
    return stringifyWithBigint(result.anf);
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

/**
 * Recursively sort object keys so two tiers that emit the same ANF in a
 * different key order compare equal.
 *
 * The previous implementation was `JSON.stringify(obj, Object.keys(obj).sort(), 2)`.
 * An ARRAY second argument to `JSON.stringify` is not a key ordering — it is a
 * property ALLOW-LIST, applied at EVERY nesting depth. Seeded with the ROOT's
 * keys (`contractName`, `methods`, `properties`), it deleted every key that did
 * not happen to share a name with a root key, at every level: each method
 * serialised as `{}` and each property as `{}`. ANF-compare mode was therefore
 * asserting little beyond "the tiers agree on the contract name and on how many
 * methods there are" — which is why it never saw the readonly-rendering split
 * that `--hex` surfaced immediately (see the READONLY PARITY note in
 * `packages/runar-testing/src/fuzzer/renderers.ts`).
 */
function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      // `sourceLoc` carries {file, line, column} back to the ORIGINATING source.
      // Under `--render native` every tier compiles a DIFFERENT file, so these
      // legitimately differ and say nothing about ANF parity. (Source-map
      // fidelity has its own tests; it is not what this differential gates.)
      if (k === 'sourceLoc') continue;
      out[k] = sortKeysDeep((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

function canonicalizeJson(s: string): string {
  try {
    return JSON.stringify(sortKeysDeep(JSON.parse(s)), null, 2);
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
): Promise<IRDifferentialReport> {
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
  const requireTiers = options.requireTiers ?? compilers;
  const results: IRDifferentialResult[] = [];
  // Tier PRESENCE per program. It is classified after the loop, against the
  // complete `everProduced` set — see `classifyIRRun`.
  const outcomes: IRProgramOutcome[] = [];

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
      outputs[compiler] = normalizeOutput(raw, compareHex);
      if (verbose) console.log(`    ${compiler}: ${outputs[compiler]!.slice(0, 60)}${outputs[compiler]!.length > 60 ? '...' : ''}`);
    }

    const received = Object.entries(outputs) as Array<[CompilerName, string]>;
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
        mismatchDetails = `Output mismatch: ${mismatches.join(', ')}`;
      }
    }

    outcomes.push({ received: received.map(([n]) => n), failed: [...failed] });
    results.push({
      contractName: contract.name,
      sources,
      outputs,
      // Filled in after the loop, once tier presence can be judged against the
      // whole run rather than a prefix of it.
      match: true,
      mismatchDetails,
    });
  }

  // Tier presence is judged ONCE, here, against the complete run. A tier that
  // produced nothing at all is a missing tier, not an absent toolchain we get
  // to ignore.
  const classification = classifyIRRun({ programs: outcomes, compilers, requireTiers });

  let mismatchCount = 0;
  for (let i = 0; i < results.length; i++) {
    const result = results[i]!;
    const verdict = classification.perProgram[i]!;
    const parts = [result.mismatchDetails, verdict.details].filter(Boolean);
    result.match = verdict.match && !result.mismatchDetails;
    result.mismatchDetails = parts.length > 0 ? parts.join('; ') : undefined;

    if (!result.match) {
      mismatchCount++;
      if (verbose) console.log(`  MISMATCH (${result.contractName}): ${result.mismatchDetails}`);
      saveFinding(findingsDir, result);
    }
  }

  console.log('');
  console.log(
    `IR differential fuzzing complete: ${contracts.length} programs, ${mismatchCount} mismatches` +
      (classification.allRejectedCount > 0
        ? `, ${classification.allRejectedCount} rejected by every tier`
        : ''),
  );
  console.log(
    `  Tiers that compiled at least one program: ${classification.everProduced.join(', ') || '(none)'}`,
  );
  if (classification.noComparisonCount > 0) {
    console.log(
      `  Programs with a single surviving tier (no comparison made): ${classification.noComparisonCount}`,
    );
  }

  return {
    results,
    mismatchCount,
    allRejectedCount: classification.allRejectedCount,
    noComparisonCount: classification.noComparisonCount,
    everProduced: classification.everProduced,
    requiredTiers: classification.requiredTiers,
    missingRequiredTiers: classification.missingRequiredTiers,
  };
}
