import fc from 'fast-check';
import { writeFileSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CompilerName = 'ts' | 'go' | 'rust' | 'python' | 'zig' | 'ruby' | 'java';

export interface DifferentialResult {
  programSource: string;
  tsOutput?: string;
  goOutput?: string;
  rustOutput?: string;
  pythonOutput?: string;
  zigOutput?: string;
  rubyOutput?: string;
  javaOutput?: string;
  match: boolean;
  mismatchDetails?: string;
}

export interface FuzzerOptions {
  seed?: number;
  compilers?: CompilerName[];
  verbose?: boolean;
  /** Compare final hex script instead of IR. */
  compareHex?: boolean;
  /** Directory to save failing cases. */
  findingsDir?: string;
}

// ---------------------------------------------------------------------------
// Program generators
// ---------------------------------------------------------------------------

const runarIdentifier = fc.stringOf(
  fc.constantFrom('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'),
  { minLength: 1, maxLength: 4 },
).map((s) => `_${s}`);

const runarBigintLiteral = fc.oneof(
  fc.constant('0n'),
  fc.constant('1n'),
  fc.integer({ min: 0, max: 1000 }).map((n) => `${n}n`),
  fc.integer({ min: -100, max: -1 }).map((n) => `${n}n`),
);

const runarBoolLiteral = fc.oneof(fc.constant('true'), fc.constant('false'));

const bigintExpr: fc.Arbitrary<string> = fc.oneof(
  runarBigintLiteral,
  fc.tuple(runarBigintLiteral, fc.constantFrom('+', '-', '*'), runarBigintLiteral).map(
    ([a, op, b]) => `(${a} ${op} ${b})`,
  ),
);

const boolExpr: fc.Arbitrary<string> = fc.oneof(
  runarBoolLiteral,
  fc.tuple(runarBigintLiteral, fc.constantFrom('===', '!==', '<', '>', '<=', '>='), runarBigintLiteral).map(
    ([a, op, b]) => `(${a} ${op} ${b})`,
  ),
  fc.tuple(
    fc.oneof(runarBoolLiteral, fc.constant('true')),
    fc.constantFrom('&&', '||'),
    fc.oneof(runarBoolLiteral, fc.constant('false')),
  ).map(([a, op, b]) => `(${a} ${op} ${b})`),
);

interface PropDef {
  name: string;
  type: string;
  readonly: boolean;
}

const propDef: fc.Arbitrary<PropDef> = fc.record({
  name: runarIdentifier,
  type: fc.constant('bigint'),
  readonly: fc.boolean(),
});

function assembleContract(
  contractName: string,
  props: PropDef[],
  bodyStatements: string[],
  params: Array<{ name: string; type: string }>,
): string {
  const uniqueProps: PropDef[] = [];
  const seenNames = new Set<string>();
  for (const p of props) {
    if (!seenNames.has(p.name)) {
      seenNames.add(p.name);
      uniqueProps.push(p);
    }
  }

  const lines: string[] = [];
  lines.push(`import { SmartContract, assert } from 'runar-lang';`);
  lines.push('');
  lines.push(`class ${contractName} extends SmartContract {`);

  for (const p of uniqueProps) {
    const prefix = p.readonly ? 'readonly ' : '';
    lines.push(`  ${prefix}${p.name}: ${p.type};`);
  }
  lines.push('');

  const ctorParams = uniqueProps.map((p) => `${p.name}: ${p.type}`).join(', ');
  const superArgs = uniqueProps.map((p) => p.name).join(', ');
  lines.push(`  constructor(${ctorParams}) {`);
  lines.push(`    super(${superArgs});`);
  for (const p of uniqueProps) {
    lines.push(`    this.${p.name} = ${p.name};`);
  }
  lines.push('  }');
  lines.push('');

  const methodParams = params.map((p) => `${p.name}: ${p.type}`).join(', ');
  lines.push(`  public verify(${methodParams}): void {`);
  for (const stmt of bodyStatements) {
    lines.push(`    ${stmt}`);
  }
  lines.push('  }');
  lines.push('}');
  return lines.join('\n');
}

const runarContractArb: fc.Arbitrary<string> = fc
  .tuple(
    fc.array(propDef, { minLength: 1, maxLength: 3 }),
    fc.array(runarIdentifier, { minLength: 1, maxLength: 3 }),
    fc.array(
      fc.oneof(
        fc.tuple(runarIdentifier, bigintExpr).map(
          ([name, expr]) => `const ${name}_v: bigint = ${expr};`,
        ),
        fc.tuple(boolExpr, bigintExpr, bigintExpr).map(
          ([cond, thenExpr, elseExpr]) =>
            `let _ifr: bigint = ${cond} ? ${thenExpr} : ${elseExpr};`,
        ),
      ),
      { minLength: 0, maxLength: 3 },
    ),
    boolExpr,
  )
  .map(([props, paramNames, bodyStmts, assertExpr]) => {
    const uniqueParamNames = [...new Set(paramNames)];
    const params = uniqueParamNames.map((n) => ({ name: n, type: 'bigint' }));
    const statements = [...bodyStmts, `assert(${assertExpr});`];
    return assembleContract('FuzzContract', props, statements, params);
  });

// ---------------------------------------------------------------------------
// Compiler invocation (using execFileSync for safety)
// ---------------------------------------------------------------------------

const ROOT = resolve(__dirname, '../..');

function runCompilerProcess(
  cmd: string,
  args: string[],
  options: { cwd?: string; timeout?: number } = {},
): string | null {
  try {
    return execFileSync(cmd, args, {
      timeout: options.timeout ?? 15_000,
      encoding: 'utf-8',
      cwd: options.cwd ?? ROOT,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// In-process TS compile for IR mode (F-169)
// ---------------------------------------------------------------------------
//
// IR mode used to shell out to the CLI with `--ir`, but the TS CLI's `--ir`
// means "embed the IR in the artifact JSON FILE" and prints `Compiling: ...`
// / `Artifact written: ...` chatter to stdout — never the IR itself
// (packages/runar-cli/src/commands/compile.ts). Every other tier's
// `--emit-ir` has the opposite contract: stdout carries ONLY the IR (see
// compilers/go/main.go). So `ts`'s "output" was never comparable against the
// other six tiers in IR mode.
//
// `conformance/fuzzer/ir-differential.ts` already solved exactly this by
// compiling in-process via runar-compiler's `compile()`, which hands back
// the ANF object directly — there is no stdout contract to get wrong. This
// mirrors that fix (`loadTsCompile` / `tsCompileRun` there).
type RunarCompileFn = (
  source: string,
  options?: { fileName?: string; disableConstantFolding?: boolean },
) => { success: boolean; anf?: unknown };

let _cachedTsCompile: RunarCompileFn | null | undefined;

async function loadTsCompile(): Promise<RunarCompileFn | null> {
  if (_cachedTsCompile !== undefined) return _cachedTsCompile;
  try {
    const srcEntry = resolve(ROOT, 'packages/runar-compiler/src/index.ts');
    const mod = (await import(pathToFileURL(srcEntry).href)) as Record<string, unknown>;
    if (typeof mod.compile === 'function') {
      _cachedTsCompile = mod.compile as RunarCompileFn;
      return _cachedTsCompile;
    }
  } catch {
    // fall through
  }
  _cachedTsCompile = null;
  return _cachedTsCompile;
}

// Match Go/Rust/Python/Java's JCS bigint encoding (bare integer when safe,
// decimal string otherwise) so canonicalize()'s string comparison compares
// like for like against the native tiers' `--emit-ir` stdout.
function stringifyAnfWithBigint(value: unknown): string {
  return JSON.stringify(value, (_k, v) => {
    if (typeof v === 'bigint') {
      if (v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)) {
        return Number(v);
      }
      return v.toString();
    }
    return v;
  });
}

function compileTsSource(source: string, tmpDir: string, hex: boolean = false): string | null {
  if (!hex) {
    // IR mode: compile in-process (see note above) instead of spawning the
    // CLI. Requires loadTsCompile() to have been awaited by the caller
    // first; if the cache was never warmed, there is nothing to compile
    // with and this tier reports as unavailable, same as a missing binary.
    const compile = _cachedTsCompile;
    if (!compile) return null;
    try {
      const result = compile(source, {
        fileName: 'fuzz-test.runar.ts',
        disableConstantFolding: true,
      });
      // PIPELINE-DEPTH SYMMETRY (mirrors ir-differential.ts's tsCompileRun):
      // the native tiers' `--emit-ir` returns straight out of the frontend,
      // before stack-lowering/emit ever run, so a `result.success` gate here
      // would make `ts` the only tier gated on the back end -- a program
      // that lowers fine but fails emit would silently drop `ts` out of
      // `outputs` while the other tiers compare among themselves.
      if (!result.anf) return null;
      return stringifyAnfWithBigint(result.anf);
    } catch {
      return null;
    }
  }

  const tmpFile = join(tmpDir, 'fuzz-test.runar.ts');
  writeFileSync(tmpFile, source, 'utf-8');
  const args = [
    '--import', 'tsx',
    resolve(ROOT, 'packages/runar-cli/src/bin.ts'), 'compile',
    '--hex', '--disable-constant-folding', tmpFile,
  ];
  return runCompilerProcess('node', args);
}

function compileGoSource(source: string, tmpDir: string, hex: boolean = false): string | null {
  const goBinary = findGoBinary();
  if (!goBinary) return null;
  const tmpFile = join(tmpDir, 'fuzz-test-go.runar.ts');
  writeFileSync(tmpFile, source, 'utf-8');
  const flag = hex ? '--hex' : '--emit-ir';
  return runCompilerProcess(goBinary, ['--source', tmpFile, flag, '--disable-constant-folding']);
}

function compileRustSource(source: string, tmpDir: string, hex: boolean = false): string | null {
  const rustBinary = findRustBinary();
  if (!rustBinary) return null;
  const tmpFile = join(tmpDir, 'fuzz-test-rust.runar.ts');
  writeFileSync(tmpFile, source, 'utf-8');
  const flag = hex ? '--hex' : '--emit-ir';
  return runCompilerProcess(rustBinary, ['--source', tmpFile, flag, '--disable-constant-folding']);
}

function compilePythonSource(source: string, tmpDir: string, hex: boolean = false): string | null {
  const tmpFile = join(tmpDir, 'fuzz-test-python.runar.ts');
  writeFileSync(tmpFile, source, 'utf-8');
  const flag = hex ? '--hex' : '--emit-ir';
  return runCompilerProcess('python3', ['-m', 'runar_compiler', '--source', tmpFile, flag, '--disable-constant-folding'], {
    cwd: resolve(ROOT, 'compilers/python'),
  });
}

function compileZigSource(source: string, tmpDir: string, hex: boolean = false): string | null {
  const zigBinary = findZigBinary();
  if (!zigBinary) return null;
  const tmpFile = join(tmpDir, 'fuzz-test-zig.runar.ts');
  writeFileSync(tmpFile, source, 'utf-8');
  const flag = hex ? '--hex' : '--emit-ir';
  return runCompilerProcess(zigBinary, ['--source', tmpFile, flag, '--disable-constant-folding']);
}

function compileRubySource(source: string, tmpDir: string, hex: boolean = false): string | null {
  const rubyScript = findRubyBinary();
  if (!rubyScript) return null;
  const tmpFile = join(tmpDir, 'fuzz-test-ruby.runar.ts');
  writeFileSync(tmpFile, source, 'utf-8');
  const flag = hex ? '--hex' : '--emit-ir';
  return runCompilerProcess('ruby', [rubyScript, '--source', tmpFile, flag, '--disable-constant-folding']);
}

let _javaSkipWarned = false;
/**
 * The Java compiler parses all 9 .runar.* formats just like the other 6
 * compilers, but the legacy string-based fuzzer in this file only emits
 * .runar.ts source directly — there is no structured AST it could re-render
 * as Java. We therefore skip Java in this harness and direct users to the
 * IR-differential harness in `ir-differential.ts`, which has a structured
 * generator and renders every compiler's native source (.runar.java
 * included) from a shared `GeneratedContract`.
 */
function compileJavaSource(_source: string, _tmpDir: string, _hex: boolean = false): string | null {
  const javaJar = findJavaBinary();
  if (javaJar && !_javaSkipWarned) {
    _javaSkipWarned = true;
    console.warn(
      'note: Java compiler is available but the legacy fuzzer only renders .runar.ts ' +
      '(no structured AST -> Java renderer); use `npx tsx conformance/fuzzer/index.ts ' +
      '--ir --render native` to include Java.',
    );
  }
  return null;
}

// ---------------------------------------------------------------------------
// Binary discovery
// ---------------------------------------------------------------------------

function findGoBinary(): string | null {
  const candidates = [
    resolve(ROOT, 'compilers/go/runar-go'),
  ];
  for (const c of candidates) {
    try {
      execFileSync(c, ['--help'], { stdio: 'pipe', timeout: 5000 });
      return c;
    } catch { /* continue */ }
  }
  return null;
}

function findRustBinary(): string | null {
  const candidates = [
    resolve(ROOT, 'compilers/rust/target/release/runar-compiler-rust'),
  ];
  for (const c of candidates) {
    try {
      execFileSync(c, ['--help'], { stdio: 'pipe', timeout: 5000 });
      return c;
    } catch { /* continue */ }
  }
  return null;
}

function findZigBinary(): string | null {
  const candidates = [
    resolve(ROOT, 'compilers/zig/zig-out/bin/runar-zig'),
  ];
  for (const c of candidates) {
    try {
      execFileSync(c, ['--help'], { stdio: 'pipe', timeout: 5000 });
      return c;
    } catch { /* continue */ }
  }
  return null;
}

function findRubyBinary(): string | null {
  const rubyScript = resolve(ROOT, 'compilers/ruby/bin/runar-compiler-ruby');
  try {
    execFileSync('ruby', ['--version'], { stdio: 'pipe', timeout: 5000 });
    if (existsSync(rubyScript)) return rubyScript;
  } catch { /* no ruby */ }
  return null;
}

/**
 * Mirrors the Java-binary discovery in `conformance/runner/runner.ts` so the
 * legacy fuzzer can at least tell whether `java -jar <runar-java.jar>` would
 * be reachable, even though this harness has no Java AST renderer (see
 * `compileJavaSource` above) and therefore cannot drive the Java compiler.
 */
function findJavaBinary(): string | null {
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

// ---------------------------------------------------------------------------
// Compiler dispatch
// ---------------------------------------------------------------------------

type CompileFn = (source: string, tmpDir: string, hex?: boolean) => string | null;

const COMPILER_MAP: Record<CompilerName, CompileFn> = {
  ts: compileTsSource,
  go: compileGoSource,
  rust: compileRustSource,
  python: compilePythonSource,
  zig: compileZigSource,
  ruby: compileRubySource,
  java: compileJavaSource,
};

// Recursively sort object keys so two tiers that emit the same IR in a
// different key order compare equal.
//
// The previous implementation was
// `JSON.stringify(JSON.parse(json), Object.keys(JSON.parse(json)).sort(), 2)`.
// An ARRAY second argument to `JSON.stringify` is not a key ordering — it is
// a property ALLOW-LIST, applied at EVERY nesting depth. Seeded with the
// ROOT's keys (`contractName`, `methods`, `properties`), it deleted every
// key that did not happen to share a name with a root key, at every level:
// each method serialized as `{}` and each binding inside it as `{}` too.
// The comparison was therefore asserting little beyond "the tiers agree on
// the contract name and on how many top-level keys there are" — the exact
// same bug `conformance/fuzzer/ir-differential.ts`'s `sortKeysDeep` fixed
// for its own (structurally identical) `canonicalizeJson`; this ports that
// fix rather than inventing a second one.
function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      // `sourceLoc` carries {file, line, column} back to the file EACH
      // compiler was handed. Every compile*Source function above writes the
      // shared generated source to a different per-tier filename
      // (fuzz-test.runar.ts, fuzz-test-go.runar.ts, ...), so `file`
      // legitimately differs across tiers and says nothing about IR parity.
      if (k === 'sourceLoc') continue;
      out[k] = sortKeysDeep((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

function canonicalize(json: string): string {
  try {
    return JSON.stringify(sortKeysDeep(JSON.parse(json)), null, 2);
  } catch {
    return json;
  }
}

// ---------------------------------------------------------------------------
// Failing case persistence
// ---------------------------------------------------------------------------

function saveFinding(
  findingsDir: string,
  source: string,
  outputs: Array<{ name: string; output: string }>,
  mismatchDetails: string,
): void {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = join(findingsDir, timestamp);
  mkdirSync(dir, { recursive: true });

  writeFileSync(join(dir, 'source.runar.ts'), source, 'utf-8');

  for (const { name, output } of outputs) {
    writeFileSync(join(dir, `${name}-output.txt`), output, 'utf-8');
  }

  writeFileSync(
    join(dir, 'finding.json'),
    JSON.stringify({ timestamp, mismatchDetails }, null, 2),
    'utf-8',
  );
}

// ---------------------------------------------------------------------------
// Differential fuzzing harness
// ---------------------------------------------------------------------------

export async function runDifferentialFuzzing(
  numPrograms: number,
  options?: FuzzerOptions,
): Promise<DifferentialResult[]> {
  const compilers = options?.compilers ?? ['ts', 'go', 'rust', 'python', 'zig', 'ruby'];
  const verbose = options?.verbose ?? false;
  const compareHex = options?.compareHex ?? false;
  const findingsDir = options?.findingsDir ?? join(__dirname, '..', 'fuzz-findings');

  const tmpDir = join(__dirname, '..', '.tmp', 'fuzz');
  if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });

  // IR mode's `ts` tier compiles in-process (see compileTsSource); warm the
  // cached compile() handle once, up front, rather than per-program.
  if (!compareHex && compilers.includes('ts')) await loadTsCompile();

  const results: DifferentialResult[] = [];
  let mismatchCount = 0;

  const programs = fc.sample(runarContractArb, {
    numRuns: numPrograms,
    seed: options?.seed,
  });

  for (let i = 0; i < programs.length; i++) {
    const source = programs[i]!;

    if (verbose) {
      console.log(`\n--- Fuzz program ${i + 1}/${programs.length} ---`);
      console.log(source);
    }

    const outputs: Array<{ name: CompilerName; output: string }> = [];

    for (const compiler of compilers) {
      const compileFn = COMPILER_MAP[compiler];
      const output = compileFn(source, tmpDir, compareHex);
      if (output !== null) {
        const normalized = compareHex ? output.toLowerCase() : canonicalize(output);
        outputs.push({ name: compiler, output: normalized });
      }
    }

    let match = true;
    let mismatchDetails: string | undefined;

    if (outputs.length >= 2) {
      const reference = outputs[0]!;
      for (let j = 1; j < outputs.length; j++) {
        const other = outputs[j]!;
        if (reference.output !== other.output) {
          match = false;
          mismatchDetails = `Output mismatch between ${reference.name} and ${other.name}`;
          break;
        }
      }
    }

    if (!match) {
      mismatchCount++;
      if (verbose) {
        console.log(`  MISMATCH: ${mismatchDetails}`);
      }
      saveFinding(findingsDir, source, outputs, mismatchDetails!);
    } else if (verbose) {
      const compiledWith = outputs.map((o) => o.name).join(', ');
      console.log(`  OK (compiled with: ${compiledWith})`);
    }

    const result: DifferentialResult = {
      programSource: source,
      match,
      mismatchDetails,
    };

    for (const o of outputs) {
      const key = `${o.name}Output` as keyof DifferentialResult;
      (result as unknown as Record<string, unknown>)[key] = o.output;
    }

    results.push(result);
  }

  console.log('');
  console.log(`Differential fuzzing complete: ${programs.length} programs, ${mismatchCount} mismatches`);

  return results;
}

export async function runPropertyBasedDifferential(options?: FuzzerOptions): Promise<void> {
  const tmpDir = join(__dirname, '..', '.tmp', 'fuzz');
  if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });

  const compilers = options?.compilers ?? ['ts', 'go', 'rust', 'python', 'zig', 'ruby'];
  const compareHex = options?.compareHex ?? false;

  // IR mode's `ts` tier compiles in-process (see compileTsSource); warm the
  // cached compile() handle before fc.assert's (synchronous) predicate runs.
  if (!compareHex && compilers.includes('ts')) await loadTsCompile();

  fc.assert(
    fc.property(runarContractArb, (source: string) => {
      const outputs: Array<{ name: string; output: string }> = [];

      for (const compiler of compilers) {
        const compileFn = COMPILER_MAP[compiler];
        const output = compileFn(source, tmpDir, compareHex);
        if (output !== null) {
          const normalized = compareHex ? output.toLowerCase() : canonicalize(output);
          outputs.push({ name: compiler, output: normalized });
        }
      }

      if (outputs.length < 2) return true;

      const reference = outputs[0]!.output;
      for (let i = 1; i < outputs.length; i++) {
        if (outputs[i]!.output !== reference) {
          return false;
        }
      }
      return true;
    }),
    {
      numRuns: 100,
      seed: options?.seed,
      verbose: options?.verbose ? fc.VerbosityLevel.Verbose : fc.VerbosityLevel.None,
    },
  );
}

export { runarContractArb };
