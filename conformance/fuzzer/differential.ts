import fc from 'fast-check';
import { writeFileSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
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

function compileTsSource(source: string, tmpDir: string, hex: boolean = false): string | null {
  const tmpFile = join(tmpDir, 'fuzz-test.runar.ts');
  writeFileSync(tmpFile, source, 'utf-8');
  const args = ['--import', 'tsx', resolve(ROOT, 'packages/runar-cli/src/bin.ts'), 'compile'];
  if (!hex) args.push('--ir');
  args.push('--disable-constant-folding', tmpFile);
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
 * The Java compiler (compilers/java/) only parses `.runar.java` source today.
 * The `.runar.ts` parser for Java lands in milestone 7. The legacy string-
 * based fuzzer in this file generates TypeScript source directly, so there
 * is no structured AST to re-render as Java; we simply skip Java here and
 * direct users to the IR-differential harness in `ir-differential.ts`, which
 * renders every compiler's native source from a shared generator.
 */
function compileJavaSource(_source: string, _tmpDir: string, _hex: boolean = false): string | null {
  const javaJar = findJavaBinary();
  if (javaJar && !_javaSkipWarned) {
    _javaSkipWarned = true;
    console.warn(
      'note: Java compiler is available but the legacy fuzzer generates .runar.ts source only; ' +
      'use `npx tsx conformance/fuzzer/index.ts --ir --render native` to include Java.',
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
 * be reachable, even though it cannot currently drive Java (see
 * `compileJavaSource` above).
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

function canonicalize(json: string): string {
  try {
    return JSON.stringify(JSON.parse(json), Object.keys(JSON.parse(json)).sort(), 2);
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
      (result as Record<string, unknown>)[key] = o.output;
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
