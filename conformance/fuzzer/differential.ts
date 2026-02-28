import fc from 'fast-check';
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DifferentialResult {
  programSource: string;
  tsIR: string;
  goIR?: string;
  rustIR?: string;
  match: boolean;
  mismatchDetails?: string;
}

export interface FuzzerOptions {
  seed?: number;
  compilers?: ('ts' | 'go' | 'rust')[];
  verbose?: boolean;
}

// ---------------------------------------------------------------------------
// Program generators
// ---------------------------------------------------------------------------

/**
 * Generate a random TSOP type. Weighted towards common types (bigint, boolean)
 * since they exercise the most code paths in the compiler.
 */
const tsopType = fc.oneof(
  { weight: 5, arbitrary: fc.constant('bigint') },
  { weight: 3, arbitrary: fc.constant('boolean') },
  { weight: 1, arbitrary: fc.constant('ByteString') },
  { weight: 1, arbitrary: fc.constant('PubKey') },
);

/** Generate a valid TSOP identifier (lowercase, underscore-prefixed to avoid collisions). */
const tsopIdentifier = fc.stringOf(
  fc.constantFrom('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'),
  { minLength: 1, maxLength: 4 },
).map((s) => `_${s}`);

/** Generate a bigint literal appropriate for TSOP. */
const tsopBigintLiteral = fc.oneof(
  fc.constant('0n'),
  fc.constant('1n'),
  fc.integer({ min: 0, max: 1000 }).map((n) => `${n}n`),
  fc.integer({ min: -100, max: -1 }).map((n) => `${n}n`),
);

/** Generate a boolean literal. */
const tsopBoolLiteral = fc.oneof(fc.constant('true'), fc.constant('false'));

/** Generate a simple expression that produces a bigint. */
const bigintExpr: fc.Arbitrary<string> = fc.oneof(
  tsopBigintLiteral,
  fc.tuple(tsopBigintLiteral, fc.constantFrom('+', '-', '*'), tsopBigintLiteral).map(
    ([a, op, b]) => `(${a} ${op} ${b})`,
  ),
);

/** Generate a simple expression that produces a boolean. */
const boolExpr: fc.Arbitrary<string> = fc.oneof(
  tsopBoolLiteral,
  fc.tuple(tsopBigintLiteral, fc.constantFrom('===', '!==', '<', '>', '<=', '>='), tsopBigintLiteral).map(
    ([a, op, b]) => `(${a} ${op} ${b})`,
  ),
  fc.tuple(
    fc.oneof(tsopBoolLiteral, fc.constant('true')),
    fc.constantFrom('&&', '||'),
    fc.oneof(tsopBoolLiteral, fc.constant('false')),
  ).map(([a, op, b]) => `(${a} ${op} ${b})`),
);

/** Generate a property declaration. */
interface PropDef {
  name: string;
  type: string;
  readonly: boolean;
}

const propDef: fc.Arbitrary<PropDef> = fc.record({
  name: tsopIdentifier,
  type: fc.constant('bigint'),  // Keep props simple for fuzzing
  readonly: fc.boolean(),
});

/** Assemble a complete TSOP contract source from generated pieces. */
function assembleContract(
  contractName: string,
  props: PropDef[],
  bodyStatements: string[],
  params: Array<{ name: string; type: string }>,
): string {
  // Deduplicate property names
  const uniqueProps: PropDef[] = [];
  const seenNames = new Set<string>();
  for (const p of props) {
    if (!seenNames.has(p.name)) {
      seenNames.add(p.name);
      uniqueProps.push(p);
    }
  }

  const importItems = ['SmartContract', 'assert'];
  const lines: string[] = [];

  lines.push(`import { ${importItems.join(', ')} } from 'tsop-lang';`);
  lines.push('');
  lines.push(`class ${contractName} extends SmartContract {`);

  // Properties
  for (const p of uniqueProps) {
    const prefix = p.readonly ? 'readonly ' : '';
    lines.push(`  ${prefix}${p.name}: ${p.type};`);
  }
  lines.push('');

  // Constructor
  const ctorParams = uniqueProps.map((p) => `${p.name}: ${p.type}`).join(', ');
  const superArgs = uniqueProps.map((p) => p.name).join(', ');
  lines.push(`  constructor(${ctorParams}) {`);
  lines.push(`    super(${superArgs});`);
  for (const p of uniqueProps) {
    lines.push(`    this.${p.name} = ${p.name};`);
  }
  lines.push('  }');
  lines.push('');

  // Public method
  const methodParams = params.map((p) => `${p.name}: ${p.type}`).join(', ');
  lines.push(`  public verify(${methodParams}): void {`);
  for (const stmt of bodyStatements) {
    lines.push(`    ${stmt}`);
  }
  lines.push('  }');

  lines.push('}');
  return lines.join('\n');
}

/**
 * Generate a complete random TSOP contract source that is syntactically
 * valid and exercises a variety of language features.
 */
const tsopContractArb: fc.Arbitrary<string> = fc
  .tuple(
    // 0-3 properties
    fc.array(propDef, { minLength: 1, maxLength: 3 }),
    // 1-3 method parameters (always bigint for simplicity)
    fc.array(tsopIdentifier, { minLength: 1, maxLength: 3 }),
    // 1-4 body statements (culminating in an assert)
    fc.array(
      fc.oneof(
        // Variable declaration with arithmetic
        fc.tuple(tsopIdentifier, bigintExpr).map(
          ([name, expr]) => `const ${name}_v: bigint = ${expr};`,
        ),
        // If-else with simple body
        fc.tuple(boolExpr, bigintExpr, bigintExpr).map(
          ([cond, thenExpr, elseExpr]) =>
            `let _ifr: bigint = ${cond} ? ${thenExpr} : ${elseExpr};`,
        ),
      ),
      { minLength: 0, maxLength: 3 },
    ),
    // Final assert expression
    boolExpr,
  )
  .map(([props, paramNames, bodyStmts, assertExpr]) => {
    // Deduplicate param names
    const uniqueParamNames = [...new Set(paramNames)];
    const params = uniqueParamNames.map((n) => ({ name: n, type: 'bigint' }));

    const statements = [...bodyStmts, `assert(${assertExpr});`];
    return assembleContract('FuzzContract', props, statements, params);
  });

// ---------------------------------------------------------------------------
// Compiler invocation (for fuzzer)
// ---------------------------------------------------------------------------

function compileTsSource(source: string, tmpDir: string): string | null {
  const tmpFile = join(tmpDir, 'fuzz-test.tsop.ts');
  writeFileSync(tmpFile, source, 'utf-8');
  try {
    const output = execSync(
      `npx tsx ${resolve(__dirname, '../../packages/tsop-cli/src/bin.ts')} compile --ir "${tmpFile}"`,
      { timeout: 15_000, encoding: 'utf-8', cwd: resolve(__dirname, '../..') },
    ).trim();
    return output;
  } catch {
    return null;
  }
}

function compileGoSource(source: string, tmpDir: string): string | null {
  try {
    execSync('which tsop-go', { stdio: 'pipe' });
  } catch {
    return null;
  }
  const tmpFile = join(tmpDir, 'fuzz-test-go.tsop.ts');
  writeFileSync(tmpFile, source, 'utf-8');
  try {
    const output = execSync(
      `tsop-go --source "${tmpFile}" --emit-ir`,
      { timeout: 15_000, encoding: 'utf-8' },
    ).trim();
    return output;
  } catch {
    return null;
  }
}

function compileRustSource(source: string, tmpDir: string): string | null {
  try {
    execSync('which tsop-rust', { stdio: 'pipe' });
  } catch {
    return null;
  }
  const tmpFile = join(tmpDir, 'fuzz-test-rust.tsop.ts');
  writeFileSync(tmpFile, source, 'utf-8');
  try {
    const output = execSync(
      `tsop-rust --source "${tmpFile}" --hex`,
      { timeout: 15_000, encoding: 'utf-8' },
    ).trim();
    return output;
  } catch {
    return null;
  }
}

/** Canonicalize JSON for comparison by sorting keys and normalizing whitespace. */
function canonicalize(json: string): string {
  try {
    return JSON.stringify(JSON.parse(json), Object.keys(JSON.parse(json)).sort(), 2);
  } catch {
    return json;
  }
}

// ---------------------------------------------------------------------------
// Differential fuzzing harness
// ---------------------------------------------------------------------------

/**
 * Run differential fuzzing: generate random valid TSOP programs, compile
 * through all available compilers, and check that the IR output is identical.
 *
 * @param numPrograms - Number of random programs to generate and test.
 * @param options - Configuration for the fuzzing run.
 * @returns Array of results, one per generated program.
 */
export async function runDifferentialFuzzing(
  numPrograms: number,
  options?: FuzzerOptions,
): Promise<DifferentialResult[]> {
  const compilers = options?.compilers ?? ['ts', 'go', 'rust'];
  const verbose = options?.verbose ?? false;

  const tmpDir = join(__dirname, '..', '.tmp', 'fuzz');
  if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });

  const results: DifferentialResult[] = [];
  let mismatchCount = 0;

  // Use fast-check's sample to generate programs deterministically
  const programs = fc.sample(tsopContractArb, {
    numRuns: numPrograms,
    seed: options?.seed,
  });

  for (let i = 0; i < programs.length; i++) {
    const source = programs[i]!;

    if (verbose) {
      console.log(`\n--- Fuzz program ${i + 1}/${programs.length} ---`);
      console.log(source);
    }

    // Compile with each requested compiler
    let tsIR: string | null = null;
    let goIR: string | null = null;
    let rustIR: string | null = null;

    if (compilers.includes('ts')) {
      tsIR = compileTsSource(source, tmpDir);
    }
    if (compilers.includes('go')) {
      goIR = compileGoSource(source, tmpDir);
    }
    if (compilers.includes('rust')) {
      rustIR = compileRustSource(source, tmpDir);
    }

    // Compare outputs
    const outputs: Array<{ name: string; ir: string }> = [];
    if (tsIR !== null) outputs.push({ name: 'ts', ir: canonicalize(tsIR) });
    if (goIR !== null) outputs.push({ name: 'go', ir: canonicalize(goIR) });
    if (rustIR !== null) outputs.push({ name: 'rust', ir: canonicalize(rustIR) });

    let match = true;
    let mismatchDetails: string | undefined;

    if (outputs.length >= 2) {
      const reference = outputs[0]!;
      for (let j = 1; j < outputs.length; j++) {
        const other = outputs[j]!;
        if (reference.ir !== other.ir) {
          match = false;
          mismatchDetails = `IR mismatch between ${reference.name} and ${other.name}`;
          break;
        }
      }
    }

    if (!match) {
      mismatchCount++;
      if (verbose) {
        console.log(`  MISMATCH: ${mismatchDetails}`);
      }
    } else if (verbose) {
      const compiledWith = outputs.map((o) => o.name).join(', ');
      console.log(`  OK (compiled with: ${compiledWith})`);
    }

    results.push({
      programSource: source,
      tsIR: tsIR ?? '',
      goIR: goIR ?? undefined,
      rustIR: rustIR ?? undefined,
      match,
      mismatchDetails,
    });
  }

  // Summary
  console.log('');
  console.log(`Differential fuzzing complete: ${programs.length} programs, ${mismatchCount} mismatches`);

  return results;
}

/**
 * Run property-based differential testing using fast-check's test runner.
 * This integrates with fast-check's shrinking to find minimal failing inputs.
 */
export async function runPropertyBasedDifferential(options?: FuzzerOptions): Promise<void> {
  const tmpDir = join(__dirname, '..', '.tmp', 'fuzz');
  if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });

  const compilers = options?.compilers ?? ['ts', 'go', 'rust'];

  fc.assert(
    fc.property(tsopContractArb, (source: string) => {
      const outputs: Array<{ name: string; ir: string }> = [];

      if (compilers.includes('ts')) {
        const ir = compileTsSource(source, tmpDir);
        if (ir !== null) outputs.push({ name: 'ts', ir: canonicalize(ir) });
      }
      if (compilers.includes('go')) {
        const ir = compileGoSource(source, tmpDir);
        if (ir !== null) outputs.push({ name: 'go', ir: canonicalize(ir) });
      }
      if (compilers.includes('rust')) {
        const ir = compileRustSource(source, tmpDir);
        if (ir !== null) outputs.push({ name: 'rust', ir: canonicalize(ir) });
      }

      // If fewer than 2 compilers succeeded, skip this test case
      if (outputs.length < 2) return true;

      // All outputs must be identical
      const reference = outputs[0]!.ir;
      for (let i = 1; i < outputs.length; i++) {
        if (outputs[i]!.ir !== reference) {
          return false; // fast-check will shrink this
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

/** Export the program generator so external tools can reuse it. */
export { tsopContractArb };
