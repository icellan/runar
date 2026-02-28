import { readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { join, basename, resolve, dirname, extname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const GO_COMPILER_DIR = resolve(__dirname, '../../compilers/go');
const RUST_COMPILER_DIR = resolve(__dirname, '../../compilers/rust');

/** Escape a string for safe interpolation into a shell command (single-quote wrapping). */
function shellEscape(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
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
// Types
// ---------------------------------------------------------------------------

export interface ConformanceResult {
  testName: string;
  tsCompiler: CompilerOutput;
  goCompiler?: CompilerOutput;
  rustCompiler?: CompilerOutput;
  irMatch: boolean;
  scriptMatch: boolean;
  errors: string[];
}

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
function findGoBinary(): string | null {
  const candidates = [
    join(GO_COMPILER_DIR, 'tsop-go'),
    join(GO_COMPILER_DIR, 'tsop-go.exe'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  // Try PATH
  try {
    execSync('which tsop-go', { stdio: 'pipe' });
    return 'tsop-go';
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
function findRustBinary(): string | null {
  const candidates = [
    join(RUST_COMPILER_DIR, 'target/release/tsop-compiler-rust'),
    join(RUST_COMPILER_DIR, 'target/debug/tsop-compiler-rust'),
    join(RUST_COMPILER_DIR, 'tsop-compiler-rust'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  // Try PATH
  try {
    execSync('which tsop-compiler-rust', { stdio: 'pipe', env: cargoAwareEnv() });
    return 'tsop-compiler-rust';
  } catch {
    // Fallback: try `cargo run` from the compiler directory
    if (existsSync(join(RUST_COMPILER_DIR, 'Cargo.toml'))) {
      try {
        execSync('cargo --version', { stdio: 'pipe', env: cargoAwareEnv() });
        return `cargo run --release --manifest-path ${shellEscape(join(RUST_COMPILER_DIR, 'Cargo.toml'))} --`;
      } catch {
        // Cargo not available
      }
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Compiler invocations
// ---------------------------------------------------------------------------

/**
 * Run the TypeScript reference compiler on the given source.
 *
 * Invokes tsop-cli to emit an artifact JSON, then reads script/IR from the
 * generated artifact instead of parsing human-readable CLI stdout.
 */
function runTsCompiler(source: string, sourceFile: string): CompilerOutput {
  const start = performance.now();
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    const artifactDir = join(tmpDir, 'artifacts-ts');
    if (!existsSync(artifactDir)) mkdirSync(artifactDir, { recursive: true });

    execSync(
      `npx tsx ${shellEscape(resolve(__dirname, '../../packages/tsop-cli/src/bin.ts'))} compile ${shellEscape(tmpFile)} --ir -o ${shellEscape(artifactDir)}`,
      { timeout: 30_000, encoding: 'utf-8', cwd: resolve(__dirname, '../..') },
    );

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
function runGoCompiler(source: string, sourceFile: string): CompilerOutput | undefined {
  const binary = findGoBinary();
  if (!binary) return undefined;

  const start = performance.now();
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `go-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    // Get IR output
    const irOutput = execSync(
      `${binary} --source ${shellEscape(tmpFile)} --emit-ir`,
      { timeout: 30_000, encoding: 'utf-8', cwd: GO_COMPILER_DIR },
    ).trim();

    // Get script hex output
    const scriptHexOutput = execSync(
      `${binary} --source ${shellEscape(tmpFile)} --hex`,
      { timeout: 30_000, encoding: 'utf-8', cwd: GO_COMPILER_DIR },
    ).trim();

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
function runRustCompiler(source: string, sourceFile: string): CompilerOutput | undefined {
  const binary = findRustBinary();
  if (!binary) return undefined;

  const start = performance.now();
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `rust-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    // Get IR output (required for parity checks)
    const irOutput = execSync(
      `${binary} --source ${shellEscape(tmpFile)} --emit-ir`,
      {
        timeout: 30_000,
        encoding: 'utf-8',
        cwd: RUST_COMPILER_DIR,
        env: cargoAwareEnv(),
      },
    ).trim();

    // Get script hex output
    const scriptHexOutput = execSync(
      `${binary} --source ${shellEscape(tmpFile)} --hex`,
      {
        timeout: 30_000,
        encoding: 'utf-8',
        cwd: RUST_COMPILER_DIR,
        env: cargoAwareEnv(),
      },
    ).trim();

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

// ---------------------------------------------------------------------------
// Output parsing & canonicalization
// ---------------------------------------------------------------------------

/**
 * Parse the output of a Go/Rust compiler invocation. Both are expected to
 * output a JSON blob with { ir: ..., scriptHex: ..., scriptAsm: ... }.
 */
function parseCompilerOutput(output: string): {
  ir: string;
  scriptHex: string;
  scriptAsm: string;
} {
  try {
    const parsed = JSON.parse(output);
    return {
      ir: typeof parsed.ir === 'string' ? parsed.ir : JSON.stringify(parsed.ir),
      scriptHex: parsed.scriptHex ?? '',
      scriptAsm: parsed.scriptAsm ?? '',
    };
  } catch {
    // Fall back: treat the whole output as IR JSON (no script output)
    return { ir: output, scriptHex: '', scriptAsm: '' };
  }
}

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

/** Recursively sort object keys for deterministic serialization. */
function sortKeys(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
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
 */
function compareIR(...outputs: (CompilerOutput | undefined)[]): boolean {
  const successfulIRs = outputs
    .filter((o): o is CompilerOutput => o !== undefined && o.success && o.irJson !== '')
    .map((o) => o.irJson);

  if (successfulIRs.length < 2) return true; // Nothing to compare
  return successfulIRs.every((ir) => ir === successfulIRs[0]);
}

/**
 * Compare compiled Bitcoin Script hex across all available compilers.
 * Returns true if every pair of successful compilers produced the same hex.
 */
function compareScript(...outputs: (CompilerOutput | undefined)[]): boolean {
  const successfulHexes = outputs
    .filter((o): o is CompilerOutput => o !== undefined && o.success && o.scriptHex !== '')
    .map((o) => o.scriptHex.toLowerCase().replace(/\s/g, ''));

  if (successfulHexes.length < 2) return true; // Nothing to compare
  return successfulHexes.every((hex) => hex === successfulHexes[0]);
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

/**
 * Run the conformance test in a single test directory.
 *
 * The directory is expected to contain:
 * - `<name>.tsop.ts` -- the contract source
 * - `expected-ir.json` -- golden ANF IR (optional)
 * - `expected-script.hex` -- golden compiled script (optional)
 */
export async function runConformanceTest(testDir: string): Promise<ConformanceResult> {
  const testName = basename(testDir);
  const sourceFile = join(testDir, `${testName}.tsop.ts`);
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

  // Run all compilers
  const tsResult = runTsCompiler(source, sourceFile);
  const goResult = runGoCompiler(source, sourceFile);
  const rustResult = runRustCompiler(source, sourceFile);

  if (!tsResult.success) {
    errors.push(`TypeScript compiler failed: ${tsResult.error ?? 'unknown error'}`);
  }
  if (goResult && !goResult.success) {
    errors.push(`Go compiler failed: ${goResult.error ?? 'unknown error'}`);
  }
  if (rustResult && !rustResult.success) {
    errors.push(`Rust compiler failed: ${rustResult.error ?? 'unknown error'}`);
  }

  // Cross-compiler IR comparison
  const irMatch = compareIR(tsResult, goResult, rustResult);
  if (!irMatch) {
    errors.push('IR mismatch between compilers');
  }

  // Cross-compiler script comparison
  const scriptMatch = compareScript(tsResult, goResult, rustResult);
  if (!scriptMatch) {
    errors.push('Script hex mismatch between compilers');
  }

  // Golden file comparisons
  if (existsSync(expectedIrFile) && tsResult.success) {
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
  }

  if (existsSync(expectedScriptFile) && tsResult.success) {
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
  }

  return {
    testName,
    tsCompiler: tsResult,
    goCompiler: goResult,
    rustCompiler: rustResult,
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

  const results: ConformanceResult[] = [];
  for (const testDir of testDirs) {
    const result = await runConformanceTest(testDir);
    results.push(result);
  }

  return results;
}

/**
 * Update the golden files for a given test case from the TypeScript compiler
 * output. This is used to establish the initial baseline.
 */
export async function updateGoldenFiles(testDir: string): Promise<void> {
  const testName = basename(testDir);
  const sourceFile = join(testDir, `${testName}.tsop.ts`);
  const source = readFileSync(sourceFile, 'utf-8');

  const tsResult = runTsCompiler(source, sourceFile);
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
