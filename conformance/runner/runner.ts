import { readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { join, basename, resolve, dirname, extname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const GO_COMPILER_DIR = resolve(__dirname, '../../compilers/go');
const RUST_COMPILER_DIR = resolve(__dirname, '../../compilers/rust');
const PYTHON_COMPILER_DIR = resolve(__dirname, '../../compilers/python');

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
  /** Source format used (e.g. '.runar.ts', '.runar.sol', '.runar.move', '.runar.py', '.runar.go', '.runar.rs', '.runar.rb') */
  format?: string;
  tsCompiler: CompilerOutput;
  goCompiler?: CompilerOutput;
  rustCompiler?: CompilerOutput;
  pythonCompiler?: CompilerOutput;
  irMatch: boolean;
  scriptMatch: boolean;
  errors: string[];
}

/**
 * Known input format extensions and which compilers support them.
 */
export const INPUT_FORMATS = [
  { ext: '.runar.ts',   compilers: ['ts', 'go', 'rust', 'python'] as const },
  { ext: '.runar.sol',  compilers: ['ts', 'go', 'rust', 'python'] as const },
  { ext: '.runar.move', compilers: ['ts', 'go', 'rust', 'python'] as const },
  { ext: '.runar.py',   compilers: ['ts', 'go', 'rust', 'python'] as const },
  { ext: '.runar.go',   compilers: ['go', 'python'] as const },
  { ext: '.runar.rs',   compilers: ['rust', 'python'] as const },
  { ext: '.runar.rb',   compilers: ['ts', 'go', 'rust', 'python'] as const },
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
function findGoBinary(): string | null {
  const candidates = [
    join(GO_COMPILER_DIR, 'runar-go'),
    join(GO_COMPILER_DIR, 'runar-go.exe'),
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
function findRustBinary(): string | null {
  const candidates = [
    join(RUST_COMPILER_DIR, 'target/release/runar-compiler-rust'),
    join(RUST_COMPILER_DIR, 'target/debug/runar-compiler-rust'),
    join(RUST_COMPILER_DIR, 'runar-compiler-rust'),
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
 * Invokes runar-cli to emit an artifact JSON, then reads script/IR from the
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
      `npx tsx ${shellEscape(resolve(__dirname, '../../packages/runar-cli/src/bin.ts'))} compile ${shellEscape(tmpFile)} --ir --disable-constant-folding -o ${shellEscape(artifactDir)}`,
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
      `${binary} --source ${shellEscape(tmpFile)} --emit-ir --disable-constant-folding`,
      { timeout: 30_000, encoding: 'utf-8', cwd: GO_COMPILER_DIR, maxBuffer: 10 * 1024 * 1024 },
    ).trim();

    // Get script hex output
    const scriptHexOutput = execSync(
      `${binary} --source ${shellEscape(tmpFile)} --hex --disable-constant-folding`,
      { timeout: 30_000, encoding: 'utf-8', cwd: GO_COMPILER_DIR, maxBuffer: 10 * 1024 * 1024 },
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
      `${binary} --source ${shellEscape(tmpFile)} --emit-ir --disable-constant-folding`,
      {
        timeout: 30_000,
        encoding: 'utf-8',
        cwd: RUST_COMPILER_DIR,
        env: cargoAwareEnv(),
        maxBuffer: 10 * 1024 * 1024,
      },
    ).trim();

    // Get script hex output
    const scriptHexOutput = execSync(
      `${binary} --source ${shellEscape(tmpFile)} --hex --disable-constant-folding`,
      {
        timeout: 30_000,
        encoding: 'utf-8',
        cwd: RUST_COMPILER_DIR,
        env: cargoAwareEnv(),
        maxBuffer: 10 * 1024 * 1024,
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

/**
 * Check whether the Python compiler is available (`python3 -m runar_compiler`).
 */
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
function runPythonCompiler(source: string, sourceFile: string): CompilerOutput | undefined {
  const binary = findPythonCompiler();
  if (!binary) return undefined;

  const start = performance.now();
  try {
    const tmpDir = join(__dirname, '..', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const tmpFile = join(tmpDir, `python-${basename(sourceFile)}`);
    writeFileSync(tmpFile, source, 'utf-8');

    // Get IR output
    const irOutput = execSync(
      `${binary} --source ${shellEscape(tmpFile)} --emit-ir --disable-constant-folding`,
      { timeout: 30_000, encoding: 'utf-8', cwd: PYTHON_COMPILER_DIR, maxBuffer: 10 * 1024 * 1024 },
    ).trim();

    // Get script hex output
    const scriptHexOutput = execSync(
      `${binary} --source ${shellEscape(tmpFile)} --hex --disable-constant-folding`,
      { timeout: 30_000, encoding: 'utf-8', cwd: PYTHON_COMPILER_DIR, maxBuffer: 10 * 1024 * 1024 },
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

  // Run all compilers
  const tsResult = runTsCompiler(source, sourceFile);
  const goResult = runGoCompiler(source, sourceFile);
  const rustResult = runRustCompiler(source, sourceFile);
  const pythonResult = runPythonCompiler(source, sourceFile);

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

  // Cross-compiler IR comparison
  const irMatch = compareIR(tsResult, goResult, rustResult, pythonResult);
  if (!irMatch) {
    errors.push('IR mismatch between compilers');
  }

  // Cross-compiler script comparison
  const scriptMatch = compareScript(tsResult, goResult, rustResult, pythonResult);
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
    if (pythonResult?.success && pythonResult.irJson && pythonResult.irJson !== expectedIr) {
      errors.push('Python compiler IR does not match golden file');
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
    if (pythonResult?.success && pythonResult.scriptHex) {
      const pythonScript = pythonResult.scriptHex.toLowerCase().replace(/\s/g, '');
      if (pythonScript !== expectedScript) {
        errors.push('Python compiler script does not match golden file');
      }
    }
  }

  return {
    testName,
    tsCompiler: tsResult,
    goCompiler: goResult,
    rustCompiler: rustResult,
    pythonCompiler: pythonResult,
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
  const sourceFile = resolveSourceFile(testDir, testName);
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

// ---------------------------------------------------------------------------
// Multi-format conformance testing
// ---------------------------------------------------------------------------

/**
 * Discover all input format source files in a test directory.
 *
 * Checks `source.json` for external references first, then scans for local
 * files. This allows tests to reference sources in `examples/` instead of
 * duplicating them.
 *
 * Returns an array of { ext, sourceFile } for each format found.
 */
function discoverFormats(testDir: string, testName: string): { ext: string; sourceFile: string }[] {
  const found: { ext: string; sourceFile: string }[] = [];

  // Check source.json for external references
  const configFile = join(testDir, 'source.json');
  if (existsSync(configFile)) {
    const config = JSON.parse(readFileSync(configFile, 'utf-8')) as {
      path?: string;
      sources?: Record<string, string>;
    };
    if (config.sources) {
      // Multi-format: { sources: { ".runar.ts": "path", ".runar.sol": "path", ... } }
      for (const [ext, relPath] of Object.entries(config.sources)) {
        const sourceFile = resolve(testDir, relPath);
        if (existsSync(sourceFile)) {
          found.push({ ext, sourceFile });
        }
      }
    } else if (config.path) {
      // Single-format: { path: "path/to/file.runar.ts" }
      const sourceFile = resolve(testDir, config.path);
      if (existsSync(sourceFile)) {
        const ext = INPUT_FORMATS.find(f => sourceFile.endsWith(f.ext))?.ext ?? '.runar.ts';
        found.push({ ext, sourceFile });
      }
    }
  }

  // Also check local files (skip formats already found via source.json)
  for (const { ext } of INPUT_FORMATS) {
    if (found.some(f => f.ext === ext)) continue;
    const sourceFile = join(testDir, `${testName}${ext}`);
    if (existsSync(sourceFile)) {
      found.push({ ext, sourceFile });
    }
  }

  return found;
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
  const testName = basename(testDir);
  const expectedIrFile = join(testDir, 'expected-ir.json');
  const expectedScriptFile = join(testDir, 'expected-script.hex');

  const source = readFileSync(format.sourceFile, 'utf-8');
  const errors: string[] = [];

  // Determine which compilers support this format
  const formatDef = INPUT_FORMATS.find(f => f.ext === format.ext);
  const supportedCompilers = formatDef?.compilers ?? EMPTY_COMPILERS;

  // Run compilers that support this format
  const tsResult = supportedCompilers.includes('ts')
    ? runTsCompiler(source, format.sourceFile)
    : { irJson: '', scriptHex: '', scriptAsm: '', success: false, error: 'Format not supported by TS compiler', durationMs: 0 } as CompilerOutput;

  const goResult = supportedCompilers.includes('go')
    ? runGoCompiler(source, format.sourceFile)
    : undefined;

  const rustResult = supportedCompilers.includes('rust')
    ? runRustCompiler(source, format.sourceFile)
    : undefined;

  const pythonResult = supportedCompilers.includes('python')
    ? runPythonCompiler(source, format.sourceFile)
    : undefined;

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

  // Cross-compiler comparison within this format
  const irMatch = compareIR(
    supportedCompilers.includes('ts') ? tsResult : undefined,
    goResult,
    rustResult,
    pythonResult,
  );
  if (!irMatch) {
    errors.push(`IR mismatch between compilers for ${format.ext}`);
  }

  const scriptMatch = compareScript(
    supportedCompilers.includes('ts') ? tsResult : undefined,
    goResult,
    rustResult,
    pythonResult,
  );
  if (!scriptMatch) {
    errors.push(`Script hex mismatch between compilers for ${format.ext}`);
  }

  // Golden file comparison (use any successful compiler output)
  if (existsSync(expectedIrFile)) {
    const expectedIr = canonicalizeJson(readFileSync(expectedIrFile, 'utf-8'));
    const allOutputs = [
      supportedCompilers.includes('ts') ? tsResult : undefined,
      goResult,
      rustResult,
      pythonResult,
    ].filter((o): o is CompilerOutput => o !== undefined && o.success && o.irJson !== '');

    for (const output of allOutputs) {
      if (output.irJson !== expectedIr) {
        errors.push(`IR does not match golden file for ${format.ext}`);
        break;
      }
    }
  }

  if (existsSync(expectedScriptFile)) {
    const expectedScript = readFileSync(expectedScriptFile, 'utf-8').trim().toLowerCase();
    const allOutputs = [
      supportedCompilers.includes('ts') ? tsResult : undefined,
      goResult,
      rustResult,
      pythonResult,
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

  const results: ConformanceResult[] = [];
  for (const format of formats) {
    results.push(await runConformanceTestForFormat(testDir, format));
  }

  return results;
}

/**
 * Discover and run multi-format conformance tests across all test directories.
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

  const allResults: ConformanceResult[] = [];
  for (const testDir of testDirs) {
    const results = await runMultiFormatConformanceTest(testDir);

    // If a specific format filter is requested, only include matching results
    if (options?.format) {
      allResults.push(...results.filter(r => r.format === options.format));
    } else {
      allResults.push(...results);
    }
  }

  return allResults;
}
