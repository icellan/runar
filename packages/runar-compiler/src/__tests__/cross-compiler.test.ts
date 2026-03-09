import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync } from 'child_process';
import { writeFileSync, mkdtempSync, rmSync, readdirSync, readFileSync, existsSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { compile } from '../index.js';
import type { ANFProgram } from '../ir/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Check if Go is available
// ---------------------------------------------------------------------------

let hasGo = false;
try {
  execSync('go version', { stdio: 'pipe' });
  hasGo = true;
} catch {
  // Go not available
}

// ---------------------------------------------------------------------------
// Check if Rust (cargo) is available and the compiler is built
// ---------------------------------------------------------------------------

let hasRust = false;
let rustBinaryPath: string | null = null;

try {
  execSync('cargo --version', { stdio: 'pipe' });
  hasRust = true;
} catch {
  // Rust/cargo not available
}

if (hasRust) {
  const candidatePath = join(__dirname, '..', '..', '..', '..', 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust');
  if (existsSync(candidatePath)) {
    rustBinaryPath = candidatePath;
  } else {
    // Try building the release binary
    try {
      execSync('cargo build --release', {
        cwd: join(__dirname, '..', '..', '..', '..', 'compilers', 'rust'),
        timeout: 120000,
        stdio: 'pipe',
      });
      if (existsSync(candidatePath)) {
        rustBinaryPath = candidatePath;
      }
    } catch {
      // Build failed; Rust tests will be skipped
    }
  }
}

function tsCompileErrors(sourceName: string, diagnostics: { severity?: string; message?: string }[]): string {
  const errors = diagnostics
    .filter((d) => d.severity === 'error')
    .map((d) => d.message)
    .filter((m): m is string => typeof m === 'string' && m.length > 0);

  if (errors.length === 0) {
    return `Compilation of ${sourceName} failed with no error diagnostics.`;
  }

  return `Compilation of ${sourceName} failed:\n${errors.map((e) => `  ${e}`).join('\n')}`;
}

// Path to the Go compiler source
const GO_COMPILER_DIR = join(__dirname, '..', '..', '..', '..', 'compilers', 'go');

// Path to the Rust compiler source
const RUST_COMPILER_DIR = join(__dirname, '..', '..', '..', '..', 'compilers', 'rust');

// Path to the conformance tests directory
const CONFORMANCE_DIR = join(__dirname, '..', '..', '..', '..', 'conformance', 'tests');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Serialize an ANF program to JSON, handling bigint values.
 */
function anfToJson(anf: ANFProgram): string {
  return JSON.stringify(anf, (_key, value) => {
    if (typeof value === 'bigint') {
      // The Go IR parser expects plain numbers for small values
      if (value >= Number.MIN_SAFE_INTEGER && value <= Number.MAX_SAFE_INTEGER) {
        return Number(value);
      }
      return value.toString();
    }
    return value;
  }, 2);
}

/**
 * Run the Go compiler on an ANF IR JSON file, returning the hex output.
 * Returns null if the Go compiler fails.
 */
function runGoCompiler(irFilePath: string): string | null {
  try {
    const result = execSync(
      `go run . --ir "${irFilePath}" --hex`,
      {
        cwd: GO_COMPILER_DIR,
        timeout: 30000,
        stdio: ['pipe', 'pipe', 'pipe'],
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    return result.toString().trim();
  } catch {
    return null;
  }
}

/**
 * Run the Rust compiler on an ANF IR JSON file, returning the hex output.
 * Uses the pre-built release binary for speed. Returns null if the compiler fails.
 */
function runRustCompiler(irFilePath: string): string | null {
  if (!rustBinaryPath) return null;
  try {
    const result = execSync(
      `"${rustBinaryPath}" --ir "${irFilePath}" --hex`,
      {
        cwd: RUST_COMPILER_DIR,
        timeout: 30000,
        stdio: ['pipe', 'pipe', 'pipe'],
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    return result.toString().trim();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Contract sources (without imports, matching the e2e test convention)
// ---------------------------------------------------------------------------

/**
 * Contract sources WITHOUT import statements -- the parser recognizes
 * SmartContract, assert, PubKey, Sig etc. as built-in names from context.
 *
 * These match the convention used in the existing e2e.test.ts.
 */
const P2PKH_SOURCE = `
class P2PKH extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig: Sig) {
    assert(checkSig(sig, this.pk));
  }
}
`;

const HASHLOCK_SOURCE = `
class HashLock extends SmartContract {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) === this.hashValue);
  }
}
`;

const ESCROW_SOURCE = `
class Escrow extends SmartContract {
  readonly buyer: PubKey;
  readonly seller: PubKey;
  readonly arbiter: PubKey;

  constructor(buyer: PubKey, seller: PubKey, arbiter: PubKey) {
    super(buyer, seller, arbiter);
    this.buyer = buyer;
    this.seller = seller;
    this.arbiter = arbiter;
  }

  public release(sig: Sig) {
    assert(checkSig(sig, this.buyer));
  }

  public refund(sig: Sig) {
    assert(checkSig(sig, this.seller));
  }
}
`;

const CONTRACT_SOURCES: { name: string; source: string }[] = [
  { name: 'P2PKH', source: P2PKH_SOURCE },
  { name: 'HashLock', source: HASHLOCK_SOURCE },
  { name: 'Escrow', source: ESCROW_SOURCE },
];


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe.skipIf(!hasGo)('Cross-compiler: TS IR -> Go Script', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-cross-'));
  });

  afterAll(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  for (const { name, source } of CONTRACT_SOURCES) {
    it(`TS compiler produces ANF IR for ${name}`, () => {
      const result = compile(source);
      if (!result.success) {
        const errors = result.diagnostics.filter(d => d.severity === 'error');
        throw new Error(`Compilation of ${name} failed:\n` + errors.map(e => `  ${e.message}`).join('\n'));
      }
      expect(result.anf).not.toBeNull();
      expect(result.anf!.contractName).toBe(name);
      expect(result.anf!.methods.length).toBeGreaterThan(0);
    });

    it(`Go compiler accepts ${name} ANF IR and produces hex matching TS`, () => {
      const tsResult = compile(source);
      if (!tsResult.success) {
        throw new Error(tsCompileErrors(name, tsResult.diagnostics));
      }

      expect(tsResult.anf).not.toBeNull();
      expect(tsResult.scriptHex).toBeTruthy();
      const tsAnf = tsResult.anf!;

      const irJson = anfToJson(tsAnf);
      const irPath = join(tempDir, `${name}.anf.json`);
      writeFileSync(irPath, irJson);

      const hexOutput = runGoCompiler(irPath);

      // The Go compiler must produce output matching the TS reference byte-for-byte
      expect(hexOutput).not.toBeNull();
      expect(hexOutput!.length).toBeGreaterThan(0);
      const tsHex = tsResult.scriptHex as string;
      expect(hexOutput!.toLowerCase()).toBe(tsHex.toLowerCase());
    });
  }

  it('both TS and Go compilers accept the same P2PKH ANF IR and produce identical hex', () => {
    const result = compile(P2PKH_SOURCE);
    expect(result.success).toBe(true);
    expect(result.anf).not.toBeNull();

    // TS compiler produced ANF IR successfully
    const tsAnf = result.anf!;
    expect(tsAnf.contractName).toBe('P2PKH');

    // Write ANF IR for Go
    const irJson = anfToJson(tsAnf);
    const irPath = join(tempDir, 'p2pkh-both.anf.json');
    writeFileSync(irPath, irJson);

    const goHex = runGoCompiler(irPath);

    // Go must produce hex output matching the TS reference byte-for-byte
    expect(goHex).not.toBeNull();
    expect(goHex!.length).toBeGreaterThan(0);
    const tsHex = result.scriptHex as string;
    expect(goHex!.toLowerCase()).toBe(tsHex.toLowerCase());
  });
});

// ---------------------------------------------------------------------------
// Cross-compiler: TS IR -> Rust Script
// ---------------------------------------------------------------------------

describe.skipIf(!hasRust || !rustBinaryPath)('Cross-compiler: TS IR -> Rust Script', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-cross-rust-'));
  });

  afterAll(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  for (const { name, source } of CONTRACT_SOURCES) {
    it(`Rust compiler accepts ${name} ANF IR and produces hex matching TS`, () => {
      const tsResult = compile(source);
      if (!tsResult.success) {
        throw new Error(tsCompileErrors(name, tsResult.diagnostics));
      }

      expect(tsResult.anf).not.toBeNull();
      expect(tsResult.scriptHex).toBeTruthy();
      const tsAnf = tsResult.anf!;

      const irJson = anfToJson(tsAnf);
      const irPath = join(tempDir, `${name}.anf.json`);
      writeFileSync(irPath, irJson);

      const hexOutput = runRustCompiler(irPath);

      // The Rust compiler must produce output matching the TS reference byte-for-byte
      expect(hexOutput).not.toBeNull();
      expect(hexOutput!.length).toBeGreaterThan(0);
      const tsHex = tsResult.scriptHex as string;
      expect(hexOutput!.toLowerCase()).toBe(tsHex.toLowerCase());
    });
  }

  it('both TS and Rust compilers accept the same P2PKH ANF IR and produce identical hex', () => {
    const result = compile(P2PKH_SOURCE);
    expect(result.success).toBe(true);
    expect(result.anf).not.toBeNull();

    const tsAnf = result.anf!;
    expect(tsAnf.contractName).toBe('P2PKH');

    const irJson = anfToJson(tsAnf);
    const irPath = join(tempDir, 'p2pkh-both-rust.anf.json');
    writeFileSync(irPath, irJson);

    const rustHex = runRustCompiler(irPath);

    expect(rustHex).not.toBeNull();
    expect(rustHex!.length).toBeGreaterThan(0);
    const tsHex = result.scriptHex as string;
    expect(rustHex!.toLowerCase()).toBe(tsHex.toLowerCase());
  });
});

// ---------------------------------------------------------------------------
// Test compilation of all example contracts through TS + Go pipeline
// ---------------------------------------------------------------------------

function findExampleContracts(): { name: string; source: string }[] {
  const examplesDir = join(__dirname, '..', '..', '..', '..', 'examples', 'ts');
  const contracts: { name: string; source: string }[] = [];

  try {
    const dirs = readdirSync(examplesDir, { withFileTypes: true });
    for (const dir of dirs) {
      if (!dir.isDirectory()) continue;
      const dirPath = join(examplesDir, dir.name);
      const files = readdirSync(dirPath);
      for (const file of files) {
        if (file.endsWith('.runar.ts')) {
          const source = readFileSync(join(dirPath, file), 'utf-8');
          contracts.push({ name: file.replace('.runar.ts', ''), source });
        }
      }
    }
  } catch {
    // examples directory may not exist
  }

  return contracts;
}

describe.skipIf(!hasGo)('Cross-compiler: all examples TS IR -> Go', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-cross-examples-'));
  });

  afterAll(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  const examples = findExampleContracts();

  for (const example of examples) {
    it(`compiles ${example.name} through TS -> Go pipeline`, () => {
      // Compile through TS compiler
      const result = compile(example.source);

      if (!result.success) {
        throw new Error(tsCompileErrors(example.name, result.diagnostics));
      }

      expect(result.anf).not.toBeNull();
      expect(result.scriptHex).toBeTruthy();
      const exampleAnf = result.anf!;

      // Write ANF IR to temp file
      const irJson = anfToJson(exampleAnf);
      const irPath = join(tempDir, `${example.name}.anf.json`);
      writeFileSync(irPath, irJson);

      // Run Go compiler
      const goHex = runGoCompiler(irPath);

      expect(goHex).not.toBeNull();
      expect(goHex!.length).toBeGreaterThan(0);
      expect(goHex!.toLowerCase()).toBe(result.scriptHex!.toLowerCase());
    });
  }
});

// ---------------------------------------------------------------------------
// Conformance golden file tests: Go output must match expected-script.hex
// ---------------------------------------------------------------------------

function findConformanceTests(): { name: string; sourceFile: string; hexFile: string }[] {
  const tests: { name: string; sourceFile: string; hexFile: string }[] = [];

  try {
    const dirs = readdirSync(CONFORMANCE_DIR, { withFileTypes: true });
    for (const dir of dirs) {
      if (!dir.isDirectory()) continue;
      const dirPath = join(CONFORMANCE_DIR, dir.name);
      const hexFile = join(dirPath, 'expected-script.hex');
      if (!existsSync(hexFile)) continue;

      // Find the .runar.ts source file: check source.json first, then local files
      let sourceFile: string | undefined;
      const configFile = join(dirPath, 'source.json');
      if (existsSync(configFile)) {
        const config = JSON.parse(readFileSync(configFile, 'utf-8')) as {
          path?: string;
          sources?: Record<string, string>;
        };
        if (config.sources?.['.runar.ts']) {
          sourceFile = resolve(dirPath, config.sources['.runar.ts']);
        } else if (config.path) {
          sourceFile = resolve(dirPath, config.path);
        }
      }
      if (!sourceFile) {
        const files = readdirSync(dirPath);
        const runarFile = files.find(f => f.endsWith('.runar.ts'));
        if (runarFile) sourceFile = join(dirPath, runarFile);
      }
      if (!sourceFile) continue;

      tests.push({
        name: dir.name,
        sourceFile,
        hexFile,
      });
    }
  } catch {
    // conformance directory may not exist
  }

  return tests;
}

describe.skipIf(!hasGo)('Cross-compiler conformance: Go output vs golden hex', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-cross-conformance-'));
  });

  afterAll(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  const conformanceTests = findConformanceTests();

  for (const test of conformanceTests) {
    it(`${test.name}: Go hex output matches expected-script.hex`, () => {
      const source = readFileSync(test.sourceFile, 'utf-8');
      const expectedHex = readFileSync(test.hexFile, 'utf-8').trim();

      // Compile through TS compiler
      const result = compile(source);
      if (!result.success) {
        throw new Error(tsCompileErrors(test.name, result.diagnostics));
      }

      expect(result.anf).not.toBeNull();
      const conformanceAnf = result.anf!;

      // Write ANF IR to temp file
      const irJson = anfToJson(conformanceAnf);
      const irPath = join(tempDir, `${test.name}.anf.json`);
      writeFileSync(irPath, irJson);

      // Run Go compiler
      const goHex = runGoCompiler(irPath);

      // Go must produce output
      expect(goHex).not.toBeNull();
      expect(goHex!.length).toBeGreaterThan(0);

      // Byte-for-byte comparison against the golden hex file
      expect(goHex!.toLowerCase()).toBe(expectedHex.toLowerCase());
    });
  }
});

// ---------------------------------------------------------------------------
// Cross-compiler: all examples TS IR -> Rust
// ---------------------------------------------------------------------------

describe.skipIf(!hasRust || !rustBinaryPath)('Cross-compiler: all examples TS IR -> Rust', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-cross-examples-rust-'));
  });

  afterAll(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  const examples = findExampleContracts();

  for (const example of examples) {
    it(`compiles ${example.name} through TS -> Rust pipeline`, () => {
      const result = compile(example.source);

      if (!result.success) {
        throw new Error(tsCompileErrors(example.name, result.diagnostics));
      }

      expect(result.anf).not.toBeNull();
      expect(result.scriptHex).toBeTruthy();
      const exampleAnf = result.anf!;

      const irJson = anfToJson(exampleAnf);
      const irPath = join(tempDir, `${example.name}.anf.json`);
      writeFileSync(irPath, irJson);

      const rustHex = runRustCompiler(irPath);

      expect(rustHex).not.toBeNull();
      expect(rustHex!.length).toBeGreaterThan(0);
      expect(rustHex!.toLowerCase()).toBe(result.scriptHex!.toLowerCase());
    });
  }
});

// ---------------------------------------------------------------------------
// Conformance golden file tests: Rust output must match expected-script.hex
// ---------------------------------------------------------------------------

describe.skipIf(!hasRust || !rustBinaryPath)('Cross-compiler conformance: Rust output vs golden hex', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-cross-conformance-rust-'));
  });

  afterAll(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  const conformanceTests = findConformanceTests();

  for (const test of conformanceTests) {
    it(`${test.name}: Rust hex output matches expected-script.hex`, () => {
      const source = readFileSync(test.sourceFile, 'utf-8');
      const expectedHex = readFileSync(test.hexFile, 'utf-8').trim();

      const result = compile(source);
      if (!result.success) {
        throw new Error(tsCompileErrors(test.name, result.diagnostics));
      }

      expect(result.anf).not.toBeNull();
      const conformanceAnf = result.anf!;

      const irJson = anfToJson(conformanceAnf);
      const irPath = join(tempDir, `${test.name}.anf.json`);
      writeFileSync(irPath, irJson);

      const rustHex = runRustCompiler(irPath);

      expect(rustHex).not.toBeNull();
      expect(rustHex!.length).toBeGreaterThan(0);
      expect(rustHex!.toLowerCase()).toBe(expectedHex.toLowerCase());
    });
  }
});

// ---------------------------------------------------------------------------
// Cross-compiler: all three compilers produce identical hex
// ---------------------------------------------------------------------------

describe.skipIf(!hasGo || !hasRust || !rustBinaryPath)('Cross-compiler: all three compilers produce identical hex', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-cross-all-'));
  });

  afterAll(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  it('TS, Go, and Rust all produce identical hex for P2PKH', () => {
    const result = compile(P2PKH_SOURCE);
    expect(result.success).toBe(true);
    expect(result.anf).not.toBeNull();
    expect(result.scriptHex).toBeTruthy();

    const tsAnf = result.anf!;
    const tsHex = (result.scriptHex as string).toLowerCase();

    const irJson = anfToJson(tsAnf);
    const irPath = join(tempDir, 'p2pkh-all-three.anf.json');
    writeFileSync(irPath, irJson);

    // Run Go compiler
    const goHex = runGoCompiler(irPath);
    expect(goHex).not.toBeNull();
    expect(goHex!.length).toBeGreaterThan(0);

    // Run Rust compiler
    const rustHex = runRustCompiler(irPath);
    expect(rustHex).not.toBeNull();
    expect(rustHex!.length).toBeGreaterThan(0);

    // All three must match
    expect(goHex!.toLowerCase()).toBe(tsHex);
    expect(rustHex!.toLowerCase()).toBe(tsHex);
    expect(goHex!.toLowerCase()).toBe(rustHex!.toLowerCase());
  });
});
