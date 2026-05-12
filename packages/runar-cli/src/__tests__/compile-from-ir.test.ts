// ---------------------------------------------------------------------------
// Tests for runar-cli compile --from-ir
// ---------------------------------------------------------------------------

import { describe, it, expect, beforeAll, afterAll, beforeEach, vi, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { pathToFileURL } from 'node:url';

const VALID_P2PKH = `
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;
  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`;

let workDir: string;

beforeAll(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-cli-from-ir-'));
});

afterAll(() => {
  if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
});

describe('compile --from-ir', () => {
  let compileCommand: typeof import('../commands/compile.js').compileCommand;

  beforeAll(async () => {
    // Warm the dynamic-import path used by compile.ts.
    const sourceEntry = path.resolve(process.cwd(), 'packages/runar-compiler/src/index.ts');
    if (fs.existsSync(sourceEntry)) {
      await import(pathToFileURL(sourceEntry).href);
    }
  }, 60_000);

  beforeEach(async () => {
    const mod = await import('../commands/compile.js');
    compileCommand = mod.compileCommand;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('produces hex byte-identical to source-mode --hex for the same contract', async () => {
    // Step 1: compile from source to grab the canonical hex via the
    // exported compile() function (this is what the CLI's source mode
    // already does, modulo IR-snapshot inclusion).
    const sourceEntry = path.resolve(process.cwd(), 'packages/runar-compiler/src/index.ts');
    const compilerMod = (await import(pathToFileURL(sourceEntry).href)) as {
      compile: (s: string, o?: { fileName?: string; disableConstantFolding?: boolean }) => {
        success: boolean;
        scriptHex?: string;
        anf?: unknown;
      };
    };
    const sourceResult = compilerMod.compile(VALID_P2PKH, {
      fileName: 'P2PKH.runar.ts',
      disableConstantFolding: true,
    });
    expect(sourceResult.success).toBe(true);
    expect(sourceResult.scriptHex).toBeTruthy();
    expect(sourceResult.anf).toBeTruthy();

    // Step 2: serialize the ANF to a JSON file the way TS does (bigint → "42n").
    const irPath = path.join(workDir, 'P2PKH.anf.json');
    fs.writeFileSync(
      irPath,
      JSON.stringify(sourceResult.anf, (_k, v) => {
        if (typeof v === 'bigint') return `${v}n`;
        return v;
      }),
    );

    // Step 3: invoke compileCommand with --from-ir, capturing stdout for --hex.
    const outDir = path.join(workDir, 'artifacts');
    fs.mkdirSync(outDir, { recursive: true });

    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await compileCommand([], {
      output: outDir,
      fromIr: irPath,
      hex: true,
      disableConstantFolding: true,
    });

    const calls = writeSpy.mock.calls.map(c => String(c[0]));
    const printed = calls.join('').trim();
    expect(printed).toBe(sourceResult.scriptHex);

    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
    writeSpy.mockRestore();
  }, 60_000);

  it('writes a minimal artifact JSON to the output dir when --hex is omitted', async () => {
    const sourceEntry = path.resolve(process.cwd(), 'packages/runar-compiler/src/index.ts');
    const compilerMod = (await import(pathToFileURL(sourceEntry).href)) as {
      compile: (s: string, o?: { fileName?: string; disableConstantFolding?: boolean }) => {
        success: boolean;
        scriptHex?: string;
        anf?: unknown;
      };
    };
    const sourceResult = compilerMod.compile(VALID_P2PKH, {
      fileName: 'P2PKH.runar.ts',
      disableConstantFolding: true,
    });

    const irPath = path.join(workDir, 'P2PKH-artifact.anf.json');
    fs.writeFileSync(
      irPath,
      JSON.stringify(sourceResult.anf, (_k, v) => {
        if (typeof v === 'bigint') return `${v}n`;
        return v;
      }),
    );

    const outDir = path.join(workDir, 'artifacts2');
    fs.mkdirSync(outDir, { recursive: true });

    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await compileCommand([], {
      output: outDir,
      fromIr: irPath,
      disableConstantFolding: true,
    });

    const baseName = path.basename(irPath, path.extname(irPath));
    const artifactPath = path.join(outDir, `${baseName}.json`);
    expect(fs.existsSync(artifactPath)).toBe(true);
    const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf-8')) as {
      contractName?: string;
      script?: string;
      asm?: string;
    };
    expect(artifact.contractName).toBe('P2PKH');
    expect(artifact.script).toBe(sourceResult.scriptHex);
    expect(typeof artifact.asm).toBe('string');
    expect(artifact.asm!.length).toBeGreaterThan(0);

    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
  }, 60_000);

  it('reports an error and sets exit code 1 when the IR file does not exist', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const originalExitCode = process.exitCode;

    await compileCommand([], {
      output: path.join(workDir, 'noop'),
      fromIr: '/tmp/this-file-does-not-exist-runar-from-ir-test.json',
    });

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => String(c[0]));
    expect(errCalls.some(m => m.includes('Error reading IR file'))).toBe(true);

    process.exitCode = originalExitCode;
    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
  });
});
