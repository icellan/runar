// ---------------------------------------------------------------------------
// Tests for runar-cli compile flags --parse-only (G-4) and --hex (G-5).
//
// Both flags previously had per-tier coverage in Go / Rust / Python / Zig /
// Ruby / Java CLIs but were missing on the TS CLI (--parse-only) or coupled
// to --from-ir (--hex). These tests assert that the TS CLI matches its
// peers: --parse-only works against source input, --hex prints script hex
// for source input.
// ---------------------------------------------------------------------------

import { describe, it, expect, beforeAll, afterAll, beforeEach, vi, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

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

// A source that parses fine but fails type-check (calls Math.floor, which
// the validator/typechecker rejects). Used to assert --parse-only *succeeds*
// past the type-check stage — i.e. that we really did stop at parse.
const PARSE_OK_TYPECHECK_BAD = `
import { SmartContract, assert } from 'runar-lang';

class TypecheckBad extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) {
    super(x);
    this.x = x;
  }
  public unlock(y: bigint) {
    assert(Math.floor(y) === this.x);
  }
}
`;

const SYNTAX_BAD = `class Broken extends SmartContract { = = = `;

let workDir: string;

beforeAll(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-cli-flags-'));
});

afterAll(() => {
  if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
});

describe('compile --parse-only (G-4)', () => {
  let compileCommand: typeof import('../commands/compile.js').compileCommand;

  beforeAll(async () => {
    // Warm the compiler import so the first real test doesn't pay the
    // cold-start cost against its own timeout.
    const sourceEntry = path.resolve(process.cwd(), 'packages/runar-compiler/src/index.ts');
    if (fs.existsSync(sourceEntry)) {
      const { pathToFileURL } = await import('node:url');
      await import(pathToFileURL(sourceEntry).href);
    } else {
      await import('runar-compiler');
    }
  }, 60_000);

  beforeEach(async () => {
    const mod = await import('../commands/compile.js');
    compileCommand = mod.compileCommand;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('prints "parser ok" and writes no artifact for a valid source', async () => {
    const srcPath = path.join(workDir, 'P2PKH-parseonly-ok.runar.ts');
    fs.writeFileSync(srcPath, VALID_P2PKH);
    const outDir = path.join(workDir, 'parseonly-ok-out');
    fs.mkdirSync(outDir, { recursive: true });

    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const originalExitCode = process.exitCode;

    await compileCommand([srcPath], {
      output: outDir,
      parseOnly: true,
    });

    const printed = writeSpy.mock.calls.map(c => String(c[0])).join('').trim();
    expect(printed).toBe('parser ok');
    // No artifact should have been written.
    const baseName = path.basename(srcPath, path.extname(srcPath));
    expect(fs.existsSync(path.join(outDir, `${baseName}.json`))).toBe(false);
    expect(process.exitCode === undefined || process.exitCode === 0).toBe(true);

    process.exitCode = originalExitCode;
    writeSpy.mockRestore();
    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
  }, 60_000);

  it('succeeds for a source whose type-check would fail (proves we stopped at parse)', async () => {
    const srcPath = path.join(workDir, 'TypecheckBad-parseonly.runar.ts');
    fs.writeFileSync(srcPath, PARSE_OK_TYPECHECK_BAD);
    const outDir = path.join(workDir, 'parseonly-tcbad-out');
    fs.mkdirSync(outDir, { recursive: true });

    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const originalExitCode = process.exitCode;

    await compileCommand([srcPath], {
      output: outDir,
      parseOnly: true,
    });

    const printed = writeSpy.mock.calls.map(c => String(c[0])).join('').trim();
    expect(printed).toBe('parser ok');
    expect(process.exitCode === undefined || process.exitCode === 0).toBe(true);

    process.exitCode = originalExitCode;
    writeSpy.mockRestore();
    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
  }, 60_000);

  it('exits non-zero and reports diagnostics for a syntactically invalid source', async () => {
    const srcPath = path.join(workDir, 'Broken-parseonly.runar.ts');
    fs.writeFileSync(srcPath, SYNTAX_BAD);
    const outDir = path.join(workDir, 'parseonly-bad-out');
    fs.mkdirSync(outDir, { recursive: true });

    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const originalExitCode = process.exitCode;

    await compileCommand([srcPath], {
      output: outDir,
      parseOnly: true,
    });

    expect(process.exitCode).toBe(1);
    const printed = writeSpy.mock.calls.map(c => String(c[0])).join('').trim();
    expect(printed).not.toContain('parser ok');

    process.exitCode = originalExitCode;
    writeSpy.mockRestore();
    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
  }, 60_000);

  it('errors when invoked with no source files', async () => {
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const originalExitCode = process.exitCode;

    await compileCommand([], {
      output: path.join(workDir, 'parseonly-empty-out'),
      parseOnly: true,
    });

    expect(process.exitCode).toBe(1);
    const errs = consoleErrSpy.mock.calls.map(c => String(c[0]));
    expect(errs.some(m => m.includes('--parse-only requires'))).toBe(true);

    process.exitCode = originalExitCode;
    consoleErrSpy.mockRestore();
  });
});

describe('compile --hex on source input (G-5)', () => {
  let compileCommand: typeof import('../commands/compile.js').compileCommand;

  beforeEach(async () => {
    const mod = await import('../commands/compile.js');
    compileCommand = mod.compileCommand;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('prints script hex to stdout and writes no artifact', async () => {
    // First grab the canonical hex via the library compile() so we can
    // assert byte-identity.
    const compilerMod = (await import('runar-compiler')) as unknown as {
      compile: (s: string, o?: { fileName?: string }) => { success: boolean; scriptHex?: string };
    };
    const sourceResult = compilerMod.compile(VALID_P2PKH, { fileName: 'P2PKH.runar.ts' });
    expect(sourceResult.success).toBe(true);
    expect(sourceResult.scriptHex).toBeTruthy();

    const srcPath = path.join(workDir, 'P2PKH-hex.runar.ts');
    fs.writeFileSync(srcPath, VALID_P2PKH);
    const outDir = path.join(workDir, 'hex-out');
    fs.mkdirSync(outDir, { recursive: true });

    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await compileCommand([srcPath], {
      output: outDir,
      hex: true,
    });

    const printed = writeSpy.mock.calls.map(c => String(c[0])).join('').trim();
    expect(printed).toBe(sourceResult.scriptHex);
    // No artifact should have been written.
    const baseName = path.basename(srcPath, path.extname(srcPath));
    expect(fs.existsSync(path.join(outDir, `${baseName}.json`))).toBe(false);

    writeSpy.mockRestore();
    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
  }, 60_000);
});
