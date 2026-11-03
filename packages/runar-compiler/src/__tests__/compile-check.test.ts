// ---------------------------------------------------------------------------
// Tests for compileCheck — TS frontend-only validation wrapper
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileCheck, compileFromANF, loadANFFromJSON, compile } from '../index.js';

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

// Type-check failure: unknown function `Math.floor` is not a Rúnar built-in.
const INVALID_UNKNOWN_FUNCTION = `
import { SmartContract, assert } from 'runar-lang';

class Bad extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) {
    super(x);
    this.x = x;
  }
  public method() {
    assert(Math.floor(1) === 1);
  }
}
`;

// Validation failure: not extending SmartContract / StatefulSmartContract.
const INVALID_NO_BASE = `
class NotAContract {
  readonly x: bigint = 0n;
}
`;

describe('compileCheck', () => {
  it('returns void on a valid contract', () => {
    expect(() => compileCheck(VALID_P2PKH, 'P2PKH.runar.ts')).not.toThrow();
  });

  it('accepts the file name via positional argument', () => {
    expect(() => compileCheck(VALID_P2PKH, 'P2PKH.runar.ts')).not.toThrow();
  });

  it('accepts the file name via the options bag', () => {
    expect(() => compileCheck(VALID_P2PKH, undefined, { fileName: 'P2PKH.runar.ts' })).not.toThrow();
  });

  it('throws on type-check failure (unknown function call)', () => {
    expect(() => compileCheck(INVALID_UNKNOWN_FUNCTION, 'Bad.runar.ts')).toThrow(/compileCheck failed/);
  });

  it('throws on parse / validation failure (missing SmartContract base)', () => {
    expect(() => compileCheck(INVALID_NO_BASE, 'NotAContract.runar.ts')).toThrow(/compileCheck failed/);
  });

  it('error message identifies the file name', () => {
    let caught: Error | null = null;
    try {
      compileCheck(INVALID_UNKNOWN_FUNCTION, 'NamedFile.runar.ts');
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).not.toBeNull();
    expect(caught!.message).toContain('NamedFile.runar.ts');
  });
});

// A valid FixedArray contract: single-element and runtime-indexed writes,
// mirrors BASIC_ARRAY in 03b-expand-fixed-arrays.test.ts (kept inline here
// per sibling-file convention — expand-fixed-arrays fixtures aren't exported).
const VALID_FIXED_ARRAY = `
class Boardy extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public setZero(v: bigint) {
    this.board[0] = v;
    assert(true);
  }
}
`;

// A FixedArray contract whose initializer length (2) doesn't match the
// declared array length (3) — rejected by pass 3b (expandFixedArrays), not
// by typecheck, so it only exercises the post-typecheck expansion diagnostics.
const INVALID_FIXED_ARRAY_LENGTH = `
class BadInit extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n];

  constructor() {
    super();
  }

  public m() {
    assert(true);
  }
}
`;

describe('compileCheck acceptance matches compile()', () => {
  // This corpus exercises every stage compileCheck mirrors: a plain valid
  // contract, a valid FixedArray contract (exercises pass 3b success), a
  // FixedArray contract that fails pass 3b (expandFixedArrays) specifically,
  // and a contract that fails pass 3 (typecheck). For each, compileCheck
  // must throw iff compile() reports failure — proving compileCheck is a
  // faithful preview of compile(), not that either one is "correct".
  const corpus: Array<{ name: string; source: string; fileName: string; expected: 'accept' | 'reject' }> = [
    { name: 'valid contract (no FixedArray)', source: VALID_P2PKH, fileName: 'P2PKH.runar.ts', expected: 'accept' },
    { name: 'valid FixedArray contract', source: VALID_FIXED_ARRAY, fileName: 'Boardy.runar.ts', expected: 'accept' },
    { name: 'FixedArray initializer length mismatch (pass 3b failure)', source: INVALID_FIXED_ARRAY_LENGTH, fileName: 'BadInit.runar.ts', expected: 'reject' },
    { name: 'typecheck failure (unknown function, pass 3 failure)', source: INVALID_UNKNOWN_FUNCTION, fileName: 'Bad.runar.ts', expected: 'reject' },
  ];

  for (const { name, source, fileName, expected } of corpus) {
    it(`compile() and compileCheck() agree: ${name}`, () => {
      const compileResult = compile(source, { fileName });
      expect(compileResult.success).toBe(expected === 'accept');

      let compileCheckThrew = false;
      try {
        compileCheck(source, fileName);
      } catch {
        compileCheckThrew = true;
      }
      expect(compileCheckThrew).toBe(!compileResult.success);
    });
  }
});

describe('compileCheck JSDoc matches its real implementation', () => {
  // compileCheck runs the same front end as compile(): parse, validate, one
  // typecheck pass, then expandFixedArrays (which has its own diagnostics).
  // Neither compileCheck nor compile() typechecks the expanded contract a
  // second time. This test reads the JSDoc directly above `export function
  // compileCheck` out of the source file and checks it doesn't promise a
  // typecheck pass running again after expandFixedArrays.
  it('does not claim a second typecheck pass after FixedArray expansion', () => {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const indexSource = readFileSync(join(__dirname, '../index.ts'), 'utf8');
    const match = indexSource.match(/\/\*\*([\s\S]*?)\*\/\s*\nexport function compileCheck/);
    expect(match).not.toBeNull();
    const doc = match![1];

    // Positive anchor: the doc must still describe the real one-typecheck
    // pipeline, so this test can't pass vacuously if the pipeline line is
    // ever deleted outright.
    expect(doc).toMatch(/parse\s*→\s*validate\s*→\s*typecheck\s*→\s*expandFixedArrays/);

    // Negative: no "→ typecheck" shortly after "expandFixedArrays" — that
    // phrasing is what claimed a second typecheck pass at HEAD.
    expect(doc).not.toMatch(/expandFixedArrays[\s\S]{0,40}?→\s*typecheck/i);
  });
});

describe('compileFromANF + loadANFFromJSON (--from-ir backing functions)', () => {
  it('round-trips: source → ANF → JSON → ANF → hex matches source-mode hex', () => {
    const fromSource = compile(VALID_P2PKH, {
      fileName: 'P2PKH.runar.ts',
      disableConstantFolding: true,
    });
    expect(fromSource.success).toBe(true);
    expect(fromSource.scriptHex).toBeDefined();
    expect(fromSource.anf).not.toBeNull();

    const json = JSON.stringify(fromSource.anf, (_k, v) => {
      if (typeof v === 'bigint') return `${v}n`;
      return v;
    });
    const reloaded = loadANFFromJSON(json);
    const fromIr = compileFromANF(reloaded, { disableConstantFolding: true });
    expect(fromIr.scriptHex).toBe(fromSource.scriptHex);
    expect(fromIr.scriptAsm).toBe(fromSource.scriptAsm);
  });

  it('loadANFFromJSON rejects malformed top-level shapes', () => {
    expect(() => loadANFFromJSON('null')).toThrow();
    expect(() => loadANFFromJSON('"a string"')).toThrow();
    expect(() => loadANFFromJSON('{}')).toThrow(/contractName/);
    expect(() => loadANFFromJSON('{"contractName":"X"}')).toThrow(/properties/);
    expect(() => loadANFFromJSON('{"contractName":"X","properties":[]}')).toThrow(/methods/);
  });

  it('loadANFFromJSON parses bigint-tagged strings ("42n") back to BigInt', () => {
    const minimal = '{"contractName":"X","properties":[],"methods":[],"v":"42n"}';
    const parsed = loadANFFromJSON(minimal) as unknown as { v: unknown };
    expect(typeof parsed.v).toBe('bigint');
    expect(parsed.v).toBe(42n);
  });
});
