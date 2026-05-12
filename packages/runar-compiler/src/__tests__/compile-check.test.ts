// ---------------------------------------------------------------------------
// Tests for compileCheck — TS frontend-only validation wrapper
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
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
