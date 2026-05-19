// ---------------------------------------------------------------------------
// Tests for CompilerResult<T> / DiagnosticList — uniform pass-recovery
// wrapper plus the per-pass `*R` adapters.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import {
  CompilerResult,
  parseR,
  validateR,
  typecheckR,
  lowerToANFR,
  lowerToStackR,
  emitR,
} from '../index.js';
import type { Diagnostic } from '../index.js';

const err = (msg: string): Diagnostic => ({ message: msg, severity: 'error' });
const warn = (msg: string): Diagnostic => ({ message: msg, severity: 'warning' });

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

// Type-check failure: calls a non-Rúnar function.
const INVALID_UNKNOWN_FUNCTION = `
import { SmartContract, assert } from 'runar-lang';

class Bad extends SmartContract {
  constructor() { super(); }
  public unlock() {
    assert(Math.floor(1.5) === 1);
  }
}
`;

describe('CompilerResult — core surface', () => {
  it('ok(v) is successful with empty errors and the given value', () => {
    const r = CompilerResult.ok(42);
    expect(r.ok).toBe(true);
    expect(r.errors).toEqual([]);
    expect(r.warnings).toEqual([]);
    expect(r.value).toBe(42);
  });

  it('ok(v, warnings) carries warnings through', () => {
    const w = warn('stylistic note');
    const r = CompilerResult.ok('hello', [w]);
    expect(r.ok).toBe(true);
    expect(r.warnings).toEqual([w]);
  });

  it('fail([err]) is unsuccessful with null value', () => {
    const e = err('boom');
    const r = CompilerResult.fail<number>([e]);
    expect(r.ok).toBe(false);
    expect(r.value).toBeNull();
    expect(r.errors).toEqual([e]);
  });

  it('map propagates value through the function when ok', () => {
    const r = CompilerResult.ok(3).map(n => n * 2);
    expect(r.ok).toBe(true);
    expect(r.value).toBe(6);
  });

  it('map does NOT invoke f when failed; errors are propagated unchanged', () => {
    let invoked = false;
    const e = err('cannot proceed');
    const r = CompilerResult.fail<number>([e]).map(n => {
      invoked = true;
      return n * 2;
    });
    expect(invoked).toBe(false);
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual([e]);
    expect(r.value).toBeNull();
  });

  it('map preserves warnings in both ok and failed cases', () => {
    const w = warn('heads up');
    const r1 = CompilerResult.ok(1, [w]).map(n => n + 1);
    expect(r1.warnings).toEqual([w]);
    const e = err('nope');
    const r2 = CompilerResult.fail<number>([e], [w]).map(n => n + 1);
    expect(r2.warnings).toEqual([w]);
  });

  it('flatMap chains through and merges diagnostics from both stages', () => {
    const w1 = warn('first warn');
    const w2 = warn('second warn');
    const e2 = err('second error');
    const r = CompilerResult.ok(10, [w1])
      .flatMap(_n => CompilerResult.fail<string>([e2], [w2]));
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual([e2]);
    expect(r.warnings).toEqual([w1, w2]);
    expect(r.value).toBeNull();
  });

  it('flatMap does NOT invoke f when this is failed', () => {
    let invoked = false;
    const e = err('upstream failed');
    const r = CompilerResult.fail<number>([e]).flatMap(n => {
      invoked = true;
      return CompilerResult.ok(n + 1);
    });
    expect(invoked).toBe(false);
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual([e]);
  });

  it('flatMap returns success when both stages are ok and merges warnings', () => {
    const w1 = warn('w1');
    const w2 = warn('w2');
    const r = CompilerResult.ok(5, [w1])
      .flatMap(n => CompilerResult.ok(n * 3, [w2]));
    expect(r.ok).toBe(true);
    expect(r.value).toBe(15);
    expect(r.warnings).toEqual([w1, w2]);
    expect(r.errors).toEqual([]);
  });

  it('unwrap returns the value when ok', () => {
    expect(CompilerResult.ok('yes').unwrap()).toBe('yes');
  });

  it('unwrap throws with the first error message when failed', () => {
    const r = CompilerResult.fail<number>([err('first'), err('second')]);
    expect(() => r.unwrap()).toThrowError(/compile failed: first/);
  });

  it('unwrap throws a generic message when errors is empty (defensive)', () => {
    // Hand-crafted edge case: value=null + errors=[] is "not ok" per
    // invariant but no specific error message exists.
    const r = new CompilerResult<number>(null, [], []);
    expect(r.ok).toBe(false);
    expect(() => r.unwrap()).toThrowError(/compile failed: unknown error/);
  });
});

describe('CompilerResult — pass adapters (*R wrappers)', () => {
  it('parseR + validateR + typecheckR + lowerToANFR + lowerToStackR + emitR chain end-to-end on a valid contract', () => {
    const result = parseR(VALID_P2PKH, 'P2PKH.runar.ts')
      .flatMap(validateR)
      .flatMap(typecheckR)
      .flatMap(lowerToANFR)
      .flatMap(lowerToStackR)
      .flatMap(emitR);

    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.value).not.toBeNull();
    expect(typeof result.value!.scriptHex).toBe('string');
    expect(result.value!.scriptHex.length).toBeGreaterThan(0);
  });

  it('typecheckR fails cleanly for a non-Rúnar function call (no throw)', () => {
    const result = parseR(INVALID_UNKNOWN_FUNCTION, 'Bad.runar.ts')
      .flatMap(validateR)
      .flatMap(typecheckR);

    expect(result.ok).toBe(false);
    expect(result.value).toBeNull();
    expect(result.errors.length).toBeGreaterThan(0);
    // The downstream stages must NOT run after a failed flatMap.
    const downstream = result.flatMap(lowerToANFR);
    expect(downstream.ok).toBe(false);
    expect(downstream.value).toBeNull();
  });

  it('parseR captures syntactic garbage as a failed result rather than throwing', () => {
    const result = parseR('this is not a TypeScript class at all {{{', 'broken.runar.ts');
    expect(result.ok).toBe(false);
    expect(result.value).toBeNull();
    expect(result.errors.length).toBeGreaterThan(0);
  });
});
