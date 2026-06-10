import { describe, it, expect } from 'vitest';
import { emitVerifySLHDSA, SLH_PARAMS } from '../passes/slh-dsa-codegen.js';
import type { StackOp } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Op-count goldens for the SLH-DSA (SPHINCS+, FIPS 205) verifier emitter
// (T-006).
//
// The post-quantum-slhdsa{,-128f,-192f,-192s,-256f,-256s} conformance
// fixtures exercise this end-to-end across all 7 tiers, but the TS tier had
// no localized unit test pinning the emit output. These goldens lock the
// exact op count for a fast (128f) and a small (192s) parameter set so a
// TS-side codegen regression fails here instead of only as a conformance hex
// mismatch. They match the Go peer goldens in
// compilers/go/codegen/crypto_codegen_test.go. Update only alongside a
// deliberate codegen change.
// ---------------------------------------------------------------------------

function countSlhdsaOps(paramKey: string): number {
  const ops: StackOp[] = [];
  emitVerifySLHDSA((op: StackOp) => ops.push(op), paramKey);
  return ops.length;
}

describe('SLH-DSA codegen — op-count goldens (T-006)', () => {
  const goldens: Array<[paramKey: string, expected: number]> = [
    // +5 ops vs pre-BUG-011 baseline: the new OP_SIZE / push / OP_EQUALVERIFY
    // length guard adds 3 ops, and the rearranged tracker ordering (sig brought
    // to top first now) adds one swap on the new toTop("sig") and one swap on
    // the following toTop("pubkey") that the old code emitted as a no-op.
    ['SHA2_128f', 85766],
    ['SHA2_192s', 41904],
  ];

  for (const [paramKey, expected] of goldens) {
    it(`emitVerifySLHDSA(${paramKey}) op count is ${expected}`, () => {
      expect(countSlhdsaOps(paramKey)).toBe(expected);
    });
  }

  it('exposes all six FIPS 205 SHA-2 parameter sets', () => {
    expect(Object.keys(SLH_PARAMS).sort()).toEqual([
      'SHA2_128f',
      'SHA2_128s',
      'SHA2_192f',
      'SHA2_192s',
      'SHA2_256f',
      'SHA2_256s',
    ]);
  });

  it('rejects an unknown parameter set', () => {
    expect(() => countSlhdsaOps('SHA2_999x')).toThrow();
  });
});
