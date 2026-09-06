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
// exact op-TREE size (`if` bodies included, see countOpTree) for a fast (128f)
// and a small (192s) parameter set so a
// TS-side codegen regression fails here instead of only as a conformance hex
// mismatch. They match the Go peer goldens in
// compilers/go/codegen/crypto_codegen_test.go. Update only alongside a
// deliberate codegen change.
// ---------------------------------------------------------------------------

/**
 * Total number of StackOps in `ops`, INCLUDING the bodies of `if` ops.
 *
 * A flat `ops.length` cannot see inside a branch, so any emitter whose work
 * sits in an `if` body — the scalar ladders emit 257 / 385 conditional
 * additions, WOTS+ and SLH-DSA are almost entirely conditional — reports a
 * count that barely moves no matter what the branch contains. Adding +1.3 KB
 * of script inside the ladder's last step left the `p256Mul` / `p384Mul`
 * goldens byte-identical. Recursing is what makes the golden a gate.
 */
function countOpTree(ops: StackOp[]): number {
  let total = 0;
  for (const op of ops) {
    total++;
    if (op.op === 'if') {
      total += countOpTree(op.then);
      total += countOpTree(op.else ?? []);
    }
  }
  return total;
}

function countSlhdsaOps(paramKey: string): number {
  const ops: StackOp[] = [];
  emitVerifySLHDSA((op: StackOp) => ops.push(op), paramKey);
  return countOpTree(ops);
}

describe('SLH-DSA codegen — op-count goldens (T-006)', () => {
  const goldens: Array<[paramKey: string, expected: number]> = [
    // Counts reflect the SLH-DSA codegen miscompile fix (audit #2): emitSLHHmsg
    // dropped one reversing `swap` on the final multi-block MGF1 block (-1 op on
    // every set whose digest spans >1 SHA-256 block), and emitSLHFors now sizes
    // the FORS index window to ceil((bitOffset+a)/8) instead of capping at 2
    // bytes — so a=14 sets (192s/256s) emit a 3-byte window (an extra reverse
    // pair + the previously-skipped right-shift) on unlucky alignments. 128f
    // (a=6) sees only the Hmsg -1; 192s sees -1 + 48.
    //
    // #137 (FIPS-205 conformance) then added, per parameter set, exactly 6 + d:
    //   +6 once, in Hmsg — the MGF1 seed must be prefixed with R || PK.seed
    //     (FIPS 205 §11.2.1): 2 extra copyToTop (2 ops each) + 2 OP_CAT.
    //   +1 per hypertree layer (d layers) — wots_pkFromSig must restore the key
    //     pair address after setTypeAndClear(WOTS_PK) (FIPS 205 Alg. 8 lines
    //     8-11), turning a 1-op 4-zero-byte push into a 2-op push-depth + PICK.
    // 128f: d=22 -> 514147 + 28 = 514175.  192s: d=7 -> 256935 + 13 = 256948.
    ['SHA2_128f', 514175],
    ['SHA2_192s', 256948],
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
