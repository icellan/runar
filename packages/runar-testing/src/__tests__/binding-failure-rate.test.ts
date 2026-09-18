/**
 * Failure-rate characterisation of the two Any-S OP_PUSH_TX binding
 * constructions, as a regression guard for the assumptions documented on the
 * `@bindingVariant` directive (and used in the accompanying academic write-up).
 *
 * For a spend, z = hash256(preimage) is a ~uniform 256-bit digest and the
 * construction derives an ECDSA signature (r = Gx, s = f_variant(z)) checked on
 * chain against a fixed key. A GENUINE spend is rejected exactly when that
 * derived signature is not a valid, in-range, strict-DER ECDSA signature:
 *
 * Both variants share the C=1 key (s ≡ z+1); they differ only in the low-S fixup:
 *   - lowS: s = lowS((z + 1) mod n)  → in [0, n/2]; fails only at the single
 *           degenerate z ≡ -1 (mod n), i.e. z = n-1, where s = 0.  P(fail) = 2^-256.
 *   - all : s = z + 1  (NO mod-n reduction, NO low-S)    → fails iff s ≥ n, i.e.
 *           z ≥ n-1.   P(fail) = (2^256 - n + 1)/2^256 ≈ 2^-128.
 *
 * The model below is the same one validated bit-for-bit against the BSV Script
 * interpreter in the standalone simulation (scratchpad/sim); this test re-runs
 * the cheap legs (exact region arithmetic, boundary enumeration, pubkey
 * derivation, and a small interpreter cross-check) so the numbers can't silently
 * drift. The full Monte-Carlo leg lives in the simulation script.
 */

import { describe, it, expect } from 'vitest';
import {
  Curve, BigNumber, LockingScript, UnlockingScript, Spend, TransactionSignature, Hash,
} from '@bsv/sdk';
import { CHECK_PREIMAGE_BINDING_HEX, CHECK_PREIMAGE_BINDING_ALL_HEX } from 'runar-compiler';

const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const TWO256 = 1n << 256n;
const HALF_N = n >> 1n;
const C = { lowS: 1n, all: 1n } as const; // unified on the C=1 key 038ff83d…
type Variant = keyof typeof C;

// --- derived pubkeys P = (C·Gx^{-1})·G -------------------------------------
const curve = new Curve();
const bn = (x: bigint) => new BigNumber(x.toString(16), 16);
function pubkeyHexFor(variant: Variant): string {
  const nB = bn(n);
  const d = bn(C[variant]).mul(bn(Gx).invm(nB)).umod(nB);
  return Buffer.from(curve.g.mul(d).encode(true) as number[]).toString('hex');
}

// --- faithful model of the on-chain s-derivation ---------------------------
function deriveS(z: bigint, variant: Variant): bigint {
  if (variant === 'lowS') {
    let s = (z + C.lowS) % n;
    if (s > HALF_N) s = n - s;
    return s;
  }
  return z + C.all; // 'all': no mod, no low-S
}
function accepts(z: bigint, variant: Variant): boolean {
  const s = deriveS(z, variant);
  return s >= 1n && s < n; // in-range ⇒ s ≡ z+C exactly ⇒ verifies (see simulation)
}

// --- small interpreter cross-check -----------------------------------------
const CTX = {
  sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 100000,
  transactionVersion: 2, otherInputs: [] as never[], outputs: [] as never[],
  inputIndex: 0, inputSequence: 0xffffffff, lockTime: 0,
};
const SCOPE = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;
const blobHex: Record<Variant, string> = { lowS: CHECK_PREIMAGE_BINDING_HEX, all: CHECK_PREIMAGE_BINDING_ALL_HEX };

function pushData(bytes: Uint8Array): string {
  const hex = Buffer.from(bytes).toString('hex');
  const l = bytes.length;
  if (l < 0x4c) return l.toString(16).padStart(2, '0') + hex;
  if (l <= 0xff) return '4c' + l.toString(16).padStart(2, '0') + hex;
  const lo = (l & 0xff).toString(16).padStart(2, '0');
  const hi = ((l >> 8) & 0xff).toString(16).padStart(2, '0');
  return '4d' + lo + hi + hex;
}
function interp(variant: Variant, ctx: typeof CTX): { ok: boolean; z: bigint } {
  const lock = LockingScript.fromHex(blobHex[variant]);
  const pre = Uint8Array.from(
    TransactionSignature.formatBytes({ ...ctx, subscript: lock, scope: SCOPE }) as unknown as number[],
  );
  const z = BigInt('0x' + Buffer.from(Hash.hash256(Array.from(pre)) as number[]).toString('hex'));
  const spend = new Spend({
    ...ctx,
    lockingScript: LockingScript.fromHex(blobHex[variant]),
    unlockingScript: UnlockingScript.fromHex(pushData(pre)),
  });
  let ok = false;
  try { ok = spend.validate(); } catch { ok = false; }
  return { ok, z };
}

describe('Any-S binding failure rates', () => {
  it('derived pubkeys match the pinned compiler constants (whole construction check)', () => {
    // P = (C·Gx^{-1})·G is what makes s = z+C verify; matching the pinned key
    // validates the additive constant C for each variant.
    // Unified: both the low-S and all constructions verify against the C=1 key.
    expect(pubkeyHexFor('lowS')).toBe('038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218');
    expect(pubkeyHexFor('all')).toBe('038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218');
  });

  it("'all' failure region is exactly { z : z >= n-1 }, P(fail) ≈ 2^-128", () => {
    // Boundary transition.
    expect(accepts(n - 2n, 'all')).toBe(true);
    expect(accepts(n - 1n, 'all')).toBe(false);
    expect(accepts(n, 'all')).toBe(false);
    expect(accepts(TWO256 - 1n, 'all')).toBe(false);
    // Exact region cardinality and probability exponent.
    const region = TWO256 - (n - 1n);
    expect(region).toBe(432420386565659656852420866394968145600n);
    const p = Number(region) / Number(TWO256);
    expect(Math.round(Math.log2(p))).toBe(-128);
  });

  it("'lowS' fails only at the single degenerate z ≡ -1 (z = n-1), P(fail) = 2^-256", () => {
    const zBad = (n - C.lowS) % n;                 // (z+1) ≡ 0 mod n ⇒ z = n-1
    expect(zBad).toBe(n - 1n);
    expect(accepts(zBad, 'lowS')).toBe(false);   // s = 0
    expect(accepts(zBad - 1n, 'lowS')).toBe(true);
    // zBad+1 = n is itself a valid digest that maps to s=1 (accepts); the only
    // failing digest in [0, 2^256) is z = n-1 (zBad+n overflows 2^256).
    expect(accepts(zBad + 1n, 'lowS')).toBe(true);
    expect(zBad + n < TWO256).toBe(false);
    const p = 1 / Number(TWO256);
    expect(Math.round(Math.log2(p))).toBe(-256);
  });

  it('model matches the real interpreter across 120 spends per variant', () => {
    for (const v of ['lowS', 'all'] as const) {
      for (let i = 0; i < 120; i++) {
        const ctx = { ...CTX, lockTime: i * 101 + 1, sourceSatoshis: 100000 + i };
        const { ok, z } = interp(v, ctx);
        expect(ok, `${v} spend ${i} interpreter`).toBe(true);
        expect(accepts(z, v), `${v} spend ${i} model vs interp`).toBe(ok);
      }
    }
  });

  // Regression guard for the nVersion=1 minimal-encoding bug: the low-S variant
  // MUST succeed 100% under transactionVersion=1, where BOTH the LOW_S rule and
  // the strict minimal-encoding rule are enforced (the `00 cat bin2num 1add`
  // normalisation is what makes this hold; without OP_BIN2NUM ~50% of spends
  // fail with "non-minimally encoded script number"). Testing only nVersion=2
  // (relaxed) hides the bug — which is exactly what happened.
  it('lowS succeeds 100% at nVersion=1 (LOW_S + strict minimal-encoding)', () => {
    const v1 = { ...CTX, transactionVersion: 1 };
    for (let i = 0; i < 120; i++) {
      const ctx = { ...v1, lockTime: i * 101 + 1, sourceSatoshis: 100000 + i };
      expect(interp('lowS', ctx).ok, `lowS nVersion=1 spend ${i}`).toBe(true);
    }
  });

  it("'all' is high-S and therefore rejected under nVersion=1 (LOW_S enforced)", () => {
    // 'all' is intentionally non-low-S; at nVersion=1 the LOW_S rule rejects it.
    // This documents WHY 'all' is restricted to nVersion != 1.
    const v1 = { ...CTX, transactionVersion: 1 };
    let accepted = 0;
    for (let i = 0; i < 60; i++) {
      const ctx = { ...v1, lockTime: i * 101 + 1, sourceSatoshis: 100000 + i };
      if (interp('all', ctx).ok) accepted++;
    }
    expect(accepted, "'all' should be broadly rejected at nVersion=1").toBeLessThan(60);
  });
});
