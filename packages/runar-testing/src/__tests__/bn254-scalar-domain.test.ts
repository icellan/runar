import { describe, it, expect } from 'vitest';
import { emitMethod, emitBn254G1ScalarMul } from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

/**
 * The DOMAIN of `bn254G1ScalarMul`: every scalar, not just [0, r−1].
 *
 * The ladder builds k′ = k + 3r, seeds the accumulator at bit 255 rather than
 * stepping it, and then iterates bits 254…0. That is sound ONLY while
 * 2^255 ≤ k′ < 2^256, i.e. while
 *
 *     2^255 − 3r ≤ k < 2^256 − 3r      (≈ −0.3549·r … ≈ 2.2902·r)
 *
 * BN254's numbers are its OWN — r is 254 bits here against 256 on secp256k1 —
 * so 3r is 256 bits, 3r ≥ 2^255 and 4r−1 < 2^256. Outside that window the
 * ladder does not fail: it silently applies a DIFFERENT multiplier,
 *
 *     m = 2^255 + ((k + 3r) mod 2^255)
 *
 * which is ≢ k (mod r). Two consequences, both live:
 *
 *   • k ≥ 2^256 − 3r sets bit 256, which the loop never reads.
 *   • k ≤ 2^255 − 3r drops k′ below 2^255, so the seeded top bit is a lie.
 *
 * and it is MALLEABLE in the scalar: k and k + 3r are the same group element
 * but produce different points, while k = 2^256 − 1 and k = r − 1 are
 * different group elements that produce the SAME point.
 *
 * The fix is the same one secp256k1 and the NIST curves already carry: reduce
 * k to [0, r−1] up front with ((k mod r) + r) mod r — OP_MOD takes the sign of
 * the DIVIDEND, so the `+ r, mod r` is what normalises negative scalars.
 *
 * The reduce alone is NOT sufficient, and this file pins both halves. Reducing
 * makes k ≡ 0 (mod r) reachable (k = r, k = 3r, k = −2r all land on 0), and at
 * k ≡ 0 the last ladder step is handed accumulator == −base. The mixed-add's
 * H == 0 test cannot tell −base from +base, so without the additional R == 0
 * test at the final step that case takes the doubling branch and returns −2P
 * where the answer is the point at infinity.
 *
 * Oracle: a from-scratch double-and-add over y² = x³ + 3 written from the curve
 * parameters alone, cross-checked in the first test against values produced by
 * gnark-crypto's `bn254.G1Affine.ScalarMultiplication`. Everything runs through
 * the real @bsv/sdk `Spend` interpreter via ScriptVM, not emitter-level logic.
 */

/** BN254 base field. */
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
/** BN254 group order (254 bits). */
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** G = (1, 2). */
const GX = 1n;
const GY = 2n;

type Aff = { x: bigint; y: bigint } | null;

const m = (v: bigint) => ((v % P) + P) % P;

function inv(a: bigint): bigint {
  let r = 1n;
  let b = m(a);
  let e = P - 2n;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}

function dbl(A: Aff): Aff {
  if (A === null) return null;
  const s = m(m(3n * A.x * A.x) * inv(2n * A.y));
  const x = m(s * s - 2n * A.x);
  return { x, y: m(s * (A.x - x) - A.y) };
}

function add(A: Aff, B: Aff): Aff {
  if (A === null) return B;
  if (B === null) return A;
  if (A.x === B.x) return m(A.y + B.y) === 0n ? null : dbl(A);
  const s = m(m(B.y - A.y) * inv(m(B.x - A.x)));
  const x = m(s * s - A.x - B.x);
  return { x, y: m(s * (A.x - x) - A.y) };
}

function mul(k: bigint, A: Aff): Aff {
  let acc: Aff = null;
  let cur = A;
  let e = k;
  while (e > 0n) {
    if (e & 1n) acc = add(acc, cur);
    cur = dbl(cur);
    e >>= 1n;
  }
  return acc;
}

const hex64 = (v: bigint) => v.toString(16).padStart(64, '0');
const pointHex = (pt: NonNullable<Aff>) => hex64(pt.x) + hex64(pt.y);
const ZERO_POINT = '00'.repeat(64);
const G: NonNullable<Aff> = { x: GX, y: GY };
const G_HEX = pointHex(G);

const blob = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

/** The value bn254G1ScalarMul(P, k) MUST take: (k mod r)·P, with 0 ↦ O. */
function expected(k: bigint): string {
  const red = ((k % R) + R) % R;
  return red === 0n ? ZERO_POINT : pointHex(mul(red, G)!);
}

/** Run the emitted ladder for (G, k) through the real interpreter. */
function scalarMul(pointHexIn: string, k: bigint): string {
  const ops: StackOp[] = [
    { op: 'push', value: blob(pointHexIn) } as StackOp,
    { op: 'push', value: k } as StackOp,
  ];
  emitBn254G1ScalarMul((o: StackOp) => ops.push(o));
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const res = new ScriptVM().executeHex(scriptHex) as never as { stack: Uint8Array[] };
  return res.stack.length
    ? Buffer.from(res.stack[res.stack.length - 1]!).toString('hex')
    : '(empty)';
}

describe('bn254G1ScalarMul scalar domain', () => {
  // --- oracle agreement -----------------------------------------------------
  //
  // Values produced independently by gnark-crypto v0.14.0
  // (bn254.G1Affine.ScalarMultiplication over the standard generator).

  it('the from-scratch ladder agrees with gnark-crypto', () => {
    const GNARK: Record<string, [bigint, bigint]> = {
      '2': [
        1368015179489954701390400359078579693043519447331113978918064868415326638035n,
        9918110051302171585080402603319702774565515993150576347155970296011118125764n,
      ],
      '3': [
        3353031288059533942658390886683067124040920775575537747144343083137631628272n,
        19321533766552368860946552437480515441416830039777911637913418824951667761761n,
      ],
      '5': [
        10744596414106452074759370245733544594153395043370666422502510773307029471145n,
        848677436511517736191562425154572367705380862894644942948681172815252343932n,
      ],
      '7': [
        10415861484417082502655338383609494480414113902179649885744799961447382638712n,
        10196215078179488638353184030336251401353352596818396260819493263908881608606n,
      ],
    };
    for (const [k, [x, y]] of Object.entries(GNARK)) {
      expect(pointHex(mul(BigInt(k), G)!)).toBe(hex64(x) + hex64(y));
    }
    // (r−1)·G = −G = (1, p − 2), also checked against gnark.
    expect(pointHex(mul(R - 1n, G)!)).toBe(hex64(1n) + hex64(P - 2n));
  });

  // --- the below-r common case must not move --------------------------------

  for (const k of [1n, 2n, 3n, 5n, 7n, 12345n, R - 1n]) {
    it(`ScalarMul(G, ${k}) === ${k}·G (in-domain control)`, () => {
      expect(scalarMul(G_HEX, k)).toBe(expected(k));
    });
  }

  // --- above the upper bound: bit 256 falls off the end of the loop ---------
  //
  // k + 3r ≥ 2^256. Note that k + r and k + 2r do NOT break — 5r < 2^256 — so
  // the smallest multiple of r that exposes this is 3r, not r.

  for (const [label, k] of [
    ['3r', 3n * R],
    ['3r + 7', 3n * R + 7n],
    ['2^256 − 1', (1n << 256n) - 1n],
    ['2^300 + 12345', (1n << 300n) + 12345n],
  ] as Array<[string, bigint]>) {
    it(`ScalarMul(G, ${label}) === (k mod r)·G`, () => {
      expect(scalarMul(G_HEX, k)).toBe(expected(k));
    });
  }

  // --- below the lower bound: the seeded top bit is a lie -------------------

  for (const [label, k] of [
    ['−2r', -2n * R],
    ['−r + 3', -R + 3n],
    ['−(r + 1)', -(R + 1n)],
  ] as Array<[string, bigint]>) {
    it(`ScalarMul(G, ${label}) === (k mod r)·G`, () => {
      expect(scalarMul(G_HEX, k)).toBe(expected(k));
    });
  }

  // --- small negative scalars (inside the window, pinned for the reduce) ----

  for (const k of [-1n, -3n, -12345n]) {
    it(`ScalarMul(G, ${k}) === (r${k})·G`, () => {
      expect(scalarMul(G_HEX, k)).toBe(expected(k));
    });
  }

  // --- scalar malleability --------------------------------------------------
  //
  // These are the adversarial vectors: a Groth16 public input is caller-chosen,
  // so an attacker picks the representative of the residue class.

  it('k and k + 3r are the same group element and MUST give the same point', () => {
    const k = 5n;
    expect(scalarMul(G_HEX, k + 3n * R)).toBe(scalarMul(G_HEX, k));
  });

  it('k = 2^256 − 1 must NOT collide with k = r − 1', () => {
    // Unreduced, 2^256 − 1 applies the multiplier r − 1 exactly, so the two
    // distinct residues produce one point. That is the malleability.
    expect(scalarMul(G_HEX, (1n << 256n) - 1n)).not.toBe(scalarMul(G_HEX, R - 1n));
    expect(scalarMul(G_HEX, (1n << 256n) - 1n)).toBe(expected((1n << 256n) - 1n));
  });

  // --- k ≡ 0 (mod r): the point at infinity ---------------------------------
  //
  // Affine x‖y cannot encode O and `bn254FieldInv` is Fermat, so inv(0) = 0 and
  // the ladder yields the all-zero blob. These are the cases the last step's
  // strict H == 0 AND R == 0 test exists for: at k ≡ 0 the accumulator going
  // into the final add is exactly −base.

  for (const [label, k] of [
    ['0', 0n],
    ['r', R],
    ['2r', 2n * R],
    ['3r', 3n * R],
    ['−2r', -2n * R],
  ] as Array<[string, bigint]>) {
    it(`ScalarMul(G, ${label}) is the all-zero point (k ≡ 0 mod r)`, () => {
      expect(scalarMul(G_HEX, k)).toBe(ZERO_POINT);
    });
  }
});
