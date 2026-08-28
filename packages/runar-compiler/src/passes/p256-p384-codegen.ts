/**
 * P-256 / P-384 codegen — NIST elliptic curve operations for Bitcoin Script.
 *
 * Follows the same pattern as ec-codegen.ts (secp256k1). Uses ECTracker for
 * named stack state tracking, but with different field primes, curve orders,
 * and generator points.
 *
 * Point representation:
 *   P-256: 64 bytes (x[32] || y[32], big-endian unsigned)
 *   P-384: 96 bytes (x[48] || y[48], big-endian unsigned)
 *
 * Key difference from secp256k1: curve parameter a = -3 (not 0), which gives
 * an optimized Jacobian doubling formula.
 */

import type { StackOp } from '../ir/index.js';
import { ECTracker, POOL_FIELD_P, POOL_GROUP_N, Dom, isNonNegative } from './ec-codegen.js';
import type { EcCodegenOptions } from './ec-codegen.js';

// ===========================================================================
// P-256 constants (secp256r1 / NIST P-256)
// ===========================================================================

const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_P_MINUS_2 = P256_P - 2n;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_N_MINUS_2 = P256_N - 2n;
const P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
const P256_SQRT_EXP = (P256_P + 1n) / 4n;

// ===========================================================================
// P-384 constants (secp384r1 / NIST P-384)
// ===========================================================================

const P384_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn;
const P384_P_MINUS_2 = P384_P - 2n;
const P384_B = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn;
const P384_N = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n;
const P384_N_MINUS_2 = P384_N - 2n;
const P384_GX = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n;
const P384_GY = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn;
const P384_SQRT_EXP = (P384_P + 1n) / 4n;

// ===========================================================================
// Shared helpers
// ===========================================================================

function bigintToBytes(n: bigint, len: number): Uint8Array {
  const bytes = new Uint8Array(len);
  let v = n;
  for (let i = len - 1; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

/** Count bits in a bigint (position of highest set bit + 1). */
function bitLength(n: bigint): number {
  let bits = 0;
  let v = n;
  while (v > 0n) {
    bits++;
    v >>= 1n;
  }
  return bits;
}

// ===========================================================================
// Byte reversal helpers
// ===========================================================================

/** Emit inline byte reversal for a 32-byte value on TOS. */
function emitReverse32(e: (op: StackOp) => void): void {
  e({ op: 'opcode', code: 'OP_0' });
  e({ op: 'swap' });
  for (let i = 0; i < 32; i++) {
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'rot' });
    e({ op: 'rot' });
    e({ op: 'swap' });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'swap' });
  }
  e({ op: 'drop' });
}

/** Emit inline byte reversal for a 48-byte value on TOS. */
function emitReverse48(e: (op: StackOp) => void): void {
  e({ op: 'opcode', code: 'OP_0' });
  e({ op: 'swap' });
  for (let i = 0; i < 48; i++) {
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'rot' });
    e({ op: 'rot' });
    e({ op: 'swap' });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'swap' });
  }
  e({ op: 'drop' });
}

// ===========================================================================
// Generic curve field arithmetic (parameterized by prime)
// ===========================================================================

type CurveParams = {
  fieldP: bigint;
  fieldPMinus2: bigint;
  coordBytes: number; // 32 for P-256, 48 for P-384
  reverseBytes: (e: (op: StackOp) => void) => void;
};

const P256_PARAMS: CurveParams = {
  fieldP: P256_P,
  fieldPMinus2: P256_P_MINUS_2,
  coordBytes: 32,
  reverseBytes: emitReverse32,
};

const P384_PARAMS: CurveParams = {
  fieldP: P384_P,
  fieldPMinus2: P384_P_MINUS_2,
  coordBytes: 48,
  reverseBytes: emitReverse48,
};

function pushFieldP(t: ECTracker, name: string, c: CurveParams): void {
  t.pushConst(POOL_FIELD_P, c.fieldP, name);
}

/**
 * `a mod p` with no sign fix-up: 1 opcode instead of 7. Sound only when the
 * dividend is provably >= 0 — the caller proves that, this does not check.
 */
function cFieldModShort(t: ECTracker, aName: string, resultName: string, c: CurveParams): void {
  t.toTop(aName);
  pushFieldP(t, '_fmods_p', c);
  t.rawBlock([aName, '_fmods_p'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_MOD' });
  });
  t.setDomain(resultName, Dom.Reduced);
}

/** Does the cheap `a - b + p` subtraction pay? Only when p is pooled. */
function cCheapSubPays(t: ECTracker, c: CurveParams): boolean {
  const cost = t.constCost(POOL_FIELD_P, c.fieldP);
  return 2 * cost + 2 < cost + 8;
}

function cFieldMod(t: ECTracker, aName: string, resultName: string, c: CurveParams): void {
  if (t.sinking && isNonNegative(t.domainOf(aName))) {
    cFieldModShort(t, aName, resultName, c);
    return;
  }
  t.toTop(aName);
  pushFieldP(t, '_fmod_p', c);
  t.rawBlock([aName, '_fmod_p'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_2DUP' });
    e({ op: 'opcode', code: 'OP_MOD' });
    e({ op: 'rot' });
    e({ op: 'drop' });
    e({ op: 'over' });
    e({ op: 'opcode', code: 'OP_ADD' });
    e({ op: 'swap' });
    e({ op: 'opcode', code: 'OP_MOD' });
  });
  t.setDomain(resultName, Dom.Reduced);
}

function cFieldAdd(t: ECTracker, aName: string, bName: string, resultName: string, c: CurveParams): void {
  // Read the operand facts before rawBlock consumes their slots.
  const sumNonNeg = isNonNegative(t.domainOf(aName)) && isNonNegative(t.domainOf(bName));
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_fadd_sum', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  if (sumNonNeg) t.setDomain('_fadd_sum', Dom.NonNegative);
  cFieldMod(t, '_fadd_sum', resultName, c);
}

function cFieldSub(t: ECTracker, aName: string, bName: string, resultName: string, c: CurveParams): void {
  t.toTop(aName);
  t.toTop(bName);
  // Needs a >= 0 AND b in [0, p): then a - b > -p and one shifted reduction is
  // exact. `b >= 0` alone is not enough — a coordinate decoded from 32 unsigned
  // bytes may exceed p by up to 2^32 + 977.
  const cheap = t.sinking
    && isNonNegative(t.domainOf(aName))
    && t.domainOf(bName) === Dom.Reduced
    && cCheapSubPays(t, c);

  t.rawBlock([aName, bName], '_fsub_diff', (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
  });

  if (cheap) {
    pushFieldP(t, '_fsub_p', c);
    t.rawBlock(['_fsub_diff', '_fsub_p'], '_fsub_shift', (e) => {
      e({ op: 'opcode', code: 'OP_ADD' });
    });
    t.setDomain('_fsub_shift', Dom.NonNegative);
    cFieldModShort(t, '_fsub_shift', resultName, c);
    return;
  }
  cFieldMod(t, '_fsub_diff', resultName, c);
}

function cFieldMul(
  t: ECTracker, aName: string, bName: string, resultName: string, c: CurveParams,
  productNonNegative = false,
): void {
  // `productNonNegative` lets cFieldSqr assert the sign independently of the
  // operand: a*a >= 0 for any a whatsoever.
  const nonNeg = productNonNegative
    || (isNonNegative(t.domainOf(aName)) && isNonNegative(t.domainOf(bName)));
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_fmul_prod', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  if (nonNeg) t.setDomain('_fmul_prod', Dom.NonNegative);
  cFieldMod(t, '_fmul_prod', resultName, c);
}

function cFieldMulConst(t: ECTracker, aName: string, cv: bigint, resultName: string, c: CurveParams): void {
  // Every call site passes a small positive cv, so the product keeps a's sign.
  const nonNeg = cv > 0n && isNonNegative(t.domainOf(aName));
  t.toTop(aName);
  t.rawBlock([aName], '_fmc_prod', (e) => {
    if (cv === 2n) {
      e({ op: 'opcode', code: 'OP_2MUL' });
    } else {
      e({ op: 'push', value: cv });
      e({ op: 'opcode', code: 'OP_MUL' });
    }
  });
  if (nonNeg) t.setDomain('_fmc_prod', Dom.NonNegative);
  cFieldMod(t, '_fmc_prod', resultName, c);
}

function cFieldSqr(t: ECTracker, aName: string, resultName: string, c: CurveParams): void {
  t.copyToTop(aName, '_fsqr_copy');
  cFieldMul(t, aName, '_fsqr_copy', resultName, c, true);
}

/**
 * Field inverse via Fermat's little theorem: a^(p-2) mod p.
 * Generic square-and-multiply over all bits of (p-2).
 */
function cFieldInv(t: ECTracker, aName: string, resultName: string, c: CurveParams): void {
  const exp = c.fieldPMinus2;
  const bits = bitLength(exp);

  // Start: result = a (highest bit of exp is 1)
  t.copyToTop(aName, '_inv_r');

  for (let i = bits - 2; i >= 0; i--) {
    cFieldSqr(t, '_inv_r', '_inv_r2', c);
    t.rename('_inv_r');
    if ((exp >> BigInt(i)) & 1n) {
      t.copyToTop(aName, '_inv_a');
      cFieldMul(t, '_inv_r', '_inv_a', '_inv_m', c);
      t.rename('_inv_r');
    }
  }

  t.toTop(aName); t.drop();
  t.toTop('_inv_r'); t.rename(resultName);
}

// ===========================================================================
// Group-order arithmetic (for ECDSA: mod n operations)
// ===========================================================================

type GroupParams = {
  n: bigint;
  nMinus2: bigint;
};

const P256_GROUP: GroupParams = { n: P256_N, nMinus2: P256_N_MINUS_2 };
const P384_GROUP: GroupParams = { n: P384_N, nMinus2: P384_N_MINUS_2 };

function pushGroupN(t: ECTracker, name: string, g: GroupParams): void {
  t.pushConst(POOL_GROUP_N, g.n, name);
}

function cGroupMod(t: ECTracker, aName: string, resultName: string, g: GroupParams): void {
  t.toTop(aName);
  pushGroupN(t, '_gmod_n', g);
  t.rawBlock([aName, '_gmod_n'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_2DUP' });
    e({ op: 'opcode', code: 'OP_MOD' });
    e({ op: 'rot' });
    e({ op: 'drop' });
    e({ op: 'over' });
    e({ op: 'opcode', code: 'OP_ADD' });
    e({ op: 'swap' });
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

/**
 * Reduce a scalar to [0, n-1]: ((k mod n) + n) mod n.
 *
 * OP_MOD takes the sign of the DIVIDEND, so `k mod n` alone lands in (-n, n);
 * the `+ n, mod n` normalises the negative half. One push of n covers both
 * reductions — the same shape as `emitEcModReduce`.
 *
 * Without it, `cEmitMul`'s ladder is only correct while 2^b <= k + 3n < 2^(b+1)
 * for the fixed b it unrolls: a scalar >= ~n sets a bit above the loop's top,
 * the loop never sees it, and the ladder returns a DIFFERENT multiple of P
 * rather than failing. Scalars are contract input, so that is attacker-chosen.
 * Reducing costs 1 push + 7 opcodes (41 / 57 bytes) against a ~460 KB / 1.6 MB
 * script, and makes k >= n, k < 0 and k = 0 all well defined.
 */
function cEmitScalarReduce(t: ECTracker, kName: string, resultName: string, g: GroupParams): void {
  pushGroupN(t, '_n_red', g);
  t.rawBlock([kName, '_n_red'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_2DUP' });
    e({ op: 'opcode', code: 'OP_MOD' });
    e({ op: 'rot' });
    e({ op: 'drop' });
    e({ op: 'over' });
    e({ op: 'opcode', code: 'OP_ADD' });
    e({ op: 'swap' });
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

function cGroupMul(t: ECTracker, aName: string, bName: string, resultName: string, g: GroupParams): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_gmul_prod', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  cGroupMod(t, '_gmul_prod', resultName, g);
}

/**
 * Group-order inverse via Fermat's: a^(n-2) mod n.
 */
function cGroupInv(t: ECTracker, aName: string, resultName: string, g: GroupParams): void {
  const exp = g.nMinus2;
  const bits = bitLength(exp);

  t.copyToTop(aName, '_ginv_r');

  for (let i = bits - 2; i >= 0; i--) {
    // Square
    t.copyToTop('_ginv_r', '_ginv_sq_copy');
    cGroupMul(t, '_ginv_r', '_ginv_sq_copy', '_ginv_sq', g);
    t.rename('_ginv_r');
    if ((exp >> BigInt(i)) & 1n) {
      t.copyToTop(aName, '_ginv_a');
      cGroupMul(t, '_ginv_r', '_ginv_a', '_ginv_m', g);
      t.rename('_ginv_r');
    }
  }

  t.toTop(aName); t.drop();
  t.toTop('_ginv_r'); t.rename(resultName);
}

// ===========================================================================
// Point decompose / compose (parameterized by coordinate byte size)
// ===========================================================================

/**
 * Decompose point → (x_num, y_num) on stack.
 * P-256: 64-byte point, split at 32. P-384: 96-byte point, split at 48.
 */
function cDecomposePoint(t: ECTracker, pointName: string, xName: string, yName: string, c: CurveParams): void {
  t.toTop(pointName);
  t.rawBlock([pointName], null, (e) => {
    e({ op: 'push', value: BigInt(c.coordBytes) });
    e({ op: 'opcode', code: 'OP_SPLIT' });
  });
  t.pushTracked('_dp_xb');
  t.pushTracked('_dp_yb');

  // Convert y_bytes (on top) to num: reverse BE→LE, append sign byte, BIN2NUM
  t.rawBlock(['_dp_yb'], yName, (e) => {
    c.reverseBytes(e);
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
  });
  // A 0x00 sign byte is appended before BIN2NUM, so the coordinate decodes
  // UNSIGNED: >= 0, but possibly >= p by up to 2^32 + 977. That gap is exactly
  // what the subtraction precondition turns on.
  t.setDomain(yName, Dom.NonNegative);

  // Convert x_bytes to num
  t.toTop('_dp_xb');
  t.rawBlock(['_dp_xb'], xName, (e) => {
    c.reverseBytes(e);
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
  });
  t.setDomain(xName, Dom.NonNegative);

  // Swap to standard order [xName, yName]
  t.swap();
}

/**
 * Compose (x_num, y_num) → point bytes.
 * P-256: 64 bytes. P-384: 96 bytes.
 */
function cComposePoint(t: ECTracker, xName: string, yName: string, resultName: string, c: CurveParams): void {
  const numBinSize = BigInt(c.coordBytes + 1); // +1 for sign byte

  // Convert x to coordBytes big-endian
  t.toTop(xName);
  t.rawBlock([xName], '_cp_xb', (e) => {
    e({ op: 'push', value: numBinSize });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    e({ op: 'push', value: BigInt(c.coordBytes) });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'drop' });
    c.reverseBytes(e);
  });

  // Convert y to coordBytes big-endian
  t.toTop(yName);
  t.rawBlock([yName], '_cp_yb', (e) => {
    e({ op: 'push', value: numBinSize });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    e({ op: 'push', value: BigInt(c.coordBytes) });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'drop' });
    c.reverseBytes(e);
  });

  // Cat: x_be || y_be
  t.toTop('_cp_xb');
  t.toTop('_cp_yb');
  t.rawBlock(['_cp_xb', '_cp_yb'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_CAT' });
  });
}

/**
 * GAP-301: coordinate canonicity, leaving `_canon` on the tracker.
 *
 * `cDecomposePoint` BIN2NUMs each coordinate as an unsigned value that may be
 * >= p; the curve equation reduces it mod p, so (x + p)‖y would pass as a
 * point it is not the canonical encoding of. Reject it: require x < p AND
 * y < p (coordinates are unsigned, so the 0 <= bound holds by construction).
 * The caller ANDs `_canon` into its result so the check still returns a
 * boolean. This mirrors secp256k1's `emitEcOnCurve`, whose guard the a = -3
 * curves never received — leaving `pNNNOnCurve` accepting inputs `ecOnCurve`
 * rejects even though both are documented as THE gate for untrusted points.
 */
function cEmitCanonicityGuard(t: ECTracker, xName: string, yName: string, c: CurveParams): void {
  t.copyToTop(xName, '_x_lt');
  pushFieldP(t, '_p_for_x', c);
  t.rawBlock(['_x_lt', '_p_for_x'], '_x_canon', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.copyToTop(yName, '_y_lt');
  pushFieldP(t, '_p_for_y', c);
  t.rawBlock(['_y_lt', '_p_for_y'], '_y_canon', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.toTop('_x_canon');
  t.toTop('_y_canon');
  t.rawBlock(['_x_canon', '_y_canon'], '_canon', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
}

// ===========================================================================
// Affine point addition (for ecAdd — same formulas, different field)
// ===========================================================================

function cAffineAdd(t: ECTracker, c: CurveParams): void {
  // The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
  // denominator is zero and the correct slope is the TANGENT, (3px^2 + a)/(2py)
  // — and a = -3 on both NIST curves, so the numerator is 3px^2 - 3.
  // 8a6494b4 fixed this for secp256k1 (a = 0) but the fix was never ported
  // here, so `p256Add(P, P)` and `p384Add(P, P)` produced a wrong point and
  // every contract that doubled deployed an unspendable script.
  //
  // Both cases are the same shape, `s = num / den`, so only the NUMERATOR and
  // DENOMINATOR are selected; the single expensive cFieldInv still runs exactly
  // once. rx = s^2 - px - qx and ry = s*(px - rx) - py are already correct for
  // doubling (px == qx makes the first s^2 - 2px).
  //
  //   cond   = (px == qx) AND (py == qy)     1 when doubling, else 0
  //   num    = cond ? 3*px^2 - 3 : (qy - py)
  //   den    = cond ? 2*py       : (qx - px)
  //
  // selected as `b + cond*(a - b)` over the field, which needs no branch and
  // so keeps the emitted op sequence — and the tracker's static stack model —
  // identical on both paths.
  //
  // THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
  // sends it down the tangent path and returns 2P — an on-curve, entirely
  // plausible, WRONG point, which is strictly worse than the pre-fix chord
  // path: that one divided by zero (cFieldInv is Fermat, inv(0) = 0) and
  // produced an OFF-curve blob, so `assert(pNNNOnCurve(pNNNAdd(a, b)))` — the
  // idiom examples/ts/p384-primitives writes verbatim — rejected it.
  //
  // P + (-P) is the point at infinity, which affine x||y cannot represent. This
  // codegen already has a representation for O: the ALL-ZERO blob, which is
  // what `pNNNMul(P, 0n)` returns. So return that, by masking the result with
  // `notinf = NOT(px == qx AND NOT cond)`. O is not on the curve (0^2 != b),
  // so the on-curve gate rejects it and the idiom works again; and it adds no
  // failure channel to a pure value-producing expression, the same reason
  // cEmitScalarReduce reduces instead of rejecting.
  //
  // The mask is a bare OP_MUL with no reduction: rx, ry are already in [0, p)
  // and notinf is 0 or 1, so the product is canonical either way.
  t.copyToTop('px', '_px_eq');
  t.copyToTop('qx', '_qx_eq');
  t.rawBlock(['_px_eq', '_qx_eq'], '_xeq', (e) => {
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  t.copyToTop('py', '_py_eq');
  t.copyToTop('qy', '_qy_eq');
  t.rawBlock(['_py_eq', '_qy_eq'], '_yeq', (e) => {
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  t.copyToTop('_xeq', '_xeq_c');
  t.toTop('_yeq');
  t.rawBlock(['_xeq_c', '_yeq'], '_cond', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
  // notinf = NOT(xeq - cond): 1 exactly when px == qx and the points differ.
  t.toTop('_xeq');
  t.copyToTop('_cond', '_cond_c');
  t.rawBlock(['_xeq', '_cond_c'], '_notinf', (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
    e({ op: 'opcode', code: 'OP_NOT' });
  });

  // chord numerator / denominator
  t.copyToTop('qy', '_qy1');
  t.copyToTop('py', '_py1');
  cFieldSub(t, '_qy1', '_py1', '_num_chord', c);
  t.copyToTop('qx', '_qx1');
  t.copyToTop('px', '_px1');
  cFieldSub(t, '_qx1', '_px1', '_den_chord', c);

  // tangent numerator / denominator: 3*px^2 + a (a = -3) and 2*py
  t.copyToTop('px', '_px_t');
  cFieldSqr(t, '_px_t', '_px_sq', c);
  cFieldMulConst(t, '_px_sq', 3n, '_3px_sq', c);
  t.pushInt('_a_neg', 3n);
  cFieldSub(t, '_3px_sq', '_a_neg', '_num_tan', c);
  t.copyToTop('py', '_py_t');
  cFieldMulConst(t, '_py_t', 2n, '_den_tan', c);

  // num = num_chord + cond*(num_tan - num_chord)
  t.copyToTop('_num_chord', '_num_chord_c');
  cFieldSub(t, '_num_tan', '_num_chord_c', '_num_diff', c);
  t.copyToTop('_cond', '_cond_n');
  cFieldMul(t, '_num_diff', '_cond_n', '_num_sel', c);
  cFieldAdd(t, '_num_chord', '_num_sel', '_s_num', c);

  // den = den_chord + cond*(den_tan - den_chord)
  t.copyToTop('_den_chord', '_den_chord_c');
  cFieldSub(t, '_den_tan', '_den_chord_c', '_den_diff', c);
  t.toTop('_cond');
  t.rename('_cond_d');
  cFieldMul(t, '_den_diff', '_cond_d', '_den_sel', c);
  cFieldAdd(t, '_den_chord', '_den_sel', '_s_den', c);

  // s = s_num / s_den mod p
  cFieldInv(t, '_s_den', '_s_den_inv', c);
  cFieldMul(t, '_s_num', '_s_den_inv', '_s', c);

  // rx = s^2 - px - qx mod p
  t.copyToTop('_s', '_s_keep');
  cFieldSqr(t, '_s', '_s2', c);
  t.copyToTop('px', '_px2');
  cFieldSub(t, '_s2', '_px2', '_rx1', c);
  t.copyToTop('qx', '_qx2');
  cFieldSub(t, '_rx1', '_qx2', 'rx', c);

  // ry = s * (px - rx) - py mod p
  t.copyToTop('px', '_px3');
  t.copyToTop('rx', '_rx2');
  cFieldSub(t, '_px3', '_rx2', '_px_rx', c);
  cFieldMul(t, '_s_keep', '_px_rx', '_s_px_rx', c);
  t.copyToTop('py', '_py2');
  cFieldSub(t, '_s_px_rx', '_py2', 'ry', c);

  // Clean up original points
  t.toTop('px'); t.drop();
  t.toTop('py'); t.drop();
  t.toTop('qx'); t.drop();
  t.toTop('qy'); t.drop();

  // P == -Q -> force the all-zero point (see the header comment).
  t.toTop('rx');
  t.copyToTop('_notinf', '_notinf_x');
  t.rawBlock(['rx', '_notinf_x'], 'rx', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  t.toTop('ry');
  t.toTop('_notinf');
  t.rawBlock(['ry', '_notinf'], 'ry', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
}

// ===========================================================================
// Jacobian point doubling with a=-3 optimization
// ===========================================================================

/**
 * Jacobian doubling for curves with a = -3 (P-256, P-384).
 *
 * Uses the optimization: A = 3*(X - Z^2)*(X + Z^2) instead of 3*X^2 + a*Z^4.
 * This saves 2 field squarings compared to the generic formula.
 *
 * Expects jx, jy, jz on tracker. Replaces with updated values.
 */
function cJacobianDouble(t: ECTracker, c: CurveParams): void {
  // Z^2
  t.copyToTop('jz', '_jz_sq_tmp');
  cFieldSqr(t, '_jz_sq_tmp', '_Z2', c);

  // X - Z^2 and X + Z^2
  t.copyToTop('jx', '_jx_c1');
  t.copyToTop('_Z2', '_Z2_c1');
  cFieldSub(t, '_jx_c1', '_Z2_c1', '_X_minus_Z2', c);
  t.copyToTop('jx', '_jx_c2');
  cFieldAdd(t, '_jx_c2', '_Z2', '_X_plus_Z2', c);

  // A = 3*(X-Z^2)*(X+Z^2)
  cFieldMul(t, '_X_minus_Z2', '_X_plus_Z2', '_prod', c);
  t.pushInt('_three', 3n);
  cFieldMul(t, '_prod', '_three', '_A', c);

  // B = 4*X*Y^2
  t.copyToTop('jy', '_jy_sq_tmp');
  cFieldSqr(t, '_jy_sq_tmp', '_Y2', c);
  t.copyToTop('_Y2', '_Y2_c1');
  t.copyToTop('jx', '_jx_c3');
  cFieldMul(t, '_jx_c3', '_Y2', '_xY2', c);
  t.pushInt('_four', 4n);
  cFieldMul(t, '_xY2', '_four', '_B', c);

  // C = 8*Y^4
  cFieldSqr(t, '_Y2_c1', '_Y4', c);
  t.pushInt('_eight', 8n);
  cFieldMul(t, '_Y4', '_eight', '_C', c);

  // X3 = A^2 - 2*B
  t.copyToTop('_A', '_A_save');
  t.copyToTop('_B', '_B_save');
  cFieldSqr(t, '_A', '_A2', c);
  t.copyToTop('_B', '_B_c1');
  cFieldMulConst(t, '_B_c1', 2n, '_2B', c);
  cFieldSub(t, '_A2', '_2B', '_X3', c);

  // Y3 = A*(B - X3) - C
  t.copyToTop('_X3', '_X3_c');
  cFieldSub(t, '_B_save', '_X3_c', '_B_minus_X3', c);
  cFieldMul(t, '_A_save', '_B_minus_X3', '_A_tmp', c);
  cFieldSub(t, '_A_tmp', '_C', '_Y3', c);

  // Z3 = 2*Y*Z
  t.copyToTop('jy', '_jy_c');
  t.copyToTop('jz', '_jz_c');
  cFieldMul(t, '_jy_c', '_jz_c', '_yz', c);
  cFieldMulConst(t, '_yz', 2n, '_Z3', c);

  // Clean up and rename
  t.toTop('_B'); t.drop();
  t.toTop('jz'); t.drop();
  t.toTop('jx'); t.drop();
  t.toTop('jy'); t.drop();
  t.toTop('_X3'); t.rename('jx');
  t.toTop('_Y3'); t.rename('jy');
  t.toTop('_Z3'); t.rename('jz');
}

// ===========================================================================
// Jacobian to affine conversion
// ===========================================================================

function cJacobianToAffine(t: ECTracker, rxName: string, ryName: string, c: CurveParams): void {
  cFieldInv(t, 'jz', '_zinv', c);
  t.copyToTop('_zinv', '_zinv_keep');
  cFieldSqr(t, '_zinv', '_zinv2', c);
  t.copyToTop('_zinv2', '_zinv2_keep');
  cFieldMul(t, '_zinv_keep', '_zinv2', '_zinv3', c);
  cFieldMul(t, 'jx', '_zinv2_keep', rxName, c);
  cFieldMul(t, 'jy', '_zinv3', ryName, c);
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine)
// ===========================================================================

/**
 * Build Jacobian mixed-add ops for use inside OP_IF.
 * Stack layout: [..., ax, ay, _k, jx, jy, jz]
 * After:        [..., ax, ay, _k, jx', jy', jz']
 */
function buildJacobianAddAffineInline(e: (op: StackOp) => void, t: ECTracker, c: CurveParams): void {
  jacobianAddAffineBody(new ECTracker([...t.nm], e, t.options, [...t.dm]), false, c);
}

/**
 * The mixed-add itself, emitting through an ECTracker the caller owns.
 *
 * `keepHR` additionally leaves copies of H and R on the stack: both are zero
 * exactly when the Jacobian accumulator is the same curve point as the affine
 * operand, the one case these formulas cannot compute. See
 * buildJacobianAddOrDoubleInline.
 */
function jacobianAddAffineBody(it: ECTracker, keepHR: boolean, c: CurveParams): void {
  it.copyToTop('jz', '_jz_for_z1cu');
  it.copyToTop('jz', '_jz_for_z3');
  it.copyToTop('jy', '_jy_for_y3');
  it.copyToTop('jx', '_jx_for_u1h2');

  // Z1sq = jz^2
  cFieldSqr(it, 'jz', '_Z1sq', c);

  // Z1cu = _jz_for_z1cu * Z1sq
  it.copyToTop('_Z1sq', '_Z1sq_for_u2');
  cFieldMul(it, '_jz_for_z1cu', '_Z1sq', '_Z1cu', c);

  // U2 = ax * Z1sq_for_u2
  it.copyToTop('ax', '_ax_c');
  cFieldMul(it, '_ax_c', '_Z1sq_for_u2', '_U2', c);

  // S2 = ay * Z1cu
  it.copyToTop('ay', '_ay_c');
  cFieldMul(it, '_ay_c', '_Z1cu', '_S2', c);

  // H = U2 - jx
  cFieldSub(it, '_U2', 'jx', '_H', c);

  // R = S2 - jy
  cFieldSub(it, '_S2', 'jy', '_R', c);

  if (keepHR) {
    it.copyToTop('_H', '_H_keep');
    it.copyToTop('_R', '_R_keep');
  }

  it.copyToTop('_H', '_H_for_h3');
  it.copyToTop('_H', '_H_for_z3');

  // H2 = H^2
  cFieldSqr(it, '_H', '_H2', c);

  it.copyToTop('_H2', '_H2_for_u1h2');

  // H3 = H_for_h3 * H2
  cFieldMul(it, '_H_for_h3', '_H2', '_H3', c);

  // U1H2 = _jx_for_u1h2 * H2_for_u1h2
  cFieldMul(it, '_jx_for_u1h2', '_H2_for_u1h2', '_U1H2', c);

  it.copyToTop('_R', '_R_for_y3');
  it.copyToTop('_U1H2', '_U1H2_for_y3');
  it.copyToTop('_H3', '_H3_for_y3');

  // X3 = R^2 - H3 - 2*U1H2
  cFieldSqr(it, '_R', '_R2', c);
  cFieldSub(it, '_R2', '_H3', '_x3_tmp', c);
  cFieldMulConst(it, '_U1H2', 2n, '_2U1H2', c);
  cFieldSub(it, '_x3_tmp', '_2U1H2', '_X3', c);

  // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
  it.copyToTop('_X3', '_X3_c');
  cFieldSub(it, '_U1H2_for_y3', '_X3_c', '_u_minus_x', c);
  cFieldMul(it, '_R_for_y3', '_u_minus_x', '_r_tmp', c);
  cFieldMul(it, '_jy_for_y3', '_H3_for_y3', '_jy_h3', c);
  cFieldSub(it, '_r_tmp', '_jy_h3', '_Y3', c);

  // Z3 = _jz_for_z3 * _H_for_z3
  cFieldMul(it, '_jz_for_z3', '_H_for_z3', '_Z3', c);

  it.toTop('_X3'); it.rename('jx');
  it.toTop('_Y3'); it.rename('jy');
  it.toTop('_Z3'); it.rename('jz');
}

/**
 * Branchless select of one Jacobian coordinate: `add + cond*(dbl - add)`.
 * Consumes addName, dblName and condName.
 */
function cSelectCoord(
  t: ECTracker, addName: string, dblName: string, condName: string, resultName: string, c: CurveParams,
): void {
  t.copyToTop(addName, '_sel_add_c');
  cFieldSub(t, dblName, '_sel_add_c', '_sel_diff', c);
  cFieldMul(t, '_sel_diff', condName, '_sel_scaled', c);
  cFieldAdd(t, addName, '_sel_scaled', resultName, c);
}

/**
 * The ladder's LAST conditional step: mixed-add, but correct when the
 * accumulator already equals the point being added.
 *
 * The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the
 * two operands are the same curve point H = 0, so Z3 = Z1*H = 0 — the point at
 * infinity — and since cFieldInv is Fermat (inv(0) = 0), cJacobianToAffine
 * turns that into the ALL-ZERO point instead of 2P. `p256Mul(P, 2n)` and
 * `p384Mul(P, 2n)` returned 64 / 96 zero bytes.
 *
 * WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
 * c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
 * (c_i - 1)*P. P-256 and P-384 both have cofactor 1, so P has order n and the
 * degenerate cases are exactly c_i ≡ 2 (mod n) — accumulator == P — and
 * c_i ≡ 0 or 1 (mod n) — accumulator == -P or O. c_i ranges over a CONTIGUOUS
 * interval determined only by i, so this is decidable by interval arithmetic
 * rather than by sampling, and over the whole domain k ∈ [0, n-1] only two
 * steps qualify, both at i = 0:
 *
 *   k = 2  ->  c_0 = 3n+2 ≡ 2, odd, so the add runs: accumulator == P.  <- bug
 *   k = 0  ->  c_0 = 3n   ≡ 0, odd, so the add runs: accumulator == -P,
 *              true result the point at infinity, which affine coordinates
 *              cannot represent; it stays the all-zero point, as before.
 *
 * At i ≥ 1, c_i lies in [3n>>i, (4n-1)>>i] — the lower bound is 3n, not 3n+1,
 * because the reduce puts k = 0 in the domain.
 *
 * Handling H == 0 at every step would cost ~75% more script bytes — on P-384
 * that is another 600 KB; handling it here costs ~0.2%. The operand P is
 * caller-supplied but cannot move the exception, because the condition depends
 * only on c_i mod ord(P) and ord(P) = n for every point on these curves.
 * Points that are NOT on the curve carry no such guarantee — gate untrusted
 * input on `p256OnCurve` / `p384OnCurve` first. `decompressPubKey` now enforces
 * that itself for the one in-tree caller that takes a pubkey as input.
 *
 * THE ENTIRE ARGUMENT IS CONDITIONED ON k ∈ [0, n-1], which is only true
 * because cEmitMul reduces k mod n before adding 3n. That reduce landed one
 * commit AFTER this select (03f50d48 then f16790a9). 03f50d48 ON ITS OWN IS
 * UNSOUND: a last-step-only select while the scalar is still unbounded leaves
 * c_i free to hit 0, 1 or 2 (mod n) at other steps. The two commits must land
 * together and must never be bisected, cherry-picked or reverted apart.
 *
 * The interval argument does 100% of the work; there is no defence in depth
 * here. In particular c_i ≡ 1 (mod n) — a pre-add accumulator of O — is
 * UNREACHABLE, not handled: were it reachable the select would still take the
 * ADD path, because O is carried as Z1 = 0, which makes U2 = 0 and
 * H = -X1 != 0. Anything that changes the +3n offset, the iteration count or
 * the reduce must redo the interval check, not assume this still holds.
 *
 * Stack layout: [..., ax, ay, _k, jx, jy, jz] — same in and out.
 */
function buildJacobianAddOrDoubleInline(e: (op: StackOp) => void, t: ECTracker, c: CurveParams): void {
  const it = new ECTracker([...t.nm], e, t.options, [...t.dm]);

  // Keep the pre-add accumulator: it is what must be DOUBLED in the
  // exceptional case, and the add below consumes jx/jy/jz.
  it.copyToTop('jx', '_sx');
  it.copyToTop('jy', '_sy');
  it.copyToTop('jz', '_sz');

  jacobianAddAffineBody(it, true, c);

  // cond = (H == 0) AND (R == 0). Requiring R == 0 too keeps the
  // accumulator == -P case (k = 0) on the add path, where Z3 = 0 correctly
  // signals the point at infinity.
  it.toTop('_H_keep');
  it.pushInt('_zero_h', 0n);
  it.rawBlock(['_H_keep', '_zero_h'], '_h_is0', (e2) => {
    e2({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  it.toTop('_R_keep');
  it.pushInt('_zero_r', 0n);
  it.rawBlock(['_R_keep', '_zero_r'], '_r_is0', (e2) => {
    e2({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  it.toTop('_h_is0');
  it.toTop('_r_is0');
  it.rawBlock(['_h_is0', '_r_is0'], '_cond', (e2) => {
    e2({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  // Move the add result aside so cJacobianDouble can work on jx/jy/jz again,
  // this time holding the saved accumulator.
  it.toTop('jx'); it.rename('_add_x');
  it.toTop('jy'); it.rename('_add_y');
  it.toTop('jz'); it.rename('_add_z');
  it.toTop('_sx'); it.rename('jx');
  it.toTop('_sy'); it.rename('jy');
  it.toTop('_sz'); it.rename('jz');
  cJacobianDouble(it, c);
  it.toTop('jx'); it.rename('_dbl_x');
  it.toTop('jy'); it.rename('_dbl_y');
  it.toTop('jz'); it.rename('_dbl_z');

  it.copyToTop('_cond', '_cond_x');
  cSelectCoord(it, '_add_x', '_dbl_x', '_cond_x', 'jx', c);
  it.copyToTop('_cond', '_cond_y');
  cSelectCoord(it, '_add_y', '_dbl_y', '_cond_y', 'jy', c);
  it.toTop('_cond'); it.rename('_cond_z');
  cSelectCoord(it, '_add_z', '_dbl_z', '_cond_z', 'jz', c);
}

// ===========================================================================
// Scalar multiplication (generic for both P-256 and P-384)
// ===========================================================================

/**
 * Emit scalar multiplication: point * scalar.
 * Stack in: [point, scalar] (scalar on top).
 * Stack out: [result_point].
 *
 * Uses MSB-first double-and-add with Jacobian coordinates.
 * Adds 3*n to scalar to guarantee the top bit position, avoiding
 * the need for infinity-point handling.
 */
function cEmitMul(
  emit: (op: StackOp) => void,
  c: CurveParams,
  g: GroupParams,
  opts?: EcCodegenOptions,
): void {
  const t = new ECTracker(['_pt', '_k'], emit, opts);
  t.poolConstant(POOL_FIELD_P, c.fieldP);
  t.poolConstant(POOL_GROUP_N, g.n);
  cDecomposePoint(t, '_pt', 'ax', 'ay', c);

  // k' = k + 3n: guarantees a fixed high bit for MSB-first double-and-add.
  // For P-256: k ∈ [1, n-1], k+3n ∈ [3n+1, 4n-1], 3n > 2^257, so bit 257 is set.
  //   Run 258 iterations (bit 257 down to 0).
  // For P-384: k ∈ [1, n-1], k+3n ∈ [3n+1, 4n-1], 3n > 2^384, so bit 385 is set.
  //   Run 386 iterations (bit 385 down to 0).
  //
  // That "k ∈ [1, n-1]" is a PRECONDITION the caller cannot enforce: the
  // scalar is usually an unlock argument. Reduce it here — see cEmitScalarReduce.
  t.toTop('_k');
  cEmitScalarReduce(t, '_k', '_kr', g);
  t.pushInt('_n', g.n);
  t.rawBlock(['_kr', '_n'], '_kn', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.pushInt('_n2', g.n);
  t.rawBlock(['_kn', '_n2'], '_kn2', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.pushInt('_n3', g.n);
  t.rawBlock(['_kn2', '_n3'], '_kn3', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.rename('_k');

  // Determine iteration count based on 3*n bit length
  const threeN = 3n * g.n;
  const topBit = bitLength(threeN + g.n); // max value is 4n-1
  const startBit = topBit - 2; // highest bit is always 1 (init), start from next

  // Init accumulator = P (top bit of k+3n is always 1)
  t.copyToTop('ax', 'jx');
  t.copyToTop('ay', 'jy');
  t.pushInt('jz', 1n);

  // Iterate from startBit down to 0
  for (let bit = startBit; bit >= 0; bit--) {
    cJacobianDouble(t, c);

    // Extract bit: (k >> bit) & 1
    t.copyToTop('_k', '_k_copy');
    if (bit === 1) {
      t.rawBlock(['_k_copy'], '_shifted', (e) => {
        e({ op: 'opcode', code: 'OP_2DIV' });
      });
    } else if (bit > 1) {
      t.pushInt('_shift', BigInt(bit));
      t.rawBlock(['_k_copy', '_shift'], '_shifted', (e) => {
        e({ op: 'opcode', code: 'OP_RSHIFTNUM' });
      });
    } else {
      t.rename('_shifted');
    }
    t.pushInt('_two', 2n);
    t.rawBlock(['_shifted', '_two'], '_bit', (e) => {
      e({ op: 'opcode', code: 'OP_MOD' });
    });

    // Conditional add
    t.toTop('_bit');
    t.popTracked(); // _bit consumed by IF
    const addOps: StackOp[] = [];
    const addEmit = (op: StackOp) => addOps.push(op);
    // Only the final step can be handed two equal operands — see
    // buildJacobianAddOrDoubleInline for why, and for what it costs not to.
    if (bit === 0) buildJacobianAddOrDoubleInline(addEmit, t, c);
    else buildJacobianAddAffineInline(addEmit, t, c);
    emit({ op: 'if', then: addOps, else: [] });
  }

  cJacobianToAffine(t, '_rx', '_ry', c);

  // Clean up
  t.toTop('ax'); t.drop();
  t.toTop('ay'); t.drop();
  t.toTop('_k'); t.drop();

  cComposePoint(t, '_rx', '_ry', '_result', c);
  t.releaseConstant(POOL_GROUP_N);
  t.releaseConstant(POOL_FIELD_P);
}

// ===========================================================================
// Pubkey decompression (prefix byte + x → (x, y))
// ===========================================================================

/**
 * Square-and-multiply: base^exp mod fieldP.
 * Used for sqrt computation: y = (y^2)^((p+1)/4) mod p.
 */
function cFieldPow(t: ECTracker, baseName: string, exp: bigint, resultName: string, c: CurveParams): void {
  const bits = bitLength(exp);

  // Start: result = base (highest bit = 1)
  t.copyToTop(baseName, '_pow_r');

  for (let i = bits - 2; i >= 0; i--) {
    cFieldSqr(t, '_pow_r', '_pow_sq', c);
    t.rename('_pow_r');
    if ((exp >> BigInt(i)) & 1n) {
      t.copyToTop(baseName, '_pow_b');
      cFieldMul(t, '_pow_r', '_pow_b', '_pow_m', c);
      t.rename('_pow_r');
    }
  }

  t.toTop(baseName); t.drop();
  t.toTop('_pow_r'); t.rename(resultName);
}

/**
 * Decompress a compressed pubkey: [prefix||x] → (x_num, y_num, valid).
 *
 * For P-256/P-384 where a = -3:
 *   y^2 = x^3 - 3x + b mod p
 *   y = (y^2)^((p+1)/4) mod p
 *   Select y or p-y based on prefix parity.
 *
 * `(y^2)^((p+1)/4)` is a square root ONLY when y^2 is a quadratic residue; both
 * primes are ≡ 3 (mod 4), so for a non-residue it returns a square root of
 * -y^2 instead and the recovered point is NOT on the curve. Nor is x checked
 * against p: `cDecomposePoint`-style BIN2NUM accepts any width-fitting value
 * and every field op silently reduces it, so a non-canonical x decompresses
 * happily too.
 *
 * Both matter because the only consumer is `cEmitVerifyECDSA`, which feeds the
 * result straight into `cEmitMul`. That ladder's exception analysis (see
 * buildJacobianAddOrDoubleInline) is stated for points ON the curve, where
 * cofactor 1 pins ord(P) = n; an off-curve point lands on the twist, whose
 * order is composite, so the degenerate steps the interval argument rules out
 * become reachable. The pubkey is a caller-supplied unlock argument.
 *
 * So this emits a third output, `_dk_valid` = (x < p) AND (y_cand^2 == y^2)
 * AND (prefix ∈ {0x02, 0x03}), which the caller ANDs into the verifier's
 * boolean result. A flag, not an OP_VERIFY: `verifyECDSA_*` is a total
 * boolean-valued builtin and turning attacker-chosen bytes into a script abort
 * would be a liveness regression — the same argument cEmitScalarReduce makes
 * for reducing rather than rejecting.
 */
function decompressPubKey(
  t: ECTracker,
  pkName: string,
  qxName: string,
  qyName: string,
  c: CurveParams,
  curveB: bigint,
  sqrtExp: bigint,
): void {
  t.toTop(pkName);

  // Split: [prefix_byte, x_bytes]
  t.rawBlock([pkName], null, (e) => {
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
  });
  t.pushTracked('_dk_prefix');
  t.pushTracked('_dk_xbytes');

  // SEC1 §2.3.4 requires the prefix to be exactly 0x02 or 0x03. The parity
  // reduction below is `BIN2NUM, 2 MOD`, which accepts far more than that:
  // 0x00 / 0x04 / 0x82 all alias to "even", and 0x83 is worse than an alias —
  // BIN2NUM(0x83) = -3 (sign-magnitude), -3 mod 2 = -1, which encodes as 0x81
  // and can never equal `_dk_y_par` ∈ {<>, 0x01}, so the select silently
  // returns the OTHER square root. Test the byte itself.
  t.copyToTop('_dk_prefix', '_dk_pfx_in');
  t.rawBlock(['_dk_pfx_in'], '_dk_pfx_ok', (e) => {
    e({ op: 'dup' });
    e({ op: 'push', value: new Uint8Array([0x02]) });
    e({ op: 'opcode', code: 'OP_EQUAL' });
    e({ op: 'swap' });
    e({ op: 'push', value: new Uint8Array([0x03]) });
    e({ op: 'opcode', code: 'OP_EQUAL' });
    e({ op: 'opcode', code: 'OP_BOOLOR' });
  });

  // Convert prefix to parity: 0x02 → 0, 0x03 → 1
  t.toTop('_dk_prefix');
  t.rawBlock(['_dk_prefix'], '_dk_parity', (e) => {
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
    e({ op: 'push', value: 2n });
    e({ op: 'opcode', code: 'OP_MOD' });
  });

  // Stash parity on altstack so it doesn't interfere
  t.toTop('_dk_parity');
  t.toAlt();

  // Convert x_bytes to number
  t.toTop('_dk_xbytes');
  t.rawBlock(['_dk_xbytes'], '_dk_x', (e) => {
    c.reverseBytes(e);
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
  });

  // Save x for later (we need it as the output qx)
  t.copyToTop('_dk_x', '_dk_x_save');

  // Compute y^2 = x^3 - 3x + b mod p
  // x^2
  t.copyToTop('_dk_x', '_dk_x_c1');
  cFieldSqr(t, '_dk_x', '_dk_x2', c);
  // x^3 = x^2 * x
  cFieldMul(t, '_dk_x2', '_dk_x_c1', '_dk_x3', c);
  // 3 * x_save
  t.copyToTop('_dk_x_save', '_dk_x_for_3');
  cFieldMulConst(t, '_dk_x_for_3', 3n, '_dk_3x', c);
  // x^3 - 3x
  cFieldSub(t, '_dk_x3', '_dk_3x', '_dk_x3m3x', c);
  // + b
  t.pushInt('_dk_b', curveB);
  cFieldAdd(t, '_dk_x3m3x', '_dk_b', '_dk_y2', c);

  // y = (y^2)^sqrtExp mod p. cFieldPow CONSUMES its base, so keep a copy of
  // y^2 for the residue check at the end. It has to sit BELOW _dk_y_cand: the
  // parity select below is an OP_IF whose branches are a bare drop / nip, so
  // nothing may come between _dk_y_cand and the negated candidate.
  t.copyToTop('_dk_y2', '_dk_y2_keep');
  cFieldPow(t, '_dk_y2', sqrtExp, '_dk_y_cand', c);

  // Check if candidate y has the right parity
  t.copyToTop('_dk_y_cand', '_dk_y_check');
  t.rawBlock(['_dk_y_check'], '_dk_y_par', (e) => {
    e({ op: 'push', value: 2n });
    e({ op: 'opcode', code: 'OP_MOD' });
  });

  // Retrieve parity from altstack
  t.fromAlt('_dk_parity');

  // Compare: _dk_y_par == _dk_parity?
  t.toTop('_dk_y_par');
  t.toTop('_dk_parity');
  t.rawBlock(['_dk_y_par', '_dk_parity'], '_dk_match', (e) => {
    e({ op: 'opcode', code: 'OP_EQUAL' });
  });

  // If parities match: keep y_cand. Else: p - y_cand.
  // We'll compute p - y_cand first, then select.
  t.copyToTop('_dk_y_cand', '_dk_y_for_neg');
  pushFieldP(t, '_dk_pfn', c);
  t.toTop('_dk_y_for_neg');
  t.rawBlock(['_dk_pfn', '_dk_y_for_neg'], '_dk_neg_y', (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
  });

  // Stack: [..., _dk_x_save, _dk_y_cand, _dk_match, _dk_neg_y]
  // Use OP_IF to select: if match, use y_cand (drop neg_y), else use neg_y (drop y_cand)
  // First, bring match to top for the IF
  t.toTop('_dk_match');
  t.popTracked(); // condition consumed by IF

  // After IF consumes _dk_match, stack is: [..., _dk_x_save, _dk_y_cand, _dk_neg_y]
  // Then branch (match): we want y_cand → drop neg_y (TOS)
  // Else branch (no match): we want neg_y → nip out y_cand
  const thenOps: StackOp[] = [];
  const elseOps: StackOp[] = [];
  thenOps.push({ op: 'drop' }); // remove neg_y, leaving y_cand
  elseOps.push({ op: 'nip' }); // remove y_cand, leaving neg_y
  t._e({ op: 'if', then: thenOps, else: elseOps });

  // Tracker still has both _dk_y_cand and _dk_neg_y; one was consumed.
  // Remove one and rename the remaining to qyName.
  const negIdx = t.nm.lastIndexOf('_dk_neg_y');
  if (negIdx >= 0) t.removeSlotAt(negIdx);
  // The surviving item is _dk_y_cand — rename it
  const ycIdx = t.nm.lastIndexOf('_dk_y_cand');
  if (ycIdx >= 0) t.nm[ycIdx] = qyName;

  // Rename saved x to qxName
  const xsIdx = t.nm.lastIndexOf('_dk_x_save');
  if (xsIdx >= 0) t.nm[xsIdx] = qxName;

  // valid = (qy^2 == y^2) AND (qx < p) AND (prefix ∈ {0x02, 0x03}).
  // The selected qy is y_cand or p - y_cand, so squaring it tests the same
  // residue property either way. The first conjunct rejects an x whose RHS is a
  // quadratic non-residue — the recovered point is then off the curve; the
  // second rejects a non-canonical encoding of an otherwise fine x; the third
  // rejects a prefix byte the parity reduction would otherwise alias or, for
  // 0x83, silently invert.
  t.copyToTop(qyName, '_dk_y_sq_in');
  cFieldSqr(t, '_dk_y_sq_in', '_dk_y_sq', c);
  t.toTop('_dk_y_sq');
  t.toTop('_dk_y2_keep');
  t.rawBlock(['_dk_y_sq', '_dk_y2_keep'], '_dk_res_ok', (e) => {
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  t.copyToTop(qxName, '_dk_x_lt');
  pushFieldP(t, '_dk_p_lt', c);
  t.rawBlock(['_dk_x_lt', '_dk_p_lt'], '_dk_x_ok', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.toTop('_dk_res_ok');
  t.toTop('_dk_x_ok');
  t.rawBlock(['_dk_res_ok', '_dk_x_ok'], '_dk_curve_ok', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
  t.toTop('_dk_pfx_ok');
  t.rawBlock(['_dk_curve_ok', '_dk_pfx_ok'], '_dk_valid', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
}

// ===========================================================================
// ECDSA verification
// ===========================================================================

/**
 * Length gate for an untrusted byte argument: leaves `[flag, clamped]`.
 *
 * `flag` is `OP_SIZE(v) == want`; `clamped` is `v` forced to exactly `want`
 * bytes by `v ‖ 00*want`, split at `want`, tail dropped — truncating a long
 * value and zero-extending a short one.
 *
 * The clamp exists so the gate can stay a FLAG. Everything downstream peels a
 * fixed number of bytes (`OP_SPLIT coordBytes`, then 32/48 single-byte splits
 * inside emitReverse32/48); handed 32 <= len(sig) < 64 the reversal runs out of
 * bytes mid-loop and the SCRIPT ABORTS, which would make
 * `verifyECDSA_P256(...) || fallback` unwritable and contradict this module's
 * own totality rule (see decompressPubKey). Clamping first makes every path
 * total; the caller ANDs `flag` into the result so a wrong-length argument can
 * never verify whatever the clamped bytes computed.
 *
 * Branch-free on purpose: the tracker's static stack model, and the emitted op
 * sequence, are the same for every input length — the argument cAffineAdd makes
 * for selecting operands instead of branching.
 */
function cEmitLengthGate(t: ECTracker, name: string, want: number, flagName: string): void {
  t.toTop(name);
  t.rawBlock([name], null, (e) => {
    e({ op: 'opcode', code: 'OP_SIZE' });
    e({ op: 'push', value: BigInt(want) });
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
    e({ op: 'swap' });
    e({ op: 'push', value: new Uint8Array(want) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'push', value: BigInt(want) });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'drop' });
  });
  t.pushTracked(flagName);
  t.pushTracked(name);
}

/**
 * SEC1 §4.1.4 step 1 / FIPS 186-5 §6.4.2: verify 1 <= r <= n-1 and
 * 1 <= s <= n-1. Consumes nothing, leaves `_range_ok` above `_r` and `_s`.
 *
 * ==> THIS IS A UNIVERSAL FORGERY GUARD, NOT A HYGIENE CHECK. <==
 *
 * Nothing checked r or s at all, and `cGroupInv` is Fermat (a^(n-2) mod n), so
 * inv(0) = 0 instead of an error. With `sig = 0x00…` and the contract's own
 * genuine, PUBLIC key:
 *
 *   r = s = 0            (BIN2NUM of coordBytes zero bytes -> empty vector)
 *   w = s^(n-2) = 0      Fermat, no failure channel
 *   u1 = u2 = 0          every cGroupMul in the ladder is 0*0 mod n
 *   R1 = R2 = O          cEmitMul reduces 0, k' = 3n = 0 mod n, so Z3 = 0 and
 *                        cJacobianToAffine's Fermat inverse turns it all-zero
 *   R1 + R2              cAffineAdd sees xeq = yeq = 1, takes the tangent with
 *                        den = 2*0 = 0, so s = 0 and rx = ry = 0
 *   (R.x mod n) == r     OP_EQUAL(<>, <>) = 1
 *
 * ...and `_dk_valid` is 1 because the pubkey is genuine. TRUE. No secret, no
 * off-curve point, not bound to the message: an all-zero signature verified for
 * ANY message under ANY public key. `examples/ts/p256-wallet` made exactly that
 * call its second authentication factor.
 *
 * BOTH conjuncts are load-bearing and neither is redundant:
 *   - s = 0 (or s = n, which Fermat also inverts to 0) is what collapses both
 *     ladders to O;
 *   - r = 0 is what makes the final OP_EQUAL compare the resulting 0 against
 *     something that is also 0.
 * `r = 0, s = n` is a second spelling of the same forgery that an `s != 0`
 * check alone would miss, which is why the bound is `< n` and not `!= 0`.
 *
 * A flag rather than an OP_VERIFY, for the reason decompressPubKey gives.
 */
function cEmitSigRangeGate(t: ECTracker, g: GroupParams): void {
  t.copyToTop('_r', '_r_nz_in');
  t.rawBlock(['_r_nz_in'], '_r_nz', (e) => {
    e({ op: 'opcode', code: 'OP_0NOTEQUAL' });
  });
  t.copyToTop('_r', '_r_lt_in');
  pushGroupN(t, '_n_for_r', g);
  t.rawBlock(['_r_lt_in', '_n_for_r'], '_r_lt', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.rawBlock(['_r_nz', '_r_lt'], '_r_ok', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  t.copyToTop('_s', '_s_nz_in');
  t.rawBlock(['_s_nz_in'], '_s_nz', (e) => {
    e({ op: 'opcode', code: 'OP_0NOTEQUAL' });
  });
  t.copyToTop('_s', '_s_lt_in');
  pushGroupN(t, '_n_for_s', g);
  t.rawBlock(['_s_lt_in', '_n_for_s'], '_s_lt', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.rawBlock(['_s_nz', '_s_lt'], '_s_ok', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  t.rawBlock(['_r_ok', '_s_ok'], '_range_ok', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
}

/**
 * Verify ECDSA signature on P-256 or P-384.
 *
 * Stack in: [msg_bytes, sig_bytes, pubkey_compressed] (pubkey on top)
 * Stack out: [boolean (OP_TRUE or OP_FALSE)]
 *
 * Algorithm:
 *   1. e = SHA-256(msg) as integer
 *   2. Parse sig into (r, s) integers
 *   3. Decompress pubkey into (Qx, Qy)
 *   4. w = s^{-1} mod n
 *   5. u1 = e * w mod n
 *   6. u2 = r * w mod n
 *   7. R = u1*G + u2*Q
 *   8. result = (R.x mod n) == r
 */
function cEmitVerifyECDSA(
  emit: (op: StackOp) => void,
  c: CurveParams,
  g: GroupParams,
  curveB: bigint,
  sqrtExp: bigint,
  gx: bigint,
  gy: bigint,
  opts?: EcCodegenOptions,
): void {
  const t = new ECTracker(['_msg', '_sig', '_pk'], emit, opts);
  // The verifier does hundreds of reductions OUTSIDE the two ladders —
  // decompression's sqrt ladder, cGroupInv, cAffineAdd, the final cGroupMod.
  // Each ladder pools separately: cEmitMul runs on its own tracker that
  // deliberately cannot see this stack, so it cannot reach this slot.
  t.poolConstant(POOL_FIELD_P, c.fieldP);
  t.poolConstant(POOL_GROUP_N, g.n);

  // Step 0: length gate. `_sig` and `_pk` are bare ByteString in the builtin
  // table and the type checker imposes no width, so both arrive attacker-sized.
  // Clamp them and remember whether they were the right size — see
  // cEmitLengthGate for why a clamp and not an abort. Without it `sig ‖ junk`
  // verified identically to `sig` (fatal for any contract using signature bytes
  // as a nullifier), and a short `sig` aborted the script outright.
  cEmitLengthGate(t, '_pk', c.coordBytes + 1, '_pk_len_ok');
  cEmitLengthGate(t, '_sig', c.coordBytes * 2, '_sig_len_ok');
  t.toTop('_pk_len_ok');
  t.toTop('_sig_len_ok');
  t.rawBlock(['_pk_len_ok', '_sig_len_ok'], '_len_ok', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  // Step 1: e = SHA-256(msg) as integer
  t.toTop('_msg');
  t.rawBlock(['_msg'], '_e', (e) => {
    e({ op: 'opcode', code: 'OP_SHA256' });
    // SHA-256 produces 32 bytes BE. Convert to integer:
    emitReverse32(e);
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
  });

  // Step 2: Parse sig into (r, s)
  t.toTop('_sig');
  t.rawBlock(['_sig'], null, (e) => {
    e({ op: 'push', value: BigInt(c.coordBytes) });
    e({ op: 'opcode', code: 'OP_SPLIT' });
  });
  t.pushTracked('_r_bytes');
  t.pushTracked('_s_bytes');

  // Convert r_bytes to integer
  t.toTop('_r_bytes');
  t.rawBlock(['_r_bytes'], '_r', (e) => {
    c.reverseBytes(e);
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
  });

  // Convert s_bytes to integer
  t.toTop('_s_bytes');
  t.rawBlock(['_s_bytes'], '_s', (e) => {
    c.reverseBytes(e);
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
  });

  // Step 2b: 1 <= r, s <= n-1. Without this an all-zero signature verifies for
  // any message under any pubkey — see cEmitSigRangeGate.
  cEmitSigRangeGate(t, g);

  // Step 3: Decompress pubkey. Also yields `_dk_valid`: 0 when the pubkey
  // bytes do not decompress to a canonical on-curve point, which is ANDed into
  // the result below so such a key can never verify.
  decompressPubKey(t, '_pk', '_qx', '_qy', c, curveB, sqrtExp);

  // Collapse the three argument verdicts into one flag. Everything below then
  // carries a single item, as it did when `_dk_valid` was the only one.
  t.toTop('_len_ok');
  t.toTop('_range_ok');
  t.rawBlock(['_len_ok', '_range_ok'], '_arg_ok', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
  t.toTop('_dk_valid');
  t.rawBlock(['_arg_ok', '_dk_valid'], '_input_ok', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  // Step 4: w = s^{-1} mod n
  cGroupInv(t, '_s', '_w', g);

  // Step 5: u1 = e * w mod n
  t.copyToTop('_w', '_w_c1');
  cGroupMul(t, '_e', '_w_c1', '_u1', g);

  // Step 6: u2 = r * w mod n
  t.copyToTop('_r', '_r_save');
  cGroupMul(t, '_r', '_w', '_u2', g);

  // Step 7: R = u1*G + u2*Q
  // First: u1*G
  // Push generator point
  const pointBytes = c.coordBytes * 2;
  const gPointData = new Uint8Array(pointBytes);
  gPointData.set(bigintToBytes(gx, c.coordBytes), 0);
  gPointData.set(bigintToBytes(gy, c.coordBytes), c.coordBytes);

  t.pushBytes('_G', gPointData);
  t.toTop('_u1');

  // Stash items we need later on altstack so cEmitMul sees only [_G, _u1].
  // _input_ok goes DEEPEST — the altstack is LIFO and it is popped last.
  t.toTop('_input_ok'); t.toAlt();
  t.toTop('_r_save'); t.toAlt();
  t.toTop('_u2'); t.toAlt();
  t.toTop('_qy'); t.toAlt();
  t.toTop('_qx'); t.toAlt();

  // cEmitMul creates its own ECTracker with ['_pt', '_k'] — items below
  // the top two are invisible to it. Remove _G and _u1 from our tracker.
  t.popTracked(); // _u1
  t.popTracked(); // _G

  // Emit the mul (it manages its own tracker internally)
  cEmitMul(emit, c, g, opts);

  // After mul, one result point is on the stack
  t.pushTracked('_R1_point');

  // Altstack (top→bottom): _qx, _qy, _u2, _r_save
  // Pop qx/qy/u2 FIRST while _qx is still altstack top (LIFO order)
  t.fromAlt('_qx');
  t.fromAlt('_qy');
  t.fromAlt('_u2');

  // Now stash R1 point (altstack now has only _r_save)
  t.toTop('_R1_point'); t.toAlt();

  // Compose Q point from qx/qy
  cComposePoint(t, '_qx', '_qy', '_Q_point', c);

  t.toTop('_u2');
  // Stack: [..., _Q_point, _u2]

  // Pop from tracker, emit mul, push result
  t.popTracked(); // _u2
  t.popTracked(); // _Q_point
  cEmitMul(emit, c, g, opts);
  t.pushTracked('_R2_point');

  // Restore R1 point
  t.fromAlt('_R1_point');

  // Stack: [..., _R2_point, _R1_point]
  // emitAdd expects [point_a, point_b] with b on top
  // We want R1 + R2. Let's swap so R2 is on top (doesn't matter for add, but be consistent)
  t.swap();

  // Now: [..., _R1_point, _R2_point]
  // Decompose both, add, compose
  cDecomposePoint(t, '_R1_point', '_rpx', '_rpy', c);
  cDecomposePoint(t, '_R2_point', '_rqx', '_rqy', c);
  // Rename to what cAffineAdd expects
  const rpxIdx = t.nm.lastIndexOf('_rpx');
  if (rpxIdx >= 0) t.nm[rpxIdx] = 'px';
  const rpyIdx = t.nm.lastIndexOf('_rpy');
  if (rpyIdx >= 0) t.nm[rpyIdx] = 'py';
  const rqxIdx = t.nm.lastIndexOf('_rqx');
  if (rqxIdx >= 0) t.nm[rqxIdx] = 'qx';
  const rqyIdx = t.nm.lastIndexOf('_rqy');
  if (rqyIdx >= 0) t.nm[rqyIdx] = 'qy';

  cAffineAdd(t, c);
  // Produces rx, ry on tracker

  // Step 8: x_R mod n == r
  // We only need rx (drop ry)
  t.toTop('ry'); t.drop();

  // Reduce rx mod n
  cGroupMod(t, 'rx', '_rx_mod_n', g);

  // Restore r, then the argument verdict beneath it
  t.fromAlt('_r_save');
  t.fromAlt('_input_ok');

  // Compare
  t.toTop('_rx_mod_n');
  t.toTop('_r_save');
  t.rawBlock(['_rx_mod_n', '_r_save'], '_sig_ok', (e) => {
    e({ op: 'opcode', code: 'OP_EQUAL' });
  });

  // Arguments that were the wrong length, out of range, or did not decompress
  // to a canonical on-curve point can never verify, whatever the ladder made
  // of them.
  t.toTop('_input_ok');
  t.toTop('_sig_ok');
  t.rawBlock(['_input_ok', '_sig_ok'], '_result', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
  t.releaseConstant(POOL_GROUP_N);
  t.releaseConstant(POOL_FIELD_P);
}

// ===========================================================================
// P-256 public API
// ===========================================================================

/**
 * P-256 point addition.
 * Stack in: [P256Point, P256Point] (second on top)
 * Stack out: [P256Point]
 */
export function emitP256Add(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const t = new ECTracker(['_pa', '_pb'], emit, opts);
  t.poolConstant(POOL_FIELD_P, P256_PARAMS.fieldP);
  cDecomposePoint(t, '_pa', 'px', 'py', P256_PARAMS);
  cDecomposePoint(t, '_pb', 'qx', 'qy', P256_PARAMS);
  cAffineAdd(t, P256_PARAMS);
  cComposePoint(t, 'rx', 'ry', '_result', P256_PARAMS);
  t.releaseConstant(POOL_FIELD_P);
}

/**
 * P-256 scalar multiplication: point * scalar.
 * Stack in: [P256Point, bigint] (scalar on top)
 * Stack out: [P256Point]
 */
export function emitP256Mul(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  cEmitMul(emit, P256_PARAMS, P256_GROUP, opts);
}

/**
 * P-256 generator multiplication: G * scalar.
 * Stack in: [bigint]
 * Stack out: [P256Point]
 */
export function emitP256MulGen(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const gPoint = new Uint8Array(64);
  gPoint.set(bigintToBytes(P256_GX, 32), 0);
  gPoint.set(bigintToBytes(P256_GY, 32), 32);
  emit({ op: 'push', value: gPoint });
  emit({ op: 'swap' }); // [point, scalar]
  emitP256Mul(emit, opts);
}

/**
 * P-256 point negation.
 * Stack in: [P256Point]
 * Stack out: [P256Point]
 */
export function emitP256Negate(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const t = new ECTracker(['_pt'], emit, opts);
  t.poolConstant(POOL_FIELD_P, P256_PARAMS.fieldP);
  cDecomposePoint(t, '_pt', '_nx', '_ny', P256_PARAMS);
  pushFieldP(t, '_fp', P256_PARAMS);
  cFieldSub(t, '_fp', '_ny', '_neg_y', P256_PARAMS);
  cComposePoint(t, '_nx', '_neg_y', '_result', P256_PARAMS);
  t.releaseConstant(POOL_FIELD_P);
}

/**
 * P-256 on-curve check: y^2 == x^3 - 3x + b mod p.
 * Stack in: [P256Point]
 * Stack out: [boolean]
 */
export function emitP256OnCurve(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const t = new ECTracker(['_pt'], emit, opts);
  t.poolConstant(POOL_FIELD_P, P256_PARAMS.fieldP);
  cDecomposePoint(t, '_pt', '_x', '_y', P256_PARAMS);
  cEmitCanonicityGuard(t, '_x', '_y', P256_PARAMS);

  // lhs = y^2
  cFieldSqr(t, '_y', '_y2', P256_PARAMS);

  // rhs = x^3 - 3x + b
  t.copyToTop('_x', '_x_copy');
  t.copyToTop('_x', '_x_copy2');
  cFieldSqr(t, '_x', '_x2', P256_PARAMS);
  cFieldMul(t, '_x2', '_x_copy', '_x3', P256_PARAMS);
  cFieldMulConst(t, '_x_copy2', 3n, '_3x', P256_PARAMS);
  cFieldSub(t, '_x3', '_3x', '_x3m3x', P256_PARAMS);
  t.pushInt('_b', P256_B);
  cFieldAdd(t, '_x3m3x', '_b', '_rhs', P256_PARAMS);

  // Compare
  t.toTop('_y2');
  t.toTop('_rhs');
  t.rawBlock(['_y2', '_rhs'], '_curve_eq', (e) => {
    e({ op: 'opcode', code: 'OP_EQUAL' });
  });

  // on-curve = canonical AND curve-equation
  t.toTop('_canon');
  t.toTop('_curve_eq');
  t.rawBlock(['_canon', '_curve_eq'], '_result', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
  t.releaseConstant(POOL_FIELD_P);
}

/**
 * P-256 point compression.
 * Stack in: [P256Point (64 bytes)]
 * Stack out: [compressed (33 bytes)]
 */
export function emitP256EncodeCompressed(emit: (op: StackOp) => void): void {
  // Split at 32: [x_bytes, y_bytes]
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  // Get last byte of y for parity
  emit({ op: 'opcode', code: 'OP_SIZE' });
  emit({ op: 'push', value: 1n });
  emit({ op: 'opcode', code: 'OP_SUB' });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  // Stack: [x_bytes, y_prefix, last_byte]
  emit({ op: 'opcode', code: 'OP_BIN2NUM' });
  emit({ op: 'push', value: 2n });
  emit({ op: 'opcode', code: 'OP_MOD' });
  // Stack: [x_bytes, y_prefix, parity]
  emit({ op: 'swap' });
  emit({ op: 'drop' }); // drop y_prefix
  // Stack: [x_bytes, parity]
  emit({ op: 'if',
    then: [{ op: 'push', value: new Uint8Array([0x03]) }],
    else: [{ op: 'push', value: new Uint8Array([0x02]) }],
  });
  // Stack: [x_bytes, prefix_byte]
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_CAT' });
}

/**
 * P-256 ECDSA signature verification.
 * Stack in: [msg_bytes, sig(64B), pubkey(33B)] (pubkey on top)
 * Stack out: [boolean]
 */
export function emitVerifyECDSA_P256(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  cEmitVerifyECDSA(emit, P256_PARAMS, P256_GROUP, P256_B, P256_SQRT_EXP, P256_GX, P256_GY, opts);
}

// ===========================================================================
// P-384 public API
// ===========================================================================

/**
 * P-384 point addition.
 * Stack in: [P384Point, P384Point] (second on top)
 * Stack out: [P384Point]
 */
export function emitP384Add(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const t = new ECTracker(['_pa', '_pb'], emit, opts);
  t.poolConstant(POOL_FIELD_P, P384_PARAMS.fieldP);
  cDecomposePoint(t, '_pa', 'px', 'py', P384_PARAMS);
  cDecomposePoint(t, '_pb', 'qx', 'qy', P384_PARAMS);
  cAffineAdd(t, P384_PARAMS);
  cComposePoint(t, 'rx', 'ry', '_result', P384_PARAMS);
  t.releaseConstant(POOL_FIELD_P);
}

/**
 * P-384 scalar multiplication: point * scalar.
 * Stack in: [P384Point, bigint] (scalar on top)
 * Stack out: [P384Point]
 */
export function emitP384Mul(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  cEmitMul(emit, P384_PARAMS, P384_GROUP, opts);
}

/**
 * P-384 generator multiplication: G * scalar.
 * Stack in: [bigint]
 * Stack out: [P384Point]
 */
export function emitP384MulGen(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const gPoint = new Uint8Array(96);
  gPoint.set(bigintToBytes(P384_GX, 48), 0);
  gPoint.set(bigintToBytes(P384_GY, 48), 48);
  emit({ op: 'push', value: gPoint });
  emit({ op: 'swap' }); // [point, scalar]
  emitP384Mul(emit, opts);
}

/**
 * P-384 point negation.
 * Stack in: [P384Point]
 * Stack out: [P384Point]
 */
export function emitP384Negate(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const t = new ECTracker(['_pt'], emit, opts);
  t.poolConstant(POOL_FIELD_P, P384_PARAMS.fieldP);
  cDecomposePoint(t, '_pt', '_nx', '_ny', P384_PARAMS);
  pushFieldP(t, '_fp', P384_PARAMS);
  cFieldSub(t, '_fp', '_ny', '_neg_y', P384_PARAMS);
  cComposePoint(t, '_nx', '_neg_y', '_result', P384_PARAMS);
  t.releaseConstant(POOL_FIELD_P);
}

/**
 * P-384 on-curve check: y^2 == x^3 - 3x + b mod p.
 * Stack in: [P384Point]
 * Stack out: [boolean]
 */
export function emitP384OnCurve(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const t = new ECTracker(['_pt'], emit, opts);
  t.poolConstant(POOL_FIELD_P, P384_PARAMS.fieldP);
  cDecomposePoint(t, '_pt', '_x', '_y', P384_PARAMS);
  cEmitCanonicityGuard(t, '_x', '_y', P384_PARAMS);

  // lhs = y^2
  cFieldSqr(t, '_y', '_y2', P384_PARAMS);

  // rhs = x^3 - 3x + b
  t.copyToTop('_x', '_x_copy');
  t.copyToTop('_x', '_x_copy2');
  cFieldSqr(t, '_x', '_x2', P384_PARAMS);
  cFieldMul(t, '_x2', '_x_copy', '_x3', P384_PARAMS);
  cFieldMulConst(t, '_x_copy2', 3n, '_3x', P384_PARAMS);
  cFieldSub(t, '_x3', '_3x', '_x3m3x', P384_PARAMS);
  t.pushInt('_b', P384_B);
  cFieldAdd(t, '_x3m3x', '_b', '_rhs', P384_PARAMS);

  // Compare
  t.toTop('_y2');
  t.toTop('_rhs');
  t.rawBlock(['_y2', '_rhs'], '_curve_eq', (e) => {
    e({ op: 'opcode', code: 'OP_EQUAL' });
  });

  // on-curve = canonical AND curve-equation
  t.toTop('_canon');
  t.toTop('_curve_eq');
  t.rawBlock(['_canon', '_curve_eq'], '_result', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
  t.releaseConstant(POOL_FIELD_P);
}

/**
 * P-384 point compression.
 * Stack in: [P384Point (96 bytes)]
 * Stack out: [compressed (49 bytes)]
 */
export function emitP384EncodeCompressed(emit: (op: StackOp) => void): void {
  // Split at 48: [x_bytes, y_bytes]
  emit({ op: 'push', value: 48n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  // Get last byte of y for parity
  emit({ op: 'opcode', code: 'OP_SIZE' });
  emit({ op: 'push', value: 1n });
  emit({ op: 'opcode', code: 'OP_SUB' });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  // Stack: [x_bytes, y_prefix, last_byte]
  emit({ op: 'opcode', code: 'OP_BIN2NUM' });
  emit({ op: 'push', value: 2n });
  emit({ op: 'opcode', code: 'OP_MOD' });
  // Stack: [x_bytes, y_prefix, parity]
  emit({ op: 'swap' });
  emit({ op: 'drop' }); // drop y_prefix
  // Stack: [x_bytes, parity]
  emit({ op: 'if',
    then: [{ op: 'push', value: new Uint8Array([0x03]) }],
    else: [{ op: 'push', value: new Uint8Array([0x02]) }],
  });
  // Stack: [x_bytes, prefix_byte]
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_CAT' });
}

/**
 * P-384 ECDSA signature verification.
 * Stack in: [msg_bytes, sig(96B), pubkey(49B)] (pubkey on top)
 * Stack out: [boolean]
 */
export function emitVerifyECDSA_P384(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  cEmitVerifyECDSA(emit, P384_PARAMS, P384_GROUP, P384_B, P384_SQRT_EXP, P384_GX, P384_GY, opts);
}
