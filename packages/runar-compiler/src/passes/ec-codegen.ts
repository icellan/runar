/**
 * EC codegen — secp256k1 elliptic curve operations for Bitcoin Script.
 *
 * Follows the slh-dsa-codegen.ts pattern: self-contained module imported by
 * 05-stack-lower.ts. Uses an ECTracker (similar to SLHTracker) for named
 * stack state tracking.
 *
 * Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
 * Internal arithmetic uses Jacobian coordinates for scalar multiplication.
 */

import type { StackOp } from '../ir/index.js';
import { sizeOfPushValue } from '../metrics/cost-model.js';

// ===========================================================================
// Constants
// ===========================================================================

/** secp256k1 field prime p = 2^256 - 2^32 - 977 */
const FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
/** p - 2, used for Fermat's little theorem modular inverse */
const FIELD_P_MINUS_2 = FIELD_P - 2n;
/** secp256k1 curve order */
const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
/** secp256k1 generator x-coordinate */
const GEN_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
/** secp256k1 generator y-coordinate */
const GEN_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

function bigintToBytes32(n: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

// ===========================================================================
// ECTracker — named stack state tracker (mirrors SLHTracker)
// ===========================================================================

/**
 * Codegen options shared by every EC / NIST-curve emitter.
 *
 * Off by default: with no options (or `constantPool: false`) each emitter is
 * byte-identical to what the seven tiers ship today, so no golden, size
 * baseline, or cross-tier parity gate can move.
 */
export interface EcCodegenOptions {
  /**
   * Park large repeated constants (the field prime, the group order) in a
   * stack slot and copy them with `OP_PICK` instead of re-pushing the literal.
   *
   * `fieldMod` pushes the 256-bit prime at every modular reduction — 34 bytes
   * a time, 20,025 times in `p256-wallet` (71 % of that fixture). A pick from
   * a slot a dozen deep costs 2. See
   * `docs/experiments/script-size-optimization-baseline.md`.
   */
  constantPool?: boolean;
}

/** Stack slot names reserved for pooled constants. */
export const POOL_FIELD_P = '_pool$p';
export const POOL_GROUP_N = '_pool$n';

export class ECTracker {
  nm: (string | null)[];
  _e: (op: StackOp) => void;
  /** True when this tracker may serve constants from a pooled slot. */
  readonly pooling: boolean;

  constructor(
    init: (string | null)[],
    emit: (op: StackOp) => void,
    opts?: EcCodegenOptions,
  ) {
    this.nm = [...init];
    this._e = emit;
    this.pooling = opts?.constantPool === true;
  }

  /** The options this tracker was built with, for handing to a nested tracker. */
  get options(): EcCodegenOptions {
    return { constantPool: this.pooling };
  }

  get depth(): number { return this.nm.length; }

  findDepth(name: string): number {
    for (let i = this.nm.length - 1; i >= 0; i--)
      if (this.nm[i] === name)
        return this.nm.length - 1 - i;
    throw new Error(`ECTracker: '${name}' not on stack [${this.nm.join(',')}]`);
  }

  pushBytes(n: string, v: Uint8Array): void { this._e({ op: 'push', value: v }); this.nm.push(n); }
  pushInt(n: string, v: bigint): void { this._e({ op: 'push', value: v }); this.nm.push(n); }
  dup(n: string): void { this._e({ op: 'dup' }); this.nm.push(n); }
  drop(): void { this._e({ op: 'drop' }); this.nm.pop(); }
  nip(): void {
    this._e({ op: 'nip' });
    const L = this.nm.length;
    if (L >= 2) this.nm.splice(L - 2, 1);
  }
  over(n: string): void { this._e({ op: 'over' }); this.nm.push(n); }
  swap(): void {
    this._e({ op: 'swap' });
    const L = this.nm.length;
    if (L >= 2) {
      const t = this.nm[L - 1];
      this.nm[L - 1] = this.nm[L - 2]!;
      this.nm[L - 2] = t!;
    }
  }
  rot(): void {
    this._e({ op: 'rot' });
    const L = this.nm.length;
    if (L >= 3) {
      const r = this.nm.splice(L - 3, 1)[0]!;
      this.nm.push(r);
    }
  }
  op(code: string): void { this._e({ op: 'opcode', code }); }
  roll(d: number): void {
    if (d === 0) return;
    if (d === 1) { this.swap(); return; }
    if (d === 2) { this.rot(); return; }
    this._e({ op: 'push', value: BigInt(d) });
    this.nm.push(null);
    this._e({ op: 'roll', depth: d });
    this.nm.pop();
    const idx = this.nm.length - 1 - d;
    const r = this.nm.splice(idx, 1)[0] ?? null;
    this.nm.push(r);
  }
  pick(d: number, n: string): void {
    if (d === 0) { this.dup(n); return; }
    if (d === 1) { this.over(n); return; }
    this._e({ op: 'push', value: BigInt(d) });
    this.nm.push(null);
    this._e({ op: 'pick', depth: d });
    this.nm.pop();
    this.nm.push(n);
  }
  toTop(name: string): void { this.roll(this.findDepth(name)); }
  copyToTop(name: string, n?: string): void { this.pick(this.findDepth(name), n ?? name); }

  // -- constant pool --------------------------------------------------------
  //
  // A pooled constant is an ordinary tracked slot; nothing about the stack
  // model changes. `pushConst` just chooses, per call site and by emitted
  // bytes, between copying that slot and re-pushing the literal. Nested
  // trackers built with `[...t.nm]` inherit the slot for free, so pooled
  // constants work unchanged inside an `OP_IF` arm.

  /** Park `value` in `slot` for the lifetime of this emitter. No-op when pooling is off. */
  poolConstant(slot: string, value: bigint): void {
    if (!this.pooling || this.nm.includes(slot)) return;
    this.pushInt(slot, value);
  }

  /** Remove a pooled slot. No-op when pooling is off or the slot is absent. */
  releaseConstant(slot: string): void {
    if (!this.pooling || !this.nm.includes(slot)) return;
    this.toTop(slot);
    this.drop();
  }

  /**
   * Materialize `value` on top as `name`, from the pooled `slot` when that is
   * cheaper in emitted bytes than pushing the literal.
   *
   * The comparison is exact — `sizeOfPushValue` is the same encoder the emit
   * pass uses — so pooling can never make a call site bigger. A pick at depth
   * d costs `sizeOfPushValue(d) + 1`; depths 0 and 1 are OP_DUP / OP_OVER, 1
   * byte each.
   */
  pushConst(slot: string, value: bigint, name: string): void {
    if (this.pooling && this.nm.includes(slot)) {
      const d = this.findDepth(slot);
      const pickCost = d <= 1 ? 1 : sizeOfPushValue(BigInt(d)) + 1;
      if (pickCost < sizeOfPushValue(value)) {
        this.pick(d, name);
        return;
      }
    }
    this.pushInt(name, value);
  }
  toAlt(): void { this.op('OP_TOALTSTACK'); this.nm.pop(); }
  fromAlt(n: string): void { this.op('OP_FROMALTSTACK'); this.nm.push(n); }
  rename(n: string): void {
    if (this.nm.length > 0)
      this.nm[this.nm.length - 1] = n;
  }

  /** Emit raw opcodes tracking only net stack effect. */
  rawBlock(consume: string[], produce: string | null, fn: (e: (op: StackOp) => void) => void): void {
    for (let i = consume.length - 1; i >= 0; i--)
      this.nm.pop();
    fn(this._e);
    if (produce !== null)
      this.nm.push(produce);
  }

  /** Emit if/else with tracked stack effect. */
  emitIf(condName: string, thenFn: (e: (op: StackOp) => void) => void, elseFn: (e: (op: StackOp) => void) => void, resultName: string | null): void {
    this.toTop(condName);
    this.nm.pop(); // condition consumed
    const thenOps: StackOp[] = [];
    const elseOps: StackOp[] = [];
    thenFn((op) => thenOps.push(op));
    elseFn((op) => elseOps.push(op));
    this._e({ op: 'if', then: thenOps, else: elseOps });
    if (resultName !== null)
      this.nm.push(resultName);
  }
}

// ===========================================================================
// Field arithmetic helpers
// ===========================================================================

/** Push the field prime p onto the stack as a script number. */
function pushFieldP(t: ECTracker, name: string): void {
  t.pushConst(POOL_FIELD_P, FIELD_P, name);
}


/**
 * Reduce a scalar to [0, n-1]: ((k mod n) + n) mod n.
 *
 * OP_MOD takes the sign of the DIVIDEND, so `k mod n` alone lands in (-n, n);
 * the `+ n, mod n` normalises the negative half. One push of n covers both
 * reductions — the same shape as `emitEcModReduce`.
 *
 * Without it, `emitEcMul`'s ladder is only correct while 2^257 <= k + 3n < 2^258:
 * a scalar >= ~n sets bit 258, the 257-iteration loop never sees it, and the
 * ladder returns a DIFFERENT multiple of P rather than failing. Scalars are
 * contract input, so that is attacker-chosen. Reducing costs 1 push + 7 opcodes
 * (41 bytes) against a ~429 KB script, and makes k >= n, k < 0 and k = 0 all
 * well defined.
 */
function emitScalarReduce(t: ECTracker, kName: string, resultName: string): void {
  t.pushConst(POOL_GROUP_N, CURVE_N, '_n_red');
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

/**
 * fieldMod: reduce TOS mod p, ensure non-negative.
 * Expects 'aName' to be on the tracker stack.
 */
function fieldMod(t: ECTracker, aName: string, resultName: string): void {
  t.toTop(aName);
  pushFieldP(t, '_fmod_p');
  // (a % p + p) % p
  t.rawBlock([aName, '_fmod_p'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_2DUP' }); // a p a p
    e({ op: 'opcode', code: 'OP_MOD' });   // a p (a%p)
    e({ op: 'rot' });                       // p (a%p) a
    e({ op: 'drop' });                      // p (a%p)
    e({ op: 'over' });                      // p (a%p) p
    e({ op: 'opcode', code: 'OP_ADD' });    // p (a%p+p)
    e({ op: 'swap' });                      // (a%p+p) p
    e({ op: 'opcode', code: 'OP_MOD' });    // ((a%p+p)%p)
  });
}

/** fieldAdd: (a + b) mod p */
function fieldAdd(t: ECTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_fadd_sum', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  fieldMod(t, '_fadd_sum', resultName);
}

/** fieldSub: (a - b) mod p (non-negative) */
function fieldSub(t: ECTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_fsub_diff', (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
  });
  fieldMod(t, '_fsub_diff', resultName);
}

/** fieldMul: (a * b) mod p */
function fieldMul(t: ECTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_fmul_prod', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  fieldMod(t, '_fmul_prod', resultName);
}

/** fieldMulConst: (a * c) mod p where c is a small constant. Uses OP_2MUL for c=2. */
function fieldMulConst(t: ECTracker, aName: string, c: bigint, resultName: string): void {
  t.toTop(aName);
  t.rawBlock([aName], '_fmc_prod', (e) => {
    if (c === 2n) {
      e({ op: 'opcode', code: 'OP_2MUL' });
    } else {
      e({ op: 'push', value: c });
      e({ op: 'opcode', code: 'OP_MUL' });
    }
  });
  fieldMod(t, '_fmc_prod', resultName);
}

/** fieldSqr: (a * a) mod p */
function fieldSqr(t: ECTracker, aName: string, resultName: string): void {
  t.copyToTop(aName, '_fsqr_copy');
  fieldMul(t, aName, '_fsqr_copy', resultName);
}

/**
 * fieldInv: a^(p-2) mod p via square-and-multiply.
 * Consumes aName from the tracker.
 */
function fieldInv(t: ECTracker, aName: string, resultName: string): void {
  // p-2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
  // Bits 255..32: 224 bits, all 1 except bit 32 which is 0
  // Bits 31..0: 0xFFFFFC2D

  // Start: result = a (bit 255 = 1)
  t.copyToTop(aName, '_inv_r');
  // Bits 254 down to 33: all 1's (222 bits). Bit 32 is 0 (handled below).
  for (let i = 0; i < 222; i++) {
    fieldSqr(t, '_inv_r', '_inv_r2');
    t.rename('_inv_r');
    t.copyToTop(aName, '_inv_a');
    fieldMul(t, '_inv_r', '_inv_a', '_inv_m');
    t.rename('_inv_r');
  }
  // Bit 32 is 0: square only (no multiply)
  fieldSqr(t, '_inv_r', '_inv_r2');
  t.rename('_inv_r');
  // Bits 31 down to 0 of p-2
  const lowBits = Number(FIELD_P_MINUS_2 & 0xffffffffn);
  for (let i = 31; i >= 0; i--) {
    fieldSqr(t, '_inv_r', '_inv_r2');
    t.rename('_inv_r');
    if ((lowBits >> i) & 1) {
      t.copyToTop(aName, '_inv_a');
      fieldMul(t, '_inv_r', '_inv_a', '_inv_m');
      t.rename('_inv_r');
    }
  }
  // Clean up original input and rename result
  t.toTop(aName);
  t.drop();
  t.toTop('_inv_r');
  t.rename(resultName);
}

// ===========================================================================
// Point decompose / compose
// ===========================================================================

/**
 * Decompose 64-byte Point → (x_num, y_num) on stack.
 * Consumes pointName, produces xName and yName.
 */
function decomposePoint(t: ECTracker, pointName: string, xName: string, yName: string): void {
  t.toTop(pointName);
  // OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top)
  t.rawBlock([pointName], null, (e) => {
    e({ op: 'push', value: 32n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
  });
  // Manually track the two new items
  t.nm.push('_dp_xb');
  t.nm.push('_dp_yb');

  // Convert y_bytes (on top) to num
  // Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
  t.rawBlock(['_dp_yb'], yName, (e) => {
    emitReverse32(e);
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
  });

  // Convert x_bytes to num
  t.toTop('_dp_xb');
  t.rawBlock(['_dp_xb'], xName, (e) => {
    emitReverse32(e);
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
  });

  // Stack: [yName, xName] — swap to standard order [xName, yName]
  t.swap();
}

/**
 * Compose (x_num, y_num) → 64-byte Point.
 * Consumes xName and yName, produces resultName.
 */
function composePoint(t: ECTracker, xName: string, yName: string, resultName: string): void {
  // Convert x to 32-byte big-endian
  // Use NUM2BIN(33) to accommodate the sign byte, then drop the last byte
  t.toTop(xName);
  t.rawBlock([xName], '_cp_xb', (e) => {
    e({ op: 'push', value: 33n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    // Drop the sign byte (last byte) — split at 32, keep left
    e({ op: 'push', value: 32n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'drop' });
    emitReverse32(e);
  });

  // Convert y to 32-byte big-endian
  t.toTop(yName);
  t.rawBlock([yName], '_cp_yb', (e) => {
    e({ op: 'push', value: 33n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    e({ op: 'push', value: 32n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'drop' });
    emitReverse32(e);
  });

  // Cat: x_be || y_be (x is below y after the two toTop calls)
  t.toTop('_cp_xb');
  t.toTop('_cp_yb');
  t.rawBlock(['_cp_xb', '_cp_yb'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_CAT' });
  });
}

/**
 * Emit inline byte reversal for a 32-byte value on TOS.
 * After: reversed 32-byte value on TOS.
 */
function emitReverse32(e: (op: StackOp) => void): void {
  // Push empty accumulator, swap with data
  e({ op: 'opcode', code: 'OP_0' });
  e({ op: 'swap' });
  // 32 iterations: peel first byte, prepend to accumulator
  for (let i = 0; i < 32; i++) {
    // Stack: [accum, remaining]
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    // Stack: [accum, byte0, rest]
    e({ op: 'rot' });
    // Stack: [byte0, rest, accum]
    e({ op: 'rot' });
    // Stack: [rest, accum, byte0]
    e({ op: 'swap' });
    // Stack: [rest, byte0, accum]
    e({ op: 'opcode', code: 'OP_CAT' });
    // Stack: [rest, byte0||accum]
    e({ op: 'swap' });
    // Stack: [byte0||accum, rest]
  }
  // Stack: [reversed, empty]
  e({ op: 'drop' });
}

// ===========================================================================
// Affine point addition (for ecAdd)
// ===========================================================================

/**
 * Affine point addition: expects px, py, qx, qy on tracker.
 * Produces rx, ry. Consumes all four inputs.
 */
function affineAdd(t: ECTracker): void {
  // The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
  // denominator is zero and the correct slope is the TANGENT, 3px^2 / (2py).
  // Without this, ecAdd(P, P) silently produced a wrong point, so every
  // contract that doubled deployed an unspendable script — byte-identically
  // across all seven tiers, because they all shared the same omission.
  //
  // Both cases are the same shape, `s = num / den`, so only the NUMERATOR and
  // DENOMINATOR are selected; the single expensive fieldInv is still performed
  // exactly once. rx = s^2 - px - qx and ry = s*(px - rx) - py are already
  // correct for doubling (px == qx makes the first s^2 - 2px).
  //
  //   cond   = (px == qx) AND (py == qy)     1 when doubling, else 0
  //   num    = cond ? 3*px^2 : (qy - py)
  //   den    = cond ? 2*py   : (qx - px)
  //
  // selected as `b + cond*(a - b)` over the field, which needs no branch and
  // so keeps the emitted op sequence — and the tracker's static stack model —
  // identical on both paths.
  //
  // THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
  // sends it down the tangent path and returns 2P — an on-curve, entirely
  // plausible, WRONG point. Before the doubling fix the chord path ran there,
  // divided by zero (fieldInv is Fermat, inv(0) = 0) and produced an OFF-curve
  // blob, so `assert(ecOnCurve(ecAdd(a, b)))` — the idiom this codegen tells
  // authors to write — happened to reject it. Selecting on px alone would have
  // silently disarmed that.
  //
  // P + (-P) is the point at infinity, which affine x||y cannot represent. This
  // codegen already has a representation for O: the ALL-ZERO blob, which is
  // what `ecMul(P, 0n)` returns and what the `ec-mulgen-linear` rewrite in
  // optimizer/ec-rules.json produces for k1 + k2 ≡ 0 (mod n). So return that,
  // by masking the result with `notinf = NOT(px == qx AND NOT cond)`:
  //
  //   - it agrees with the rewrite, so the same source cannot give two answers
  //     depending on whether the optimizer fired;
  //   - O is not on the curve (0^2 != 0^3 + 7), so the on-curve gate rejects it
  //     and the idiom above works again;
  //   - it adds no failure channel to what is a pure value-producing
  //     expression, the same reason emitScalarReduce reduces instead of
  //     rejecting.
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
  // notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and the
  // points are not equal, i.e. exactly the P == -Q case.
  t.toTop('_xeq');
  t.copyToTop('_cond', '_cond_c');
  t.rawBlock(['_xeq', '_cond_c'], '_notinf', (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
    e({ op: 'opcode', code: 'OP_NOT' });
  });

  // chord numerator / denominator
  t.copyToTop('qy', '_qy1');
  t.copyToTop('py', '_py1');
  fieldSub(t, '_qy1', '_py1', '_num_chord');
  t.copyToTop('qx', '_qx1');
  t.copyToTop('px', '_px1');
  fieldSub(t, '_qx1', '_px1', '_den_chord');

  // tangent numerator / denominator: 3*px^2 and 2*py
  t.copyToTop('px', '_px_t');
  fieldSqr(t, '_px_t', '_px_sq');
  fieldMulConst(t, '_px_sq', 3n, '_num_tan');
  t.copyToTop('py', '_py_t');
  fieldMulConst(t, '_py_t', 2n, '_den_tan');

  // num = num_chord + cond*(num_tan - num_chord)
  t.copyToTop('_num_chord', '_num_chord_c');
  fieldSub(t, '_num_tan', '_num_chord_c', '_num_diff');
  t.copyToTop('_cond', '_cond_n');
  fieldMul(t, '_num_diff', '_cond_n', '_num_sel');
  fieldAdd(t, '_num_chord', '_num_sel', '_s_num');

  // den = den_chord + cond*(den_tan - den_chord)
  t.copyToTop('_den_chord', '_den_chord_c');
  fieldSub(t, '_den_tan', '_den_chord_c', '_den_diff');
  t.toTop('_cond');
  t.rename('_cond_d');
  fieldMul(t, '_den_diff', '_cond_d', '_den_sel');
  fieldAdd(t, '_den_chord', '_den_sel', '_s_den');

  // s = s_num / s_den mod p
  fieldInv(t, '_s_den', '_s_den_inv');
  fieldMul(t, '_s_num', '_s_den_inv', '_s');

  // rx = s² - px - qx mod p
  t.copyToTop('_s', '_s_keep');
  fieldSqr(t, '_s', '_s2');
  t.copyToTop('px', '_px2');
  fieldSub(t, '_s2', '_px2', '_rx1');
  t.copyToTop('qx', '_qx2');
  fieldSub(t, '_rx1', '_qx2', 'rx');

  // ry = s * (px - rx) - py mod p
  t.copyToTop('px', '_px3');
  t.copyToTop('rx', '_rx2');
  fieldSub(t, '_px3', '_rx2', '_px_rx');
  fieldMul(t, '_s_keep', '_px_rx', '_s_px_rx');
  t.copyToTop('py', '_py2');
  fieldSub(t, '_s_px_rx', '_py2', 'ry');

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
// Jacobian point operations (for ecMul)
// ===========================================================================

/**
 * Jacobian point doubling (a=0 for secp256k1).
 * Expects jx, jy, jz on tracker. Replaces with updated values.
 */
function jacobianDouble(t: ECTracker): void {
  // Save copies of jx, jy, jz for later use
  t.copyToTop('jy', '_jy_save');
  t.copyToTop('jx', '_jx_save');
  t.copyToTop('jz', '_jz_save');

  // A = jy²
  fieldSqr(t, 'jy', '_A');

  // B = 4 * jx * A
  t.copyToTop('_A', '_A_save');
  fieldMul(t, 'jx', '_A', '_xA');
  t.pushInt('_four', 4n);
  fieldMul(t, '_xA', '_four', '_B');

  // C = 8 * A²
  fieldSqr(t, '_A_save', '_A2');
  t.pushInt('_eight', 8n);
  fieldMul(t, '_A2', '_eight', '_C');

  // D = 3 * X²
  fieldSqr(t, '_jx_save', '_x2');
  t.pushInt('_three', 3n);
  fieldMul(t, '_x2', '_three', '_D');

  // nx = D² - 2*B
  t.copyToTop('_D', '_D_save');
  t.copyToTop('_B', '_B_save');
  fieldSqr(t, '_D', '_D2');
  t.copyToTop('_B', '_B1');
  fieldMulConst(t, '_B1', 2n, '_2B');
  fieldSub(t, '_D2', '_2B', '_nx');

  // ny = D*(B - nx) - C
  t.copyToTop('_nx', '_nx_copy');
  fieldSub(t, '_B_save', '_nx_copy', '_B_nx');
  fieldMul(t, '_D_save', '_B_nx', '_D_B_nx');
  fieldSub(t, '_D_B_nx', '_C', '_ny');

  // nz = 2 * Y * Z
  fieldMul(t, '_jy_save', '_jz_save', '_yz');
  fieldMulConst(t, '_yz', 2n, '_nz');

  // Clean up leftovers: _B (used via _B_save/_B1) and old jz (only copied, never consumed)
  t.toTop('_B'); t.drop();
  t.toTop('jz'); t.drop();
  t.toTop('_nx'); t.rename('jx');
  t.toTop('_ny'); t.rename('jy');
  t.toTop('_nz'); t.rename('jz');
}

/**
 * Jacobian → Affine conversion.
 * Consumes jx, jy, jz; produces rxName, ryName.
 */
function jacobianToAffine(t: ECTracker, rxName: string, ryName: string): void {
  fieldInv(t, 'jz', '_zinv');
  t.copyToTop('_zinv', '_zinv_keep');
  fieldSqr(t, '_zinv', '_zinv2');
  t.copyToTop('_zinv2', '_zinv2_keep');
  fieldMul(t, '_zinv_keep', '_zinv2', '_zinv3');
  fieldMul(t, 'jx', '_zinv2_keep', rxName);
  fieldMul(t, 'jy', '_zinv3', ryName);
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine)
// ===========================================================================

/**
 * Build Jacobian mixed-add ops for use inside OP_IF.
 * Uses an inner ECTracker to leverage field arithmetic helpers.
 *
 * Stack layout: [..., ax, ay, _k, jx, jy, jz]
 * After:        [..., ax, ay, _k, jx', jy', jz']
 */
function buildJacobianAddAffineInline(e: (op: StackOp) => void, t: ECTracker): void {
  // Create inner tracker with cloned stack state
  jacobianAddAffineBody(new ECTracker([...t.nm], e, t.options), false);
}

/**
 * The mixed-add itself, emitting through an ECTracker the caller owns.
 *
 * `keepHR` additionally leaves copies of H and R on the stack. They are the
 * exception detector: H = U2 - X1 and R = S2 - Y1 are both zero exactly when
 * the Jacobian accumulator is the same curve point as the affine operand, the
 * one case these formulas cannot compute (see buildJacobianAddOrDoubleInline).
 */
function jacobianAddAffineBody(it: ECTracker, keepHR: boolean): void {
  // Save copies of values that get consumed but are needed later
  it.copyToTop('jz', '_jz_for_z1cu');   // consumed by Z1sq, needed for Z1cu
  it.copyToTop('jz', '_jz_for_z3');     // needed for Z3
  it.copyToTop('jy', '_jy_for_y3');     // consumed by R, needed for Y3
  it.copyToTop('jx', '_jx_for_u1h2');   // consumed by H, needed for U1H2

  // Z1sq = jz²
  fieldSqr(it, 'jz', '_Z1sq');

  // Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
  it.copyToTop('_Z1sq', '_Z1sq_for_u2');
  fieldMul(it, '_jz_for_z1cu', '_Z1sq', '_Z1cu');

  // U2 = ax * Z1sq_for_u2
  it.copyToTop('ax', '_ax_c');
  fieldMul(it, '_ax_c', '_Z1sq_for_u2', '_U2');

  // S2 = ay * Z1cu
  it.copyToTop('ay', '_ay_c');
  fieldMul(it, '_ay_c', '_Z1cu', '_S2');

  // H = U2 - jx
  fieldSub(it, '_U2', 'jx', '_H');

  // R = S2 - jy
  fieldSub(it, '_S2', 'jy', '_R');

  if (keepHR) {
    it.copyToTop('_H', '_H_keep');
    it.copyToTop('_R', '_R_keep');
  }

  // Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
  it.copyToTop('_H', '_H_for_h3');
  it.copyToTop('_H', '_H_for_z3');

  // H2 = H²
  fieldSqr(it, '_H', '_H2');

  // Save H2 for U1H2
  it.copyToTop('_H2', '_H2_for_u1h2');

  // H3 = H_for_h3 * H2
  fieldMul(it, '_H_for_h3', '_H2', '_H3');

  // U1H2 = _jx_for_u1h2 * H2_for_u1h2
  fieldMul(it, '_jx_for_u1h2', '_H2_for_u1h2', '_U1H2');

  // Save R, U1H2, H3 for Y3 computation
  it.copyToTop('_R', '_R_for_y3');
  it.copyToTop('_U1H2', '_U1H2_for_y3');
  it.copyToTop('_H3', '_H3_for_y3');

  // X3 = R² - H3 - 2*U1H2
  fieldSqr(it, '_R', '_R2');
  fieldSub(it, '_R2', '_H3', '_x3_tmp');
  fieldMulConst(it, '_U1H2', 2n, '_2U1H2');
  fieldSub(it, '_x3_tmp', '_2U1H2', '_X3');

  // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
  it.copyToTop('_X3', '_X3_c');
  fieldSub(it, '_U1H2_for_y3', '_X3_c', '_u_minus_x');
  fieldMul(it, '_R_for_y3', '_u_minus_x', '_r_tmp');
  fieldMul(it, '_jy_for_y3', '_H3_for_y3', '_jy_h3');
  fieldSub(it, '_r_tmp', '_jy_h3', '_Y3');

  // Z3 = _jz_for_z3 * _H_for_z3
  fieldMul(it, '_jz_for_z3', '_H_for_z3', '_Z3');

  // Rename results to jx/jy/jz
  it.toTop('_X3'); it.rename('jx');
  it.toTop('_Y3'); it.rename('jy');
  it.toTop('_Z3'); it.rename('jz');
}

/**
 * Branchless select of one Jacobian coordinate: `add + cond*(dbl - add)`.
 * Same shape as the numerator/denominator select in affineAdd, so both paths
 * emit the identical op sequence and the tracker's static stack model holds.
 * Consumes addName, dblName and condName.
 */
function selectCoord(t: ECTracker, addName: string, dblName: string, condName: string, resultName: string): void {
  t.copyToTop(addName, '_sel_add_c');
  fieldSub(t, dblName, '_sel_add_c', '_sel_diff');
  fieldMul(t, '_sel_diff', condName, '_sel_scaled');
  fieldAdd(t, addName, '_sel_scaled', resultName);
}

/**
 * The ladder's LAST conditional step: mixed-add, but correct when the
 * accumulator already equals the point being added.
 *
 * The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the
 * two operands are the same curve point H = 0, so Z3 = Z1*H = 0 — the point at
 * infinity — and since fieldInv is Fermat (inv(0) = 0), jacobianToAffine turns
 * that into the ALL-ZERO point instead of 2P. `ecMul(P, 2n)` and
 * `ecMulGen(2n)` returned 64 zero bytes.
 *
 * WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
 * c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
 * (c_i - 1)*P. Every curve here has cofactor 1, so P has order n and the
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
 * because the reduce puts k = 0 in the domain — and that interval contains no
 * value ≡ 0, 1 or 2 (mod n) that is also odd; c_256 = 2 is even, so no add
 * runs. Handling H == 0 at every one of the 257 steps would cost ~62% more
 * script bytes; handling it here costs 0.24%.
 *
 * THE ENTIRE ARGUMENT IS CONDITIONED ON k ∈ [0, n-1], which is only true
 * because emitEcMul reduces k mod n before adding 3n. That reduce landed one
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
 * This is NOT a "no honest input hits it" argument: the operand P is caller-
 * supplied and cannot move the exception, because the condition depends only
 * on c_i mod ord(P) and ord(P) = n for every point on the curve. A point that
 * is NOT on the curve has no such guarantee — but nor does any other part of
 * this codegen; callers who accept untrusted points must gate them on
 * `ecOnCurve` first.
 *
 * Stack layout: [..., ax, ay, _k, jx, jy, jz] — same in and out.
 */
function buildJacobianAddOrDoubleInline(e: (op: StackOp) => void, t: ECTracker): void {
  const it = new ECTracker([...t.nm], e, t.options);

  // Keep the pre-add accumulator: it is what must be DOUBLED in the
  // exceptional case, and the add below consumes jx/jy/jz.
  it.copyToTop('jx', '_sx');
  it.copyToTop('jy', '_sy');
  it.copyToTop('jz', '_sz');

  jacobianAddAffineBody(it, true);

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

  // Move the add result aside so jacobianDouble can work on jx/jy/jz again,
  // this time holding the saved accumulator.
  it.toTop('jx'); it.rename('_add_x');
  it.toTop('jy'); it.rename('_add_y');
  it.toTop('jz'); it.rename('_add_z');
  it.toTop('_sx'); it.rename('jx');
  it.toTop('_sy'); it.rename('jy');
  it.toTop('_sz'); it.rename('jz');
  jacobianDouble(it);
  it.toTop('jx'); it.rename('_dbl_x');
  it.toTop('jy'); it.rename('_dbl_y');
  it.toTop('jz'); it.rename('_dbl_z');

  it.copyToTop('_cond', '_cond_x');
  selectCoord(it, '_add_x', '_dbl_x', '_cond_x', 'jx');
  it.copyToTop('_cond', '_cond_y');
  selectCoord(it, '_add_y', '_dbl_y', '_cond_y', 'jy');
  it.toTop('_cond'); it.rename('_cond_z');
  selectCoord(it, '_add_z', '_dbl_z', '_cond_z', 'jz');
}

// ===========================================================================
// Public entry points (called from stack lowerer)
// ===========================================================================

/**
 * ecAdd: add two points.
 * Stack in: [point_a, point_b] (b on top)
 * Stack out: [result_point]
 */
export function emitEcAdd(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const t = new ECTracker(['_pa', '_pb'], emit, opts);
  t.poolConstant(POOL_FIELD_P, FIELD_P);
  decomposePoint(t, '_pa', 'px', 'py');
  decomposePoint(t, '_pb', 'qx', 'qy');
  affineAdd(t);
  composePoint(t, 'rx', 'ry', '_result');
  t.releaseConstant(POOL_FIELD_P);
}

/**
 * ecMul: scalar multiplication P * k.
 * Stack in: [point, scalar] (scalar on top)
 * Stack out: [result_point]
 *
 * Uses 257-iteration MSB-first double-and-add with Jacobian coordinates.
 * Adds 3n to k so that bit 257 is always set: k+3n ∈ [3n, 4n-1], and
 * since 3n > 2^257, bit 257 is guaranteed to be 1 for all valid k.
 * This avoids the k+n overflow issue where bit 256 was only set for
 * large k, causing incorrect results for ~half of all scalar values.
 */
export function emitEcMul(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const t = new ECTracker(['_pt', '_k'], emit, opts);
  t.poolConstant(POOL_FIELD_P, FIELD_P);
  t.poolConstant(POOL_GROUP_N, CURVE_N);
  decomposePoint(t, '_pt', 'ax', 'ay');

  // k' = k + 3n: guarantees bit 257 is set for MSB-first double-and-add.
  // k ∈ [1, n-1], so k+3n ∈ [3n+1, 4n-1]. Since 3n > 2^257, bit 257
  // is always 1. Adding 3n (≡ 0 mod n) preserves the EC point: k*G = (k+3n)*G.
  //
  // "k ∈ [1, n-1]" is a PRECONDITION the caller cannot enforce — the scalar is
  // usually an unlock argument — so reduce it first. See emitScalarReduce.
  t.toTop('_k');
  emitScalarReduce(t, '_k', '_kr');
  t.pushConst(POOL_GROUP_N, CURVE_N, '_n');
  t.rawBlock(['_kr', '_n'], '_kn', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.pushConst(POOL_GROUP_N, CURVE_N, '_n2');
  t.rawBlock(['_kn', '_n2'], '_kn2', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.pushConst(POOL_GROUP_N, CURVE_N, '_n3');
  t.rawBlock(['_kn2', '_n3'], '_kn3', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.rename('_k');

  // Init accumulator = P (bit 257 of k+3n is always 1)
  t.copyToTop('ax', 'jx');
  t.copyToTop('ay', 'jy');
  t.pushInt('jz', 1n);

  // 257 iterations: bits 256 down to 0
  for (let bit = 256; bit >= 0; bit--) {
    jacobianDouble(t);

    // Extract bit: (k >> bit) & 1, using OP_RSHIFTNUM / OP_2DIV
    t.copyToTop('_k', '_k_copy');
    if (bit === 1) {
      // Single-bit shift: OP_2DIV (no push needed)
      t.rawBlock(['_k_copy'], '_shifted', (e) => {
        e({ op: 'opcode', code: 'OP_2DIV' });
      });
    } else if (bit > 1) {
      // Multi-bit shift: push shift amount, OP_RSHIFTNUM
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

    // Move _bit to TOS and remove from tracker BEFORE generating add ops,
    // because OP_IF consumes _bit and the add ops run with _bit already gone.
    t.toTop('_bit');
    t.nm.pop(); // _bit consumed by IF
    const addOps: StackOp[] = [];
    const addEmit = (op: StackOp) => addOps.push(op);
    // Only the final step can be handed two equal operands — see
    // buildJacobianAddOrDoubleInline for why, and for what it costs not to.
    if (bit === 0) buildJacobianAddOrDoubleInline(addEmit, t);
    else buildJacobianAddAffineInline(addEmit, t);
    emit({ op: 'if', then: addOps, else: [] });
  }

  jacobianToAffine(t, '_rx', '_ry');

  // Clean up
  t.toTop('ax'); t.drop();
  t.toTop('ay'); t.drop();
  t.toTop('_k'); t.drop();

  composePoint(t, '_rx', '_ry', '_result');
  t.releaseConstant(POOL_GROUP_N);
  t.releaseConstant(POOL_FIELD_P);
}

/**
 * ecMulGen: scalar multiplication G * k.
 * Stack in: [scalar]
 * Stack out: [result_point]
 */
export function emitEcMulGen(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  // Push generator point as 64-byte blob, then delegate to ecMul
  const gPoint = new Uint8Array(64);
  gPoint.set(bigintToBytes32(GEN_X), 0);
  gPoint.set(bigintToBytes32(GEN_Y), 32);
  emit({ op: 'push', value: gPoint });
  emit({ op: 'swap' }); // [point, scalar]
  emitEcMul(emit, opts);
}

/**
 * ecNegate: negate a point (x, p - y).
 * Stack in: [point]
 * Stack out: [negated_point]
 */
export function emitEcNegate(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const t = new ECTracker(['_pt'], emit, opts);
  t.poolConstant(POOL_FIELD_P, FIELD_P);
  decomposePoint(t, '_pt', '_nx', '_ny');
  pushFieldP(t, '_fp');
  fieldSub(t, '_fp', '_ny', '_neg_y');
  composePoint(t, '_nx', '_neg_y', '_result');
  t.releaseConstant(POOL_FIELD_P);
}

/**
 * ecOnCurve: check if point is on secp256k1 (y² ≡ x³ + 7 mod p).
 * Stack in: [point]
 * Stack out: [boolean]
 */
export function emitEcOnCurve(emit: (op: StackOp) => void, opts?: EcCodegenOptions): void {
  const t = new ECTracker(['_pt'], emit, opts);
  t.poolConstant(POOL_FIELD_P, FIELD_P);
  decomposePoint(t, '_pt', '_x', '_y');

  // GAP-301: coordinate canonicity. `decomposePoint` BIN2NUMs each coordinate
  // as an unsigned value that may be ≥ p; the field arithmetic below would
  // silently reduce it mod p, so a non-canonical encoding of a valid point
  // would pass. Reject it: require x < p AND y < p (coordinates are unsigned,
  // so the 0 ≤ lower bound holds by construction). Combined with the curve
  // equation at the end via OP_BOOLAND so ecOnCurve still returns a boolean.
  t.copyToTop('_x', '_x_lt');
  pushFieldP(t, '_p_for_x');
  t.rawBlock(['_x_lt', '_p_for_x'], '_x_canon', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.copyToTop('_y', '_y_lt');
  pushFieldP(t, '_p_for_y');
  t.rawBlock(['_y_lt', '_p_for_y'], '_y_canon', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.toTop('_x_canon');
  t.toTop('_y_canon');
  t.rawBlock(['_x_canon', '_y_canon'], '_canon', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  // lhs = y²
  fieldSqr(t, '_y', '_y2');

  // rhs = x³ + 7
  t.copyToTop('_x', '_x_copy');
  fieldSqr(t, '_x', '_x2');
  fieldMul(t, '_x2', '_x_copy', '_x3');
  t.pushInt('_seven', 7n);
  fieldAdd(t, '_x3', '_seven', '_rhs');

  // Compare curve equation
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
 * ecModReduce: ((value % mod) + mod) % mod
 * Stack in: [value, mod]
 * Stack out: [result]
 */
export function emitEcModReduce(emit: (op: StackOp) => void): void {
  emit({ op: 'opcode', code: 'OP_2DUP' });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'rot' });
  emit({ op: 'drop' });
  emit({ op: 'over' });
  emit({ op: 'opcode', code: 'OP_ADD' });
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_MOD' });
}

/**
 * ecEncodeCompressed: point → 33-byte compressed pubkey.
 * Stack in: [point (64 bytes)]
 * Stack out: [compressed (33 bytes)]
 */
export function emitEcEncodeCompressed(emit: (op: StackOp) => void): void {
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
 * ecMakePoint: (x: bigint, y: bigint) → Point.
 * Stack in: [x_num, y_num] (y on top)
 * Stack out: [point_bytes (64 bytes)]
 */
export function emitEcMakePoint(emit: (op: StackOp) => void): void {
  // Convert y to 32 bytes big-endian (NUM2BIN(33) to handle sign byte, then take first 32)
  emit({ op: 'push', value: 33n });
  emit({ op: 'opcode', code: 'OP_NUM2BIN' });
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  emit({ op: 'drop' });
  emitReverse32(emit);
  // Stack: [x_num, y_be]
  emit({ op: 'swap' });
  // Stack: [y_be, x_num]
  emit({ op: 'push', value: 33n });
  emit({ op: 'opcode', code: 'OP_NUM2BIN' });
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  emit({ op: 'drop' });
  emitReverse32(emit);
  // Stack: [y_be, x_be]
  emit({ op: 'swap' });
  // Stack: [x_be, y_be]
  emit({ op: 'opcode', code: 'OP_CAT' });
}

/**
 * ecPointX: extract x-coordinate from Point.
 * Stack in: [point (64 bytes)]
 * Stack out: [x as bigint]
 */
export function emitEcPointX(emit: (op: StackOp) => void): void {
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  emit({ op: 'drop' });
  emitReverse32(emit);
  // Append 0x00 sign byte to ensure unsigned interpretation
  emit({ op: 'push', value: new Uint8Array([0x00]) });
  emit({ op: 'opcode', code: 'OP_CAT' });
  emit({ op: 'opcode', code: 'OP_BIN2NUM' });
}

/**
 * ecPointY: extract y-coordinate from Point.
 * Stack in: [point (64 bytes)]
 * Stack out: [y as bigint]
 */
export function emitEcPointY(emit: (op: StackOp) => void): void {
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  emit({ op: 'swap' });
  emit({ op: 'drop' });
  emitReverse32(emit);
  // Append 0x00 sign byte to ensure unsigned interpretation
  emit({ op: 'push', value: new Uint8Array([0x00]) });
  emit({ op: 'opcode', code: 'OP_CAT' });
  emit({ op: 'opcode', code: 'OP_BIN2NUM' });
}
