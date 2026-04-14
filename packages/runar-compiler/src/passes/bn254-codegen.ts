/**
 * BN254 codegen — BN254 elliptic curve field arithmetic and G1 point operations
 * for Bitcoin Script.
 *
 * Follows the ec-codegen.ts pattern: self-contained module imported by
 * 05-stack-lower.ts. Uses a BN254Tracker (mirrors ECTracker) for named stack
 * state tracking.
 *
 * BN254 parameters:
 *   Field prime: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
 *   Curve order: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 *   Curve:       y^2 = x^3 + 3
 *   Generator:   G1 = (1, 2)
 *
 * Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
 * Internal arithmetic uses Jacobian coordinates for scalar multiplication.
 */

import type { StackOp } from '../ir/index.js';

// ===========================================================================
// Constants
// ===========================================================================

/** BN254 field prime p */
const BN254_P =
  0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;
/** p - 2, used for Fermat's little theorem modular inverse */
const BN254_P_MINUS_2 = BN254_P - 2n;
/** BN254 curve order r */
const BN254_R =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

// ===========================================================================
// BN254Tracker — named stack state tracker (mirrors ECTracker)
// ===========================================================================

export class BN254Tracker {
  nm: (string | null)[];
  _e: (op: StackOp) => void;
  primeCacheActive: boolean = false;

  constructor(init: (string | null)[], emit: (op: StackOp) => void) {
    this.nm = [...init];
    this._e = emit;
  }

  get depth(): number {
    return this.nm.length;
  }

  findDepth(name: string): number {
    for (let i = this.nm.length - 1; i >= 0; i--) {
      if (this.nm[i] === name) return this.nm.length - 1 - i;
    }
    throw new Error(
      `BN254Tracker: '${name}' not on stack [${this.nm.join(',')}]`,
    );
  }

  pushBytes(n: string, v: Uint8Array): void {
    this._e({ op: 'push', value: v });
    this.nm.push(n);
  }
  pushBigInt(n: string, v: bigint): void {
    this._e({ op: 'push', value: v });
    this.nm.push(n);
  }
  pushInt(n: string, v: bigint): void {
    this._e({ op: 'push', value: v });
    this.nm.push(n);
  }
  dup(n: string): void {
    this._e({ op: 'dup' });
    this.nm.push(n);
  }
  drop(): void {
    this._e({ op: 'drop' });
    this.nm.pop();
  }
  nip(): void {
    this._e({ op: 'nip' });
    const L = this.nm.length;
    if (L >= 2) this.nm.splice(L - 2, 1);
  }
  over(n: string): void {
    this._e({ op: 'over' });
    this.nm.push(n);
  }
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
  op(code: string): void {
    this._e({ op: 'opcode', code });
  }
  roll(d: number): void {
    if (d === 0) return;
    if (d === 1) {
      this.swap();
      return;
    }
    if (d === 2) {
      this.rot();
      return;
    }
    this._e({ op: 'push', value: BigInt(d) });
    this.nm.push(null);
    this._e({ op: 'roll', depth: d });
    this.nm.pop();
    const idx = this.nm.length - 1 - d;
    const r = this.nm.splice(idx, 1)[0] ?? null;
    this.nm.push(r);
  }
  pick(d: number, n: string): void {
    if (d === 0) {
      this.dup(n);
      return;
    }
    if (d === 1) {
      this.over(n);
      return;
    }
    this._e({ op: 'push', value: BigInt(d) });
    this.nm.push(null);
    this._e({ op: 'pick', depth: d });
    this.nm.pop();
    this.nm.push(n);
  }
  toTop(name: string): void {
    this.roll(this.findDepth(name));
  }
  copyToTop(name: string, n?: string): void {
    this.pick(this.findDepth(name), n ?? name);
  }
  toAlt(): void {
    this.op('OP_TOALTSTACK');
    this.nm.pop();
  }
  fromAlt(n: string): void {
    this.op('OP_FROMALTSTACK');
    this.nm.push(n);
  }
  rename(n: string): void {
    if (this.nm.length > 0) this.nm[this.nm.length - 1] = n;
  }

  /** Emit raw opcodes tracking only net stack effect. */
  rawBlock(
    consume: string[],
    produce: string | null,
    fn: (e: (op: StackOp) => void) => void,
  ): void {
    for (let i = consume.length - 1; i >= 0; i--) this.nm.pop();
    fn(this._e);
    if (produce !== null) this.nm.push(produce);
  }

  /** Emit if/else with tracked stack effect. */
  emitIf(
    condName: string,
    thenFn: (e: (op: StackOp) => void) => void,
    elseFn: (e: (op: StackOp) => void) => void,
    resultName: string | null,
  ): void {
    this.toTop(condName);
    this.nm.pop(); // condition consumed
    const thenOps: StackOp[] = [];
    const elseOps: StackOp[] = [];
    thenFn((op) => thenOps.push(op));
    elseFn((op) => elseOps.push(op));
    this._e({ op: 'if', then: thenOps, else: elseOps });
    if (resultName !== null) this.nm.push(resultName);
  }

  /**
   * Push the BN254 field prime onto the alt-stack for caching. Subsequent
   * calls to bn254FieldMod (et al) use OP_FROMALTSTACK / OP_DUP / OP_TOALTSTACK
   * (3 bytes) to fetch the prime instead of re-pushing the 34-byte literal.
   */
  pushPrimeCache(): void {
    this.pushBigInt('_pcache_p', BN254_P);
    this.op('OP_TOALTSTACK');
    if (this.nm.length > 0) this.nm.pop();
    this.primeCacheActive = true;
  }

  /** Remove the cached field prime from the alt-stack. */
  popPrimeCache(): void {
    this.op('OP_FROMALTSTACK');
    this.nm.push('_pcache_cleanup');
    this.drop();
    this.primeCacheActive = false;
  }
}

// ===========================================================================
// Field arithmetic helpers
// ===========================================================================

/** Push the BN254 field prime p onto the stack. */
function bn254PushFieldP(t: BN254Tracker, name: string): void {
  t.pushBigInt(name, BN254_P);
}

/**
 * bn254FieldMod: reduce TOS mod p, ensuring non-negative result.
 * Pattern: (a % p + p) % p
 *
 * When primeCacheActive is true, the prime is fetched from the alt-stack
 * (OP_FROMALTSTACK / OP_DUP / OP_TOALTSTACK) instead of pushing the 34-byte
 * literal. Saves ~93 bytes per Fp mod reduction.
 */
export function bn254FieldMod(
  t: BN254Tracker,
  aName: string,
  resultName: string,
): void {
  t.toTop(aName);
  if (t.primeCacheActive) {
    t.rawBlock([aName], resultName, (e) => {
      e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      e({ op: 'dup' });
      e({ op: 'opcode', code: 'OP_TOALTSTACK' });
      // [a, p] -> TUCK -> [p, a, p]
      e({ op: 'opcode', code: 'OP_TUCK' });
      // [p, a, p] -> MOD -> [p, a%p]
      e({ op: 'opcode', code: 'OP_MOD' });
      // [p, a%p] -> OVER -> [p, a%p, p]
      e({ op: 'over' });
      // [p, a%p, p] -> ADD -> [p, a%p+p]
      e({ op: 'opcode', code: 'OP_ADD' });
      // [p, a%p+p] -> SWAP -> [a%p+p, p]
      e({ op: 'swap' });
      // [a%p+p, p] -> MOD -> [(a%p+p)%p]
      e({ op: 'opcode', code: 'OP_MOD' });
    });
  } else {
    bn254PushFieldP(t, '_fmod_p');
    t.rawBlock([aName, '_fmod_p'], resultName, (e) => {
      e({ op: 'opcode', code: 'OP_TUCK' });
      e({ op: 'opcode', code: 'OP_MOD' });
      e({ op: 'over' });
      e({ op: 'opcode', code: 'OP_ADD' });
      e({ op: 'swap' });
      e({ op: 'opcode', code: 'OP_MOD' });
    });
  }
}

/**
 * bn254FieldModPositive: reduce a non-negative value modulo p using a single
 * OP_MOD. Safe only when the input is guaranteed non-negative.
 */
export function bn254FieldModPositive(
  t: BN254Tracker,
  aName: string,
  resultName: string,
): void {
  t.toTop(aName);
  if (t.primeCacheActive) {
    t.rawBlock([aName], resultName, (e) => {
      e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      e({ op: 'dup' });
      e({ op: 'opcode', code: 'OP_TOALTSTACK' });
      e({ op: 'opcode', code: 'OP_MOD' });
    });
  } else {
    bn254PushFieldP(t, '_fmodp_p');
    t.rawBlock([aName, '_fmodp_p'], resultName, (e) => {
      e({ op: 'opcode', code: 'OP_MOD' });
    });
  }
}

/** bn254FieldAdd: (a + b) mod p (both operands non-negative → single-mod). */
export function bn254FieldAdd(
  t: BN254Tracker,
  aName: string,
  bName: string,
  resultName: string,
): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_fadd_sum', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  bn254FieldModPositive(t, '_fadd_sum', resultName);
}

/** bn254FieldAddUnreduced: a + b without modular reduction. */
export function bn254FieldAddUnreduced(
  t: BN254Tracker,
  aName: string,
  bName: string,
  resultName: string,
): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
}

/** bn254FieldSubUnreduced: a - b without modular reduction (may be negative). */
export function bn254FieldSubUnreduced(
  t: BN254Tracker,
  aName: string,
  bName: string,
  resultName: string,
): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
  });
}

/** bn254FieldMulUnreduced: a * b without modular reduction. */
export function bn254FieldMulUnreduced(
  t: BN254Tracker,
  aName: string,
  bName: string,
  resultName: string,
): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
}

/**
 * bn254FieldSub: (a - b) mod p (non-negative).
 * Computes (a - b + p) mod p. Single mod suffices since a - b + p > 0 for
 * a ≥ 0, b ∈ [0, p-1].
 */
export function bn254FieldSub(
  t: BN254Tracker,
  aName: string,
  bName: string,
  resultName: string,
): void {
  t.toTop(aName);
  t.toTop(bName);
  if (t.primeCacheActive) {
    t.rawBlock([aName, bName], resultName, (e) => {
      e({ op: 'opcode', code: 'OP_SUB' }); // [diff]
      e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      e({ op: 'dup' });
      e({ op: 'opcode', code: 'OP_TOALTSTACK' });
      // [diff, p] -> TUCK -> [p, diff, p]
      e({ op: 'opcode', code: 'OP_TUCK' });
      // [p, diff, p] -> ADD -> [p, diff+p]
      e({ op: 'opcode', code: 'OP_ADD' });
      // [p, diff+p] -> SWAP -> [diff+p, p]
      e({ op: 'swap' });
      // [diff+p, p] -> MOD -> [(diff+p)%p]
      e({ op: 'opcode', code: 'OP_MOD' });
    });
  } else {
    t.rawBlock([aName, bName], '_fsub_diff', (e) => {
      e({ op: 'opcode', code: 'OP_SUB' });
    });
    bn254FieldMod(t, '_fsub_diff', resultName);
  }
}

/** bn254FieldMul: (a * b) mod p (both operands non-negative). */
export function bn254FieldMul(
  t: BN254Tracker,
  aName: string,
  bName: string,
  resultName: string,
): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_fmul_prod', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  bn254FieldModPositive(t, '_fmul_prod', resultName);
}

/** bn254FieldSqr: (a * a) mod p. */
export function bn254FieldSqr(
  t: BN254Tracker,
  aName: string,
  resultName: string,
): void {
  t.copyToTop(aName, '_fsqr_copy');
  bn254FieldMul(t, aName, '_fsqr_copy', resultName);
}

/**
 * bn254FieldNeg: (p - a) mod p.
 * a is a field element in [0, p-1] so p - a ∈ [1, p]. Final mod handles p.
 */
export function bn254FieldNeg(
  t: BN254Tracker,
  aName: string,
  resultName: string,
): void {
  t.toTop(aName);
  if (t.primeCacheActive) {
    t.rawBlock([aName], resultName, (e) => {
      // [a]
      e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      e({ op: 'dup' });
      e({ op: 'opcode', code: 'OP_TOALTSTACK' });
      // [a, p] -> DUP -> [a, p, p]
      e({ op: 'opcode', code: 'OP_DUP' });
      // [a, p, p] -> ROT -> [p, p, a]
      e({ op: 'rot' });
      // [p, p, a] -> SUB -> [p, p-a]
      e({ op: 'opcode', code: 'OP_SUB' });
      // [p, p-a] -> SWAP -> [p-a, p]
      e({ op: 'swap' });
      // [p-a, p] -> MOD -> [(p-a)%p]
      e({ op: 'opcode', code: 'OP_MOD' });
    });
  } else {
    bn254PushFieldP(t, '_fneg_p');
    t.rawBlock([aName, '_fneg_p'], resultName, (e) => {
      e({ op: 'opcode', code: 'OP_DUP' });
      e({ op: 'rot' });
      e({ op: 'opcode', code: 'OP_SUB' });
      e({ op: 'swap' });
      e({ op: 'opcode', code: 'OP_MOD' });
    });
  }
}

/**
 * bn254FieldMulConst: (a * c) mod p where c is a small constant.
 * Uses OP_2MUL for c=2.
 */
export function bn254FieldMulConst(
  t: BN254Tracker,
  aName: string,
  c: bigint,
  resultName: string,
): void {
  t.toTop(aName);
  t.rawBlock([aName], '_bn_mc', (e) => {
    if (c === 2n) {
      e({ op: 'opcode', code: 'OP_2MUL' });
    } else {
      e({ op: 'push', value: c });
      e({ op: 'opcode', code: 'OP_MUL' });
    }
  });
  bn254FieldModPositive(t, '_bn_mc', resultName);
}

/**
 * bn254FieldInv: a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
 *
 * BN254 p is a 254-bit prime, so p-2 is also 254 bits with MSB at bit 253.
 * We handle the MSB by initializing result = a (equivalent to processing
 * bit 253 with an empty accumulator), then loop over bits 252 down to 0.
 * That gives 253 squarings plus one conditional multiply per set bit in
 * positions 252..0.
 */
export function bn254FieldInv(
  t: BN254Tracker,
  aName: string,
  resultName: string,
): void {
  // result = a implicitly handles bit 253 (the MSB of p-2, always set)
  t.copyToTop(aName, '_inv_r');

  // Process bits 252 down to 0 (253 iterations, one squaring each)
  for (let i = 252; i >= 0; i--) {
    // Always square
    bn254FieldSqr(t, '_inv_r', '_inv_r2');
    t.rename('_inv_r');

    // Multiply if bit is set
    if (((BN254_P_MINUS_2 >> BigInt(i)) & 1n) === 1n) {
      t.copyToTop(aName, '_inv_a');
      bn254FieldMul(t, '_inv_r', '_inv_a', '_inv_m');
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

/**
 * bn254DecomposePoint: decompose 64-byte Point → (x_num, y_num) on stack.
 * Consumes pointName, produces xName and yName.
 */
export function bn254DecomposePoint(
  t: BN254Tracker,
  pointName: string,
  xName: string,
  yName: string,
): void {
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
 * bn254ComposePoint: compose (x_num, y_num) → 64-byte Point.
 * Consumes xName and yName, produces resultName.
 *
 * IMPORTANT: Callers must ensure x and y are valid field elements in [0, p-1].
 */
export function bn254ComposePoint(
  t: BN254Tracker,
  xName: string,
  yName: string,
  resultName: string,
): void {
  // Convert x to 32-byte big-endian
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

// ===========================================================================
// Affine point addition (for bn254G1Add) — unified slope formula
// ===========================================================================

/**
 * bn254G1AffineAdd: affine point addition on BN254 G1.
 * Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four inputs.
 *
 * Uses the unified slope formula
 *
 *   s = (px^2 + px*qx + qx^2) / (py + qy)
 *
 * which works for both addition (P != Q) and doubling (P == Q) on y^2 = x^3 + b.
 * The standard chord formula s = (qy - py) / (qx - px) divides by zero when
 * P == Q; the unified form is algebraically equivalent for distinct points
 * and collapses to 3*px^2 / (2*py) when P == Q — the correct doubling slope.
 *
 * The only input that still fails is P == -Q (py + qy == 0, group identity),
 * which is out of scope for Groth16 verifier usage.
 */
export function bn254G1AffineAdd(t: BN254Tracker): void {
  // s_num = px^2 + px*qx + qx^2
  t.copyToTop('px', '_px_sq_in');
  bn254FieldSqr(t, '_px_sq_in', '_px_sq');
  t.copyToTop('px', '_px_m');
  t.copyToTop('qx', '_qx_m');
  bn254FieldMul(t, '_px_m', '_qx_m', '_px_qx');
  t.copyToTop('qx', '_qx_sq_in');
  bn254FieldSqr(t, '_qx_sq_in', '_qx_sq');
  bn254FieldAdd(t, '_px_sq', '_px_qx', '_s_num_tmp');
  bn254FieldAdd(t, '_s_num_tmp', '_qx_sq', '_s_num');

  // s_den = py + qy
  t.copyToTop('py', '_py_a');
  t.copyToTop('qy', '_qy_a');
  bn254FieldAdd(t, '_py_a', '_qy_a', '_s_den');

  // s = s_num / s_den mod p
  bn254FieldInv(t, '_s_den', '_s_den_inv');
  bn254FieldMul(t, '_s_num', '_s_den_inv', '_s');

  // rx = s^2 - px - qx mod p
  t.copyToTop('_s', '_s_keep');
  bn254FieldSqr(t, '_s', '_s2');
  t.copyToTop('px', '_px2');
  bn254FieldSub(t, '_s2', '_px2', '_rx1');
  t.copyToTop('qx', '_qx2');
  bn254FieldSub(t, '_rx1', '_qx2', 'rx');

  // ry = s * (px - rx) - py mod p
  t.copyToTop('px', '_px3');
  t.copyToTop('rx', '_rx2');
  bn254FieldSub(t, '_px3', '_rx2', '_px_rx');
  bn254FieldMul(t, '_s_keep', '_px_rx', '_s_px_rx');
  t.copyToTop('py', '_py2');
  bn254FieldSub(t, '_s_px_rx', '_py2', 'ry');

  // Clean up original points
  t.toTop('px');
  t.drop();
  t.toTop('py');
  t.drop();
  t.toTop('qx');
  t.drop();
  t.toTop('qy');
  t.drop();
}

// ===========================================================================
// Jacobian point operations (for bn254G1ScalarMul)
// ===========================================================================

/**
 * bn254G1JacobianDouble: Jacobian point doubling (a=0 for BN254).
 * Expects jx, jy, jz on tracker. Replaces with updated values.
 *
 * Formulas (a=0 since y^2 = x^3 + b):
 *   A  = Y^2
 *   B  = 4*X*A
 *   C  = 8*A^2
 *   D  = 3*X^2
 *   X' = D^2 - 2*B
 *   Y' = D*(B - X') - C
 *   Z' = 2*Y*Z
 */
export function bn254G1JacobianDouble(t: BN254Tracker): void {
  // Save copies of jx, jy, jz for later use
  t.copyToTop('jy', '_jy_save');
  t.copyToTop('jx', '_jx_save');
  t.copyToTop('jz', '_jz_save');

  // A = jy^2
  bn254FieldSqr(t, 'jy', '_A');

  // B = 4 * jx * A
  t.copyToTop('_A', '_A_save');
  bn254FieldMul(t, 'jx', '_A', '_xA');
  t.pushInt('_four', 4n);
  bn254FieldMul(t, '_xA', '_four', '_B');

  // C = 8 * A^2
  bn254FieldSqr(t, '_A_save', '_A2');
  t.pushInt('_eight', 8n);
  bn254FieldMul(t, '_A2', '_eight', '_C');

  // D = 3 * X^2
  bn254FieldSqr(t, '_jx_save', '_x2');
  t.pushInt('_three', 3n);
  bn254FieldMul(t, '_x2', '_three', '_D');

  // nx = D^2 - 2*B
  t.copyToTop('_D', '_D_save');
  t.copyToTop('_B', '_B_save');
  bn254FieldSqr(t, '_D', '_D2');
  t.copyToTop('_B', '_B1');
  bn254FieldMulConst(t, '_B1', 2n, '_2B');
  bn254FieldSub(t, '_D2', '_2B', '_nx');

  // ny = D*(B - nx) - C
  t.copyToTop('_nx', '_nx_copy');
  bn254FieldSub(t, '_B_save', '_nx_copy', '_B_nx');
  bn254FieldMul(t, '_D_save', '_B_nx', '_D_B_nx');
  bn254FieldSub(t, '_D_B_nx', '_C', '_ny');

  // nz = 2 * Y * Z
  bn254FieldMul(t, '_jy_save', '_jz_save', '_yz');
  bn254FieldMulConst(t, '_yz', 2n, '_nz');

  // Clean up leftovers: _B and old jz
  t.toTop('_B');
  t.drop();
  t.toTop('jz');
  t.drop();
  t.toTop('_nx');
  t.rename('jx');
  t.toTop('_ny');
  t.rename('jy');
  t.toTop('_nz');
  t.rename('jz');
}

/**
 * bn254G1JacobianToAffine: convert Jacobian to affine coordinates.
 * Consumes jx, jy, jz; produces rxName, ryName.
 */
export function bn254G1JacobianToAffine(
  t: BN254Tracker,
  rxName: string,
  ryName: string,
): void {
  bn254FieldInv(t, 'jz', '_zinv');
  t.copyToTop('_zinv', '_zinv_keep');
  bn254FieldSqr(t, '_zinv', '_zinv2');
  t.copyToTop('_zinv2', '_zinv2_keep');
  bn254FieldMul(t, '_zinv_keep', '_zinv2', '_zinv3');
  bn254FieldMul(t, 'jx', '_zinv2_keep', rxName);
  bn254FieldMul(t, 'jy', '_zinv3', ryName);
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine) — doubling-safe
// ===========================================================================

/**
 * bn254BuildJacobianAddAffineStandard: standard Jacobian mixed-add sequence,
 * assuming the doubling case has already been excluded by the caller.
 *
 * Consumes jx, jy, jz on the tracker (the affine base point ax, ay is read
 * via copy-to-top) and produces replacement jx, jy, jz.
 *
 * WARNING: fails (H = 0) when the Jacobian accumulator equals the affine
 * base point. Callers must guard; see bn254BuildJacobianAddAffineInline.
 */
function bn254BuildJacobianAddAffineStandard(it: BN254Tracker): void {
  // Save copies of values that get consumed but are needed later
  it.copyToTop('jz', '_jz_for_z1cu'); // consumed by Z1sq, needed for Z1cu
  it.copyToTop('jz', '_jz_for_z3'); // needed for Z3
  it.copyToTop('jy', '_jy_for_y3'); // consumed by R, needed for Y3
  it.copyToTop('jx', '_jx_for_u1h2'); // consumed by H, needed for U1H2

  // Z1sq = jz^2
  bn254FieldSqr(it, 'jz', '_Z1sq');

  // Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
  it.copyToTop('_Z1sq', '_Z1sq_for_u2');
  bn254FieldMul(it, '_jz_for_z1cu', '_Z1sq', '_Z1cu');

  // U2 = ax * Z1sq_for_u2
  it.copyToTop('ax', '_ax_c');
  bn254FieldMul(it, '_ax_c', '_Z1sq_for_u2', '_U2');

  // S2 = ay * Z1cu
  it.copyToTop('ay', '_ay_c');
  bn254FieldMul(it, '_ay_c', '_Z1cu', '_S2');

  // H = U2 - jx
  bn254FieldSub(it, '_U2', 'jx', '_H');

  // R = S2 - jy
  bn254FieldSub(it, '_S2', 'jy', '_R');

  // Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
  it.copyToTop('_H', '_H_for_h3');
  it.copyToTop('_H', '_H_for_z3');

  // H2 = H^2
  bn254FieldSqr(it, '_H', '_H2');

  // Save H2 for U1H2
  it.copyToTop('_H2', '_H2_for_u1h2');

  // H3 = H_for_h3 * H2
  bn254FieldMul(it, '_H_for_h3', '_H2', '_H3');

  // U1H2 = _jx_for_u1h2 * H2_for_u1h2
  bn254FieldMul(it, '_jx_for_u1h2', '_H2_for_u1h2', '_U1H2');

  // Save R, U1H2, H3 for Y3 computation
  it.copyToTop('_R', '_R_for_y3');
  it.copyToTop('_U1H2', '_U1H2_for_y3');
  it.copyToTop('_H3', '_H3_for_y3');

  // X3 = R^2 - H3 - 2*U1H2
  bn254FieldSqr(it, '_R', '_R2');
  bn254FieldSub(it, '_R2', '_H3', '_x3_tmp');
  bn254FieldMulConst(it, '_U1H2', 2n, '_2U1H2');
  bn254FieldSub(it, '_x3_tmp', '_2U1H2', '_X3');

  // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
  it.copyToTop('_X3', '_X3_c');
  bn254FieldSub(it, '_U1H2_for_y3', '_X3_c', '_u_minus_x');
  bn254FieldMul(it, '_R_for_y3', '_u_minus_x', '_r_tmp');
  bn254FieldMul(it, '_jy_for_y3', '_H3_for_y3', '_jy_h3');
  bn254FieldSub(it, '_r_tmp', '_jy_h3', '_Y3');

  // Z3 = _jz_for_z3 * _H_for_z3
  bn254FieldMul(it, '_jz_for_z3', '_H_for_z3', '_Z3');

  // Rename results to jx/jy/jz
  it.toTop('_X3');
  it.rename('jx');
  it.toTop('_Y3');
  it.rename('jy');
  it.toTop('_Z3');
  it.rename('jz');
}

/**
 * bn254BuildJacobianAddAffineInline: doubling-safe Jacobian mixed-add wrapper
 * for use inside OP_IF. Uses an inner BN254Tracker to leverage the field
 * arithmetic helpers.
 *
 * Stack layout: [..., ax, ay, _k, jx, jy, jz]
 * After:        [..., ax, ay, _k, jx', jy', jz']
 *
 * The standard Jacobian mixed-add divides by H = ax*jz^2 - jx, which is 0 when
 * the accumulator's affine image equals the base point. To handle the doubling
 * case, we check H == 0 at runtime and delegate to Jacobian doubling when it
 * fires. The standard mixed-add runs otherwise.
 *
 * The negation case (H == 0 with R != 0, i.e. acc = -base) is
 * cryptographically unreachable for valid Groth16 inputs and not guarded.
 */
function bn254BuildJacobianAddAffineInline(
  e: (op: StackOp) => void,
  t: BN254Tracker,
): void {
  // Create inner tracker with cloned stack state
  const it = new BN254Tracker([...t.nm], e);
  // Propagate prime cache state: the cached prime on the alt-stack is
  // accessible within OP_IF branches since alt-stack persists across
  // IF/ELSE/ENDIF boundaries.
  it.primeCacheActive = t.primeCacheActive;

  // ------------------------------------------------------------------
  // Doubling-case detection: H = ax*jz^2 - jx == 0 ?
  // ------------------------------------------------------------------
  // Compute U2 = ax * jz^2 without consuming jx, jy, or jz, then compare
  // against a fresh copy of jx. Consumes only the copies.
  it.copyToTop('jz', '_jz_chk_in');
  bn254FieldSqr(it, '_jz_chk_in', '_jz_chk_sq');
  it.copyToTop('ax', '_ax_chk_copy');
  bn254FieldMul(it, '_ax_chk_copy', '_jz_chk_sq', '_u2_chk');
  it.copyToTop('jx', '_jx_chk_copy');
  it.rawBlock(['_u2_chk', '_jx_chk_copy'], '_h_is_zero', (emitInner) => {
    emitInner({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });

  // Move _h_is_zero to top so OP_IF can consume it.
  it.toTop('_h_is_zero');
  it.nm.pop(); // consumed by IF

  // ------------------------------------------------------------------
  // Gather doubling-branch ops
  // ------------------------------------------------------------------
  const doublingOps: StackOp[] = [];
  const doublingEmit = (op: StackOp) => doublingOps.push(op);
  const doublingTracker = new BN254Tracker([...it.nm], doublingEmit);
  doublingTracker.primeCacheActive = it.primeCacheActive;
  bn254G1JacobianDouble(doublingTracker);

  // ------------------------------------------------------------------
  // Gather standard-add-branch ops
  // ------------------------------------------------------------------
  const addOps: StackOp[] = [];
  const addEmit = (op: StackOp) => addOps.push(op);
  const addTracker = new BN254Tracker([...it.nm], addEmit);
  addTracker.primeCacheActive = it.primeCacheActive;
  bn254BuildJacobianAddAffineStandard(addTracker);

  // Both branches leave (jx, jy, jz) replacing the originals with the
  // same stack layout.
  it._e({ op: 'if', then: doublingOps, else: addOps });
  it.nm = doublingTracker.nm;
}

// ===========================================================================
// G1 point negation
// ===========================================================================

/** bn254G1Negate: negate a point (x, p - y). */
export function bn254G1Negate(
  t: BN254Tracker,
  pointName: string,
  resultName: string,
): void {
  bn254DecomposePoint(t, pointName, '_nx', '_ny');
  // Use bn254FieldNeg which already handles prime caching
  bn254FieldNeg(t, '_ny', '_neg_y');
  bn254ComposePoint(t, '_nx', '_neg_y', resultName);
}

// ===========================================================================
// Public emit functions — entry points called from 05-stack-lower.ts
// ===========================================================================

/**
 * emitBn254FieldAdd: BN254 field addition.
 * Stack in:  [..., a, b] (b on top)
 * Stack out: [..., (a + b) mod p]
 */
export function emitBn254FieldAdd(emit: (op: StackOp) => void): void {
  const t = new BN254Tracker(['a', 'b'], emit);
  t.pushPrimeCache();
  bn254FieldAdd(t, 'a', 'b', 'result');
  t.popPrimeCache();
}

/**
 * emitBn254FieldSub: BN254 field subtraction.
 * Stack in:  [..., a, b] (b on top)
 * Stack out: [..., (a - b) mod p]
 */
export function emitBn254FieldSub(emit: (op: StackOp) => void): void {
  const t = new BN254Tracker(['a', 'b'], emit);
  t.pushPrimeCache();
  bn254FieldSub(t, 'a', 'b', 'result');
  t.popPrimeCache();
}

/**
 * emitBn254FieldMul: BN254 field multiplication.
 * Stack in:  [..., a, b] (b on top)
 * Stack out: [..., (a * b) mod p]
 */
export function emitBn254FieldMul(emit: (op: StackOp) => void): void {
  const t = new BN254Tracker(['a', 'b'], emit);
  t.pushPrimeCache();
  bn254FieldMul(t, 'a', 'b', 'result');
  t.popPrimeCache();
}

/**
 * emitBn254FieldInv: BN254 field multiplicative inverse.
 * Stack in:  [..., a]
 * Stack out: [..., a^(p-2) mod p]
 */
export function emitBn254FieldInv(emit: (op: StackOp) => void): void {
  const t = new BN254Tracker(['a'], emit);
  t.pushPrimeCache();
  bn254FieldInv(t, 'a', 'result');
  t.popPrimeCache();
}

/**
 * emitBn254FieldNeg: BN254 field negation.
 * Stack in:  [..., a]
 * Stack out: [..., (p - a) mod p]
 */
export function emitBn254FieldNeg(emit: (op: StackOp) => void): void {
  const t = new BN254Tracker(['a'], emit);
  t.pushPrimeCache();
  bn254FieldNeg(t, 'a', 'result');
  t.popPrimeCache();
}

/**
 * emitBn254G1Add: add two BN254 G1 points.
 * Stack in:  [point_a, point_b] (b on top)
 * Stack out: [result_point]
 */
export function emitBn254G1Add(emit: (op: StackOp) => void): void {
  const t = new BN254Tracker(['_pa', '_pb'], emit);
  t.pushPrimeCache();
  bn254DecomposePoint(t, '_pa', 'px', 'py');
  bn254DecomposePoint(t, '_pb', 'qx', 'qy');
  bn254G1AffineAdd(t);
  bn254ComposePoint(t, 'rx', 'ry', '_result');
  t.popPrimeCache();
}

/**
 * emitBn254G1ScalarMul: scalar multiplication P * k on BN254 G1.
 * Stack in:  [point, scalar] (scalar on top)
 * Stack out: [result_point]
 *
 * Uses 255-iteration MSB-first double-and-add with Jacobian coordinates.
 * k' = k + 3r ensures bit 255 is always set (r is the curve order).
 */
export function emitBn254G1ScalarMul(emit: (op: StackOp) => void): void {
  const t = new BN254Tracker(['_pt', '_k'], emit);
  t.pushPrimeCache();
  // Decompose to affine base point
  bn254DecomposePoint(t, '_pt', 'ax', 'ay');

  // k' = k + 3r: guarantees bit 255 is set.
  // k ∈ [1, r-1], so k+3r ∈ [3r+1, 4r-1]. Since 3r > 2^255, bit 255
  // is always 1. Adding 3r (≡ 0 mod r) preserves the EC point: k*G = (k+3r)*G.
  t.toTop('_k');
  t.pushBigInt('_r1', BN254_R);
  t.rawBlock(['_k', '_r1'], '_kr1', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.pushBigInt('_r2', BN254_R);
  t.rawBlock(['_kr1', '_r2'], '_kr2', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.pushBigInt('_r3', BN254_R);
  t.rawBlock(['_kr2', '_r3'], '_kr3', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.rename('_k');

  // Init accumulator = P (bit 255 of k+3r is always 1)
  t.copyToTop('ax', 'jx');
  t.copyToTop('ay', 'jy');
  t.pushInt('jz', 1n);

  // 255 iterations: bits 254 down to 0
  for (let bit = 254; bit >= 0; bit--) {
    // Double accumulator
    bn254G1JacobianDouble(t);

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
    bn254BuildJacobianAddAffineInline(addEmit, t);
    emit({ op: 'if', then: addOps, else: [] });
  }

  // Convert Jacobian to affine
  bn254G1JacobianToAffine(t, '_rx', '_ry');

  // Clean up base point and scalar
  t.toTop('ax');
  t.drop();
  t.toTop('ay');
  t.drop();
  t.toTop('_k');
  t.drop();

  // Compose result
  bn254ComposePoint(t, '_rx', '_ry', '_result');
  t.popPrimeCache();
}

/**
 * emitBn254G1Negate: negate a BN254 G1 point (x, p - y).
 * Stack in:  [point]
 * Stack out: [negated_point]
 */
export function emitBn254G1Negate(emit: (op: StackOp) => void): void {
  const t = new BN254Tracker(['_pt'], emit);
  t.pushPrimeCache();
  bn254G1Negate(t, '_pt', '_result');
  t.popPrimeCache();
}

/**
 * emitBn254G1OnCurve: check if point is on BN254 G1 (y^2 = x^3 + 3 mod p).
 * Stack in:  [point]
 * Stack out: [boolean]
 */
export function emitBn254G1OnCurve(emit: (op: StackOp) => void): void {
  const t = new BN254Tracker(['_pt'], emit);
  t.pushPrimeCache();
  bn254DecomposePoint(t, '_pt', '_x', '_y');

  // lhs = y^2
  bn254FieldSqr(t, '_y', '_y2');

  // rhs = x^3 + 3
  t.copyToTop('_x', '_x_copy');
  bn254FieldSqr(t, '_x', '_x2');
  bn254FieldMul(t, '_x2', '_x_copy', '_x3');
  t.pushInt('_three', 3n); // b = 3 for BN254
  bn254FieldAdd(t, '_x3', '_three', '_rhs');

  // Compare
  t.toTop('_y2');
  t.toTop('_rhs');
  t.rawBlock(['_y2', '_rhs'], '_result', (e) => {
    e({ op: 'opcode', code: 'OP_EQUAL' });
  });
  t.popPrimeCache();
}
