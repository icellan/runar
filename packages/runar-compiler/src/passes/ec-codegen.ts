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

// ===========================================================================
// Constants
// ===========================================================================

/** secp256k1 field prime p = 2^256 - 2^32 - 977 */
const FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
/** p - 2, used for Fermat's little theorem modular inverse */
const FIELD_P_MINUS_2 = FIELD_P - 2n;
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

class ECTracker {
  nm: (string | null)[];
  _e: (op: StackOp) => void;

  constructor(init: (string | null)[], emit: (op: StackOp) => void) {
    this.nm = [...init];
    this._e = emit;
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
  // Push p directly as a BigInt — the emit pass encodes it as a proper
  // little-endian sign-magnitude script number push.
  t.pushInt(name, FIELD_P);
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
  // Bits 254 down to 32: all 1's (223 bits)
  for (let i = 0; i < 223; i++) {
    fieldSqr(t, '_inv_r', '_inv_r2');
    t.rename('_inv_r');
    t.copyToTop(aName, '_inv_a');
    fieldMul(t, '_inv_r', '_inv_a', '_inv_m');
    t.rename('_inv_r');
  }
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
  // s_num = qy - py
  t.copyToTop('qy', '_qy1');
  t.copyToTop('py', '_py1');
  fieldSub(t, '_qy1', '_py1', '_s_num');

  // s_den = qx - px
  t.copyToTop('qx', '_qx1');
  t.copyToTop('px', '_px1');
  fieldSub(t, '_qx1', '_px1', '_s_den');

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
  t.pushInt('_two1', 2n);
  fieldMul(t, '_B1', '_two1', '_2B');
  fieldSub(t, '_D2', '_2B', '_nx');

  // ny = D*(B - nx) - C
  t.copyToTop('_nx', '_nx_copy');
  fieldSub(t, '_B_save', '_nx_copy', '_B_nx');
  fieldMul(t, '_D_save', '_B_nx', '_D_B_nx');
  fieldSub(t, '_D_B_nx', '_C', '_ny');

  // nz = 2 * Y * Z
  fieldMul(t, '_jy_save', '_jz_save', '_yz');
  t.pushInt('_two2', 2n);
  fieldMul(t, '_yz', '_two2', '_nz');

  // Clean up leftover _B, rename results
  t.toTop('_B'); t.drop();
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
  const it = new ECTracker([...t.nm], e);

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
  it.pushInt('_two', 2n);
  fieldMul(it, '_U1H2', '_two', '_2U1H2');
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

// ===========================================================================
// Public entry points (called from stack lowerer)
// ===========================================================================

/**
 * ecAdd: add two points.
 * Stack in: [point_a, point_b] (b on top)
 * Stack out: [result_point]
 */
export function emitEcAdd(emit: (op: StackOp) => void): void {
  const t = new ECTracker(['_pa', '_pb'], emit);
  decomposePoint(t, '_pa', 'px', 'py');
  decomposePoint(t, '_pb', 'qx', 'qy');
  affineAdd(t);
  composePoint(t, 'rx', 'ry', '_result');
}

/**
 * ecMul: scalar multiplication P * k.
 * Stack in: [point, scalar] (scalar on top)
 * Stack out: [result_point]
 *
 * Uses 256-iteration double-and-add with Jacobian coordinates.
 */
export function emitEcMul(emit: (op: StackOp) => void): void {
  const t = new ECTracker(['_pt', '_k'], emit);
  // Decompose to affine base point
  decomposePoint(t, '_pt', 'ax', 'ay');
  // Initialize Jacobian accumulator = base point (Z=1)
  t.copyToTop('ax', 'jx');
  t.copyToTop('ay', 'jy');
  t.pushInt('jz', 1n);

  // 255 iterations: bits 254 down to 0
  for (let bit = 254; bit >= 0; bit--) {
    // Double accumulator
    jacobianDouble(t);

    // Extract bit: (k >> bit) & 1, using OP_DIV for right-shift
    t.copyToTop('_k', '_k_copy');
    if (bit > 0) {
      const divisor = 1n << BigInt(bit);
      t.pushInt('_div', divisor);
      t.rawBlock(['_k_copy', '_div'], '_shifted', (e) => {
        e({ op: 'opcode', code: 'OP_DIV' });
      });
    } else {
      t.rename('_shifted');
    }
    t.pushInt('_one', 1n);
    t.rawBlock(['_shifted', '_one'], '_bit', (e) => {
      e({ op: 'opcode', code: 'OP_AND' });
    });

    // Conditional add: if bit is 1, add base point to accumulator
    const addOps: StackOp[] = [];
    const addEmit = (op: StackOp) => addOps.push(op);
    buildJacobianAddAffineInline(addEmit, t);
    t.toTop('_bit');
    t.nm.pop(); // consumed by IF
    emit({ op: 'if', then: addOps, else: [] });
  }

  // Convert Jacobian to affine
  jacobianToAffine(t, '_rx', '_ry');

  // Clean up base point and scalar
  t.toTop('ax'); t.drop();
  t.toTop('ay'); t.drop();
  t.toTop('_k'); t.drop();

  // Compose result
  composePoint(t, '_rx', '_ry', '_result');
}

/**
 * ecMulGen: scalar multiplication G * k.
 * Stack in: [scalar]
 * Stack out: [result_point]
 */
export function emitEcMulGen(emit: (op: StackOp) => void): void {
  // Push generator point as 64-byte blob, then delegate to ecMul
  const gPoint = new Uint8Array(64);
  gPoint.set(bigintToBytes32(GEN_X), 0);
  gPoint.set(bigintToBytes32(GEN_Y), 32);
  emit({ op: 'push', value: gPoint });
  emit({ op: 'swap' }); // [point, scalar]
  emitEcMul(emit);
}

/**
 * ecNegate: negate a point (x, p - y).
 * Stack in: [point]
 * Stack out: [negated_point]
 */
export function emitEcNegate(emit: (op: StackOp) => void): void {
  const t = new ECTracker(['_pt'], emit);
  decomposePoint(t, '_pt', '_nx', '_ny');
  pushFieldP(t, '_fp');
  fieldSub(t, '_fp', '_ny', '_neg_y');
  composePoint(t, '_nx', '_neg_y', '_result');
}

/**
 * ecOnCurve: check if point is on secp256k1 (y² ≡ x³ + 7 mod p).
 * Stack in: [point]
 * Stack out: [boolean]
 */
export function emitEcOnCurve(emit: (op: StackOp) => void): void {
  const t = new ECTracker(['_pt'], emit);
  decomposePoint(t, '_pt', '_x', '_y');

  // lhs = y²
  fieldSqr(t, '_y', '_y2');

  // rhs = x³ + 7
  t.copyToTop('_x', '_x_copy');
  fieldSqr(t, '_x', '_x2');
  fieldMul(t, '_x2', '_x_copy', '_x3');
  t.pushInt('_seven', 7n);
  fieldAdd(t, '_x3', '_seven', '_rhs');

  // Compare
  t.toTop('_y2');
  t.toTop('_rhs');
  t.rawBlock(['_y2', '_rhs'], '_result', (e) => {
    e({ op: 'opcode', code: 'OP_EQUAL' });
  });
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
  emit({ op: 'push', value: 1n });
  emit({ op: 'opcode', code: 'OP_AND' });
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
