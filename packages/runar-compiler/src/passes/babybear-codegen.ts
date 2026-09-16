/**
 * Baby Bear field arithmetic codegen — Baby Bear prime field operations for Bitcoin Script.
 *
 * Follows the ec-codegen.ts pattern: self-contained module imported by
 * 05-stack-lower.ts. Uses a BBTracker for named stack state tracking.
 *
 * Baby Bear prime: p = 2^31 - 2^27 + 1 = 2013265921
 * Used by SP1 STARK proofs (FRI verification).
 *
 * All values fit in a single BSV script number (31-bit prime).
 * No multi-limb arithmetic needed.
 */

import type { StackOp } from '../ir/index.js';

// ===========================================================================
// Constants
// ===========================================================================

/** Baby Bear field prime p = 2^31 - 2^27 + 1 */
const BB_P = 2013265921n;
/** p - 2, used for Fermat's little theorem modular inverse */
const BB_P_MINUS_2 = BB_P - 2n;

// ===========================================================================
// BBTracker — named stack state tracker (mirrors ECTracker)
// ===========================================================================

class BBTracker {
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
    throw new Error(`BBTracker: '${name}' not on stack [${this.nm.join(',')}]`);
  }

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
      const third = this.nm[L - 3]!;
      this.nm[L - 3] = this.nm[L - 2]!;
      this.nm[L - 2] = this.nm[L - 1]!;
      this.nm[L - 1] = third;
    }
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

  roll(d: number): void {
    if (d === 0) return;
    if (d === 1) { this.swap(); return; }
    if (d === 2) { this.rot(); return; }
    this._e({ op: 'push', value: BigInt(d) });
    this.nm.push(null);
    this._e({ op: 'roll', depth: d });
    this.nm.pop();
    const idx = this.nm.length - 1 - d;
    const item = this.nm.splice(idx, 1)[0]!;
    this.nm.push(item);
  }

  /** Bring a named value to stack top (non-consuming copy via PICK) */
  copyToTop(name: string, newName: string): void {
    this.pick(this.findDepth(name), newName);
  }

  /** Bring a named value to stack top (consuming via ROLL) */
  toTop(name: string): void {
    const d = this.findDepth(name);
    if (d === 0) return;
    this.roll(d);
  }

  /** Rename the top-of-stack entry. The old name is replaced. */
  rename(newName: string): void {
    this.nm[this.nm.length - 1] = newName;
  }

  /**
   * rawBlock: consume named inputs from TOS, emit raw opcodes, produce named result.
   * The callback can emit arbitrary opcodes; the tracker adjusts the name stack.
   */
  rawBlock(consume: string[], produce: string | null, fn: (e: (op: StackOp) => void) => void): void {
    fn(this._e);
    for (let i = 0; i < consume.length; i++) this.nm.pop();
    if (produce !== null) this.nm.push(produce);
  }
}

// ===========================================================================
// Field arithmetic internals
// ===========================================================================

/**
 * fieldMod: ensure value is in [0, p).
 * For Baby Bear, inputs from add/mul are already non-negative, but sub can produce negatives.
 * Pattern: (a % p + p) % p
 */
function fieldMod(t: BBTracker, aName: string, resultName: string): void {
  t.toTop(aName);
  t.rawBlock([aName], resultName, (e) => {
    // (a % p + p) % p — handles negative values from sub
    e({ op: 'push', value: BB_P });
    e({ op: 'opcode', code: 'OP_MOD' });
    e({ op: 'push', value: BB_P });
    e({ op: 'opcode', code: 'OP_ADD' });
    e({ op: 'push', value: BB_P });
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

/** fieldAdd: (a + b) mod p */
function fieldAdd(t: BBTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_bb_add', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  // Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD suffices
  t.toTop('_bb_add');
  t.rawBlock(['_bb_add'], resultName, (e) => {
    e({ op: 'push', value: BB_P });
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

/** fieldSub: (a - b) mod p (non-negative) */
function fieldSub(t: BBTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_bb_diff', (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
  });
  // Difference can be negative, need full mod-reduce
  fieldMod(t, '_bb_diff', resultName);
}

/** fieldMul: (a * b) mod p */
function fieldMul(t: BBTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_bb_prod', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  // Product of two non-negative values is non-negative, simple OP_MOD
  t.toTop('_bb_prod');
  t.rawBlock(['_bb_prod'], resultName, (e) => {
    e({ op: 'push', value: BB_P });
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

/** fieldSqr: (a * a) mod p */
function fieldSqr(t: BBTracker, aName: string, resultName: string): void {
  t.copyToTop(aName, '_bb_sqr_copy');
  fieldMul(t, aName, '_bb_sqr_copy', resultName);
}

/**
 * fieldInv: a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
 * p-2 = 2013265919 = 0b111_0111_1111_1111_1111_1111_1111_1111
 * 31 bits, popcount 28.
 * ~30 squarings + ~27 multiplies = ~57 compound operations.
 */
function fieldInv(t: BBTracker, aName: string, resultName: string): void {
  // Binary representation of p-2 = 2013265919:
  // Bit 30 (MSB): 1
  // Bits 29..28: 11
  // Bit 27: 0
  // Bits 26..0: all 1's (27 ones)

  // Start: result = a (for MSB bit 30 = 1)
  t.copyToTop(aName, '_inv_r');

  // Process bits 29 down to 0 (30 bits)
  const pMinus2 = Number(BB_P_MINUS_2);
  for (let i = 29; i >= 0; i--) {
    // Always square
    fieldSqr(t, '_inv_r', '_inv_r2');
    t.rename('_inv_r');

    // Multiply if bit is set
    if ((pMinus2 >> i) & 1) {
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
// Public emit functions — entry points called from 05-stack-lower.ts
// ===========================================================================

/**
 * R-119 — a witness-supplied field element must BE a field element, aborting
 * form.
 *
 * Nothing in this module or its KoalaBear twin ever compared anything: the
 * OP_LESSTHAN / OP_WITHIN / OP_GREATERTHANOREQUAL count in both was zero. Every
 * operand of the four scalar builtins and the eight ext4 entry points is an
 * unlock argument and went straight into OP_ADD / OP_SUB / OP_MUL / OP_MOD.
 *
 * The `v` vs `v + p` half of the finding did NOT reproduce — every emitter
 * reduces its result mod p, so `bbFieldAdd(5+p, 0)` and `bbFieldAdd(5, 0)` both
 * returned 5. The NEGATIVE half did: `fieldAdd` and `fieldMul` reduce with a
 * BARE OP_MOD on the documented assumption that both operands are already in
 * [0, p-1], and OP_MOD takes the sign of the dividend. Measured before this
 * gate: `bbFieldAdd(-1, 0) -> -1` against `bbFieldAdd(p-1, 0) -> 2013265920`,
 * and the same for mul, inv and the ext4 components. Two different script
 * numbers for one residue, out of a builtin whose declared codomain is the
 * field — and script equality is numeric, so the escaped spelling breaks every
 * downstream `===` and every serialisation of the element.
 *
 * REJECT, not reduce, and gate the INPUT: a reduce would leave `v` and `v + p`
 * as two accepted spellings of one element, which is the aliasing this finding
 * is about. Gating the input makes the builtins canonical-in / canonical-out, so
 * the gate is idempotent under composition. ABORTING because these are VALUE
 * builtins — the split R-117 drew for EC and CL-BUG-095 set for the Point width.
 *
 * Public entry points only. The internal helpers run hundreds of times inside
 * `fieldInv` and the ext4 components on values canonical by construction.
 */
function emitCanonVerify(t: BBTracker, p: bigint, ...names: string[]): void {
  for (const n of names) {
    t.copyToTop(n, '_cv');
    t.rawBlock(['_cv'], null, (e) => {
      e({ op: 'push', value: 0n });
      e({ op: 'push', value: p });
      e({ op: 'opcode', code: 'OP_WITHIN' });
      e({ op: 'opcode', code: 'OP_VERIFY' });
    });
  }
}

/**
 * emitBBFieldAdd: Baby Bear field addition.
 * Stack in: [..., a, b] (b on top)
 * Stack out: [..., (a + b) mod p]
 */
export function emitBBFieldAdd(emit: (op: StackOp) => void): void {
  const t = new BBTracker(['a', 'b'], emit);
  emitCanonVerify(t, BB_P, 'a', 'b');
  fieldAdd(t, 'a', 'b', 'result');
  // Stack should now be: [result]
}

/**
 * emitBBFieldSub: Baby Bear field subtraction.
 * Stack in: [..., a, b] (b on top)
 * Stack out: [..., (a - b) mod p]
 */
export function emitBBFieldSub(emit: (op: StackOp) => void): void {
  const t = new BBTracker(['a', 'b'], emit);
  emitCanonVerify(t, BB_P, 'a', 'b');
  fieldSub(t, 'a', 'b', 'result');
}

/**
 * emitBBFieldMul: Baby Bear field multiplication.
 * Stack in: [..., a, b] (b on top)
 * Stack out: [..., (a * b) mod p]
 */
export function emitBBFieldMul(emit: (op: StackOp) => void): void {
  const t = new BBTracker(['a', 'b'], emit);
  emitCanonVerify(t, BB_P, 'a', 'b');
  fieldMul(t, 'a', 'b', 'result');
}

/**
 * emitBBFieldInv: Baby Bear field multiplicative inverse.
 * Stack in: [..., a]
 * Stack out: [..., a^(p-2) mod p]
 */
export function emitBBFieldInv(emit: (op: StackOp) => void): void {
  const t = new BBTracker(['a'], emit);
  emitCanonVerify(t, BB_P, 'a');
  fieldInv(t, 'a', 'result');
}

// ===========================================================================
// Quartic extension field operations (W = 11)
// ===========================================================================
// Extension: F[X]/(X^4 - 11).  Elements (a0, a1, a2, a3).
// Multiplication:
//   r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
//   r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
//   r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
//   r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
// ===========================================================================

const BB_W = 11n;

/** fieldMulConst: (a * c) mod p where c is a constant */
function fieldMulConst(t: BBTracker, aName: string, c: bigint, resultName: string): void {
  t.toTop(aName);
  t.rawBlock([aName], '_bb_mc', (e) => {
    e({ op: 'push', value: c });
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  t.toTop('_bb_mc');
  t.rawBlock(['_bb_mc'], resultName, (e) => {
    e({ op: 'push', value: BB_P });
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

/**
 * Emit ext4 mul component 0: a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
 * Stack in: [a0, a1, a2, a3, b0, b1, b2, b3]
 * Stack out: [result]
 */
function emitExt4MulComponent(emit: (op: StackOp) => void, component: number): void {
  const t = new BBTracker(['a0', 'a1', 'a2', 'a3', 'b0', 'b1', 'b2', 'b3'], emit);
  emitCanonVerify(t, BB_P, 'a0', 'a1', 'a2', 'a3', 'b0', 'b1', 'b2', 'b3');

  // Each component of the ext4 multiplication
  switch (component) {
    case 0: {
      // r0 = a0*b0 + 11*(a1*b3 + a2*b2 + a3*b1)
      t.copyToTop('a0', '_a0'); t.copyToTop('b0', '_b0');
      fieldMul(t, '_a0', '_b0', '_t0');     // a0*b0
      t.copyToTop('a1', '_a1'); t.copyToTop('b3', '_b3');
      fieldMul(t, '_a1', '_b3', '_t1');     // a1*b3
      t.copyToTop('a2', '_a2'); t.copyToTop('b2', '_b2');
      fieldMul(t, '_a2', '_b2', '_t2');     // a2*b2
      fieldAdd(t, '_t1', '_t2', '_t12');    // a1*b3 + a2*b2
      t.copyToTop('a3', '_a3'); t.copyToTop('b1', '_b1');
      fieldMul(t, '_a3', '_b1', '_t3');     // a3*b1
      fieldAdd(t, '_t12', '_t3', '_cross'); // a1*b3 + a2*b2 + a3*b1
      fieldMulConst(t, '_cross', BB_W, '_wcross'); // W * cross
      fieldAdd(t, '_t0', '_wcross', '_r');  // a0*b0 + W*cross
      break;
    }
    case 1: {
      // r1 = a0*b1 + a1*b0 + 11*(a2*b3 + a3*b2)
      t.copyToTop('a0', '_a0'); t.copyToTop('b1', '_b1');
      fieldMul(t, '_a0', '_b1', '_t0');     // a0*b1
      t.copyToTop('a1', '_a1'); t.copyToTop('b0', '_b0');
      fieldMul(t, '_a1', '_b0', '_t1');     // a1*b0
      fieldAdd(t, '_t0', '_t1', '_direct'); // a0*b1 + a1*b0
      t.copyToTop('a2', '_a2'); t.copyToTop('b3', '_b3');
      fieldMul(t, '_a2', '_b3', '_t2');     // a2*b3
      t.copyToTop('a3', '_a3'); t.copyToTop('b2', '_b2');
      fieldMul(t, '_a3', '_b2', '_t3');     // a3*b2
      fieldAdd(t, '_t2', '_t3', '_cross');  // a2*b3 + a3*b2
      fieldMulConst(t, '_cross', BB_W, '_wcross'); // W * cross
      fieldAdd(t, '_direct', '_wcross', '_r');
      break;
    }
    case 2: {
      // r2 = a0*b2 + a1*b1 + a2*b0 + 11*(a3*b3)
      t.copyToTop('a0', '_a0'); t.copyToTop('b2', '_b2');
      fieldMul(t, '_a0', '_b2', '_t0');     // a0*b2
      t.copyToTop('a1', '_a1'); t.copyToTop('b1', '_b1');
      fieldMul(t, '_a1', '_b1', '_t1');     // a1*b1
      fieldAdd(t, '_t0', '_t1', '_sum01');
      t.copyToTop('a2', '_a2'); t.copyToTop('b0', '_b0');
      fieldMul(t, '_a2', '_b0', '_t2');     // a2*b0
      fieldAdd(t, '_sum01', '_t2', '_direct');
      t.copyToTop('a3', '_a3'); t.copyToTop('b3', '_b3');
      fieldMul(t, '_a3', '_b3', '_t3');     // a3*b3
      fieldMulConst(t, '_t3', BB_W, '_wcross'); // W * a3*b3
      fieldAdd(t, '_direct', '_wcross', '_r');
      break;
    }
    case 3: {
      // r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
      t.copyToTop('a0', '_a0'); t.copyToTop('b3', '_b3');
      fieldMul(t, '_a0', '_b3', '_t0');     // a0*b3
      t.copyToTop('a1', '_a1'); t.copyToTop('b2', '_b2');
      fieldMul(t, '_a1', '_b2', '_t1');     // a1*b2
      fieldAdd(t, '_t0', '_t1', '_sum01');
      t.copyToTop('a2', '_a2'); t.copyToTop('b1', '_b1');
      fieldMul(t, '_a2', '_b1', '_t2');     // a2*b1
      fieldAdd(t, '_sum01', '_t2', '_sum012');
      t.copyToTop('a3', '_a3'); t.copyToTop('b0', '_b0');
      fieldMul(t, '_a3', '_b0', '_t3');     // a3*b0
      fieldAdd(t, '_sum012', '_t3', '_r');
      break;
    }
    default: throw new Error(`Invalid ext4 component: ${component}`);
  }

  // Clean up: drop the 8 input values, keep only _r
  for (const name of ['a0', 'a1', 'a2', 'a3', 'b0', 'b1', 'b2', 'b3']) {
    t.toTop(name);
    t.drop();
  }
  t.toTop('_r');
  t.rename('result');
}

/**
 * Emit ext4 inv component.
 * Tower-of-quadratic-extensions algorithm (matches Plonky3):
 *
 * View element as (even, odd) where even = (a0, a2), odd = (a1, a3)
 * in the quadratic extension F[X²]/(X⁴-W) = F'[Y]/(Y²-W) where Y = X².
 *
 * norm_0 = a0² + W*a2² - 2*W*a1*a3
 * norm_1 = 2*a0*a2 - a1² - W*a3²
 *
 * Quadratic inverse of (norm_0, norm_1):
 *   scalar = (norm_0² - W*norm_1²)^(-1)
 *   inv_n0 = norm_0 * scalar
 *   inv_n1 = -norm_1 * scalar (i.e. (p - norm_1) * scalar)
 *
 * Then: result = conjugate(a) * inv_norm
 *   conjugate(a) = (a0, -a1, a2, -a3)
 *   out_even = quad_mul((a0, a2), (inv_n0, inv_n1))
 *   out_odd  = quad_mul((-a1, -a3), (inv_n0, inv_n1))
 *   r0 = out_even[0], r1 = -out_odd[0], r2 = out_even[1], r3 = -out_odd[1]
 *
 * quad_mul((x0,x1),(y0,y1)) = (x0*y0 + W*x1*y1, x0*y1 + x1*y0)
 *
 * Stack in: [a0, a1, a2, a3]
 * Stack out: [result] (component at given index)
 */
function emitExt4InvComponent(emit: (op: StackOp) => void, component: number): void {
  const t = new BBTracker(['a0', 'a1', 'a2', 'a3'], emit);
  emitCanonVerify(t, BB_P, 'a0', 'a1', 'a2', 'a3');

  // Step 1: Compute norm_0 = a0² + W*a2² - 2*W*a1*a3
  t.copyToTop('a0', '_a0c');
  fieldSqr(t, '_a0c', '_a0sq');           // a0²
  t.copyToTop('a2', '_a2c');
  fieldSqr(t, '_a2c', '_a2sq');           // a2²
  fieldMulConst(t, '_a2sq', BB_W, '_wa2sq'); // W*a2²
  fieldAdd(t, '_a0sq', '_wa2sq', '_n0a');    // a0² + W*a2²
  t.copyToTop('a1', '_a1c');
  t.copyToTop('a3', '_a3c');
  fieldMul(t, '_a1c', '_a3c', '_a1a3');   // a1*a3
  fieldMulConst(t, '_a1a3', BB_W * 2n % BB_P, '_2wa1a3'); // 2*W*a1*a3
  fieldSub(t, '_n0a', '_2wa1a3', '_norm0'); // norm_0

  // Step 2: Compute norm_1 = 2*a0*a2 - a1² - W*a3²
  t.copyToTop('a0', '_a0d');
  t.copyToTop('a2', '_a2d');
  fieldMul(t, '_a0d', '_a2d', '_a0a2');   // a0*a2
  fieldMulConst(t, '_a0a2', 2n, '_2a0a2'); // 2*a0*a2
  t.copyToTop('a1', '_a1d');
  fieldSqr(t, '_a1d', '_a1sq');           // a1²
  fieldSub(t, '_2a0a2', '_a1sq', '_n1a'); // 2*a0*a2 - a1²
  t.copyToTop('a3', '_a3d');
  fieldSqr(t, '_a3d', '_a3sq');           // a3²
  fieldMulConst(t, '_a3sq', BB_W, '_wa3sq'); // W*a3²
  fieldSub(t, '_n1a', '_wa3sq', '_norm1'); // norm_1

  // Step 3: Quadratic inverse: scalar = (norm_0² - W*norm_1²)^(-1)
  t.copyToTop('_norm0', '_n0copy');
  fieldSqr(t, '_n0copy', '_n0sq');        // norm_0²
  t.copyToTop('_norm1', '_n1copy');
  fieldSqr(t, '_n1copy', '_n1sq');        // norm_1²
  fieldMulConst(t, '_n1sq', BB_W, '_wn1sq'); // W*norm_1²
  fieldSub(t, '_n0sq', '_wn1sq', '_det'); // norm_0² - W*norm_1²
  fieldInv(t, '_det', '_scalar');         // scalar = det^(-1)

  // Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
  t.copyToTop('_scalar', '_sc0');
  fieldMul(t, '_norm0', '_sc0', '_inv_n0'); // inv_n0 = norm_0 * scalar

  // -norm_1 = (p - norm_1) mod p
  t.copyToTop('_norm1', '_neg_n1_pre');
  t.pushInt('_pval', BB_P);
  t.toTop('_neg_n1_pre');
  t.rawBlock(['_pval', '_neg_n1_pre'], '_neg_n1_sub', (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
  });
  fieldMod(t, '_neg_n1_sub', '_neg_norm1');
  fieldMul(t, '_neg_norm1', '_scalar', '_inv_n1');

  // Step 5: Compute result components using quad_mul
  // quad_mul((x0,x1),(y0,y1)) = (x0*y0 + W*x1*y1, x0*y1 + x1*y0)
  // out_even = quad_mul((a0, a2), (inv_n0, inv_n1))
  // out_odd  = quad_mul((-a1, -a3), (inv_n0, inv_n1))
  // r0 = out_even[0], r1 = -out_odd[0], r2 = out_even[1], r3 = -out_odd[1]

  switch (component) {
    case 0: {
      // r0 = out_even[0] = a0*inv_n0 + W*a2*inv_n1
      t.copyToTop('a0', '_ea0');
      t.copyToTop('_inv_n0', '_ein0');
      fieldMul(t, '_ea0', '_ein0', '_ep0');   // a0*inv_n0
      t.copyToTop('a2', '_ea2');
      t.copyToTop('_inv_n1', '_ein1');
      fieldMul(t, '_ea2', '_ein1', '_ep1');   // a2*inv_n1
      fieldMulConst(t, '_ep1', BB_W, '_wep1'); // W*a2*inv_n1
      fieldAdd(t, '_ep0', '_wep1', '_r');
      break;
    }
    case 1: {
      // r1 = -odd_part[0] where odd_part = quad_mul((a1,a3), (inv_n0,inv_n1))
      // odd0 = a1*inv_n0 + W*a3*inv_n1
      // r1 = -odd0 = (p - odd0) mod p
      t.copyToTop('a1', '_oa1');
      t.copyToTop('_inv_n0', '_oin0');
      fieldMul(t, '_oa1', '_oin0', '_op0');   // a1*inv_n0
      t.copyToTop('a3', '_oa3');
      t.copyToTop('_inv_n1', '_oin1');
      fieldMul(t, '_oa3', '_oin1', '_op1');   // a3*inv_n1
      fieldMulConst(t, '_op1', BB_W, '_wop1'); // W*a3*inv_n1
      fieldAdd(t, '_op0', '_wop1', '_odd0');
      // Negate: r = (0 - odd0) mod p
      t.pushInt('_zero1', 0n);
      fieldSub(t, '_zero1', '_odd0', '_r');
      break;
    }
    case 2: {
      // r2 = out_even[1] = a0*inv_n1 + a2*inv_n0
      t.copyToTop('a0', '_ea0');
      t.copyToTop('_inv_n1', '_ein1');
      fieldMul(t, '_ea0', '_ein1', '_ep0');   // a0*inv_n1
      t.copyToTop('a2', '_ea2');
      t.copyToTop('_inv_n0', '_ein0');
      fieldMul(t, '_ea2', '_ein0', '_ep1');   // a2*inv_n0
      fieldAdd(t, '_ep0', '_ep1', '_r');
      break;
    }
    case 3: {
      // r3 = -odd_part[1] where odd1 = a1*inv_n1 + a3*inv_n0
      // r3 = -odd1 = (p - odd1) mod p
      t.copyToTop('a1', '_oa1');
      t.copyToTop('_inv_n1', '_oin1');
      fieldMul(t, '_oa1', '_oin1', '_op0');   // a1*inv_n1
      t.copyToTop('a3', '_oa3');
      t.copyToTop('_inv_n0', '_oin0');
      fieldMul(t, '_oa3', '_oin0', '_op1');   // a3*inv_n0
      fieldAdd(t, '_op0', '_op1', '_odd1');
      // Negate: r = (0 - odd1) mod p
      t.pushInt('_zero3', 0n);
      fieldSub(t, '_zero3', '_odd1', '_r');
      break;
    }
    default: throw new Error(`Invalid ext4 component: ${component}`);
  }

  // Clean up: drop all intermediate and input values, keep only _r
  const remaining = t.nm.filter(n => n !== null && n !== '_r') as string[];
  for (const name of remaining) {
    t.toTop(name);
    t.drop();
  }
  t.toTop('_r');
  t.rename('result');
}

// Ext4 multiplication component emitters
export function emitBBExt4Mul0(emit: (op: StackOp) => void): void { emitExt4MulComponent(emit, 0); }
export function emitBBExt4Mul1(emit: (op: StackOp) => void): void { emitExt4MulComponent(emit, 1); }
export function emitBBExt4Mul2(emit: (op: StackOp) => void): void { emitExt4MulComponent(emit, 2); }
export function emitBBExt4Mul3(emit: (op: StackOp) => void): void { emitExt4MulComponent(emit, 3); }

// Ext4 inverse component emitters
export function emitBBExt4Inv0(emit: (op: StackOp) => void): void { emitExt4InvComponent(emit, 0); }
export function emitBBExt4Inv1(emit: (op: StackOp) => void): void { emitExt4InvComponent(emit, 1); }
export function emitBBExt4Inv2(emit: (op: StackOp) => void): void { emitExt4InvComponent(emit, 2); }
export function emitBBExt4Inv3(emit: (op: StackOp) => void): void { emitExt4InvComponent(emit, 3); }
