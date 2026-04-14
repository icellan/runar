/**
 * Koala Bear field arithmetic codegen — Koala Bear prime field operations for Bitcoin Script.
 *
 * Follows the ec-codegen.ts pattern: self-contained module imported by
 * 05-stack-lower.ts. Uses a KBTracker for named stack state tracking.
 *
 * Koala Bear prime: p = 2^31 - 2^24 + 1 = 2130706433
 * Used by Plonky3 / Circle STARK proofs (FRI verification).
 *
 * All values fit in a single BSV script number (31-bit prime).
 * No multi-limb arithmetic needed.
 */

import type { StackOp } from '../ir/index.js';

// ===========================================================================
// Constants
// ===========================================================================

/** Koala Bear field prime p = 2^31 - 2^24 + 1 */
const KB_P = 2130706433n;
/** p - 2, used for Fermat's little theorem modular inverse */
const KB_P_MINUS_2 = KB_P - 2n;

// ===========================================================================
// KBTracker — named stack state tracker (mirrors ECTracker)
// ===========================================================================

export class KBTracker {
  nm: (string | null)[];
  _e: (op: StackOp) => void;
  _primeCacheActive: boolean = false;

  constructor(init: (string | null)[], emit: (op: StackOp) => void) {
    this.nm = [...init];
    this._e = emit;
  }

  get depth(): number { return this.nm.length; }

  findDepth(name: string): number {
    for (let i = this.nm.length - 1; i >= 0; i--)
      if (this.nm[i] === name)
        return this.nm.length - 1 - i;
    throw new Error(`KBTracker: '${name}' not on stack [${this.nm.join(',')}]`);
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

  /**
   * pushPrimeCache: push the KoalaBear prime to the alt-stack for caching.
   * All subsequent field operations will use the cached prime instead of pushing fresh literals.
   * This significantly reduces script size during long operations like Poseidon2.
   */
  pushPrimeCache(): void {
    this._e({ op: 'push', value: KB_P });
    this._e({ op: 'opcode', code: 'OP_TOALTSTACK' });
    this._primeCacheActive = true;
  }

  /**
   * popPrimeCache: remove the cached prime from the alt-stack.
   */
  popPrimeCache(): void {
    this._e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    this._e({ op: 'drop' });
    this._primeCacheActive = false;
  }

  /**
   * emitPrime: emit the field prime onto the stack — either from cache (alt-stack) or fresh push.
   */
  emitPrime(e: (op: StackOp) => void): void {
    if (this._primeCacheActive) {
      e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      e({ op: 'dup' });
      e({ op: 'opcode', code: 'OP_TOALTSTACK' });
    } else {
      e({ op: 'push', value: KB_P });
    }
  }
}

// ===========================================================================
// Field arithmetic internals
// ===========================================================================

/**
 * fieldMod: ensure value is in [0, p).
 * For Koala Bear, inputs from add/mul are already non-negative, but sub can produce negatives.
 * Pattern: (a % p + p) % p
 */
export function kbFieldMod(t: KBTracker, aName: string, resultName: string): void {
  t.toTop(aName);
  t.rawBlock([aName], resultName, (e) => {
    // (a % p + p) % p — handles negative values from sub
    t.emitPrime(e);
    e({ op: 'opcode', code: 'OP_MOD' });
    t.emitPrime(e);
    e({ op: 'opcode', code: 'OP_ADD' });
    t.emitPrime(e);
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

/** kbFieldAddUnreduced: a + b WITHOUT modular reduction. Result in [0, 2p-2]. */
export function kbFieldAddUnreduced(t: KBTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
}

/** kbFieldAdd: (a + b) mod p */
export function kbFieldAdd(t: KBTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_kb_add', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  // Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD suffices
  t.toTop('_kb_add');
  t.rawBlock(['_kb_add'], resultName, (e) => {
    t.emitPrime(e);
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

// Legacy alias kept for internal use
function fieldMod(t: KBTracker, aName: string, resultName: string): void {
  kbFieldMod(t, aName, resultName);
}
function fieldAdd(t: KBTracker, aName: string, bName: string, resultName: string): void {
  kbFieldAdd(t, aName, bName, resultName);
}

/** kbFieldSub: (a - b) mod p (non-negative) */
export function kbFieldSub(t: KBTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_kb_diff', (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
  });
  // Difference can be negative, need full mod-reduce
  kbFieldMod(t, '_kb_diff', resultName);
}

// Legacy alias
function fieldSub(t: KBTracker, aName: string, bName: string, resultName: string): void {
  kbFieldSub(t, aName, bName, resultName);
}

/** kbFieldMul: (a * b) mod p */
export function kbFieldMul(t: KBTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_kb_prod', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  // Product of two non-negative values is non-negative, simple OP_MOD
  t.toTop('_kb_prod');
  t.rawBlock(['_kb_prod'], resultName, (e) => {
    t.emitPrime(e);
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

// Legacy alias
function fieldMul(t: KBTracker, aName: string, bName: string, resultName: string): void {
  kbFieldMul(t, aName, bName, resultName);
}

/** kbFieldSqr: (a * a) mod p */
export function kbFieldSqr(t: KBTracker, aName: string, resultName: string): void {
  t.copyToTop(aName, '_kb_sqr_copy');
  kbFieldMul(t, aName, '_kb_sqr_copy', resultName);
}

// Legacy alias
function fieldSqr(t: KBTracker, aName: string, resultName: string): void {
  kbFieldSqr(t, aName, resultName);
}

/**
 * kbFieldMulConst: (a * c) mod p where c is a small constant.
 * Uses OP_2MUL when c==2 and OP_LSHIFTNUM when c is a power of 2 > 2.
 */
export function kbFieldMulConst(t: KBTracker, aName: string, c: bigint, resultName: string): void {
  t.toTop(aName);
  if (c === 2n) {
    t.rawBlock([aName], '_kb_mc', (e) => {
      e({ op: 'opcode', code: 'OP_2MUL' });
    });
  } else if (c > 2n && (c & (c - 1n)) === 0n) {
    // power of 2 > 2: use OP_LSHIFTNUM
    let shift = 0;
    let tmp = c;
    while (tmp > 1n) { tmp >>= 1n; shift++; }
    t.rawBlock([aName], '_kb_mc', (e) => {
      e({ op: 'push', value: BigInt(shift) });
      e({ op: 'opcode', code: 'OP_LSHIFTNUM' });
    });
  } else {
    t.rawBlock([aName], '_kb_mc', (e) => {
      e({ op: 'push', value: c });
      e({ op: 'opcode', code: 'OP_MUL' });
    });
  }
  t.toTop('_kb_mc');
  t.rawBlock(['_kb_mc'], resultName, (e) => {
    t.emitPrime(e);
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

/**
 * kbFieldInv: a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
 * p-2 = 2130706431 = 0x7eFFFFFF = 0b0111_1110_1111_1111_1111_1111_1111_1111
 * 31 bits, popcount 30.
 * 30 squarings + 29 conditional multiplies (for each set bit except MSB).
 */
export function kbFieldInv(t: KBTracker, aName: string, resultName: string): void {
  // Start: result = a (for MSB bit 30 = 1)
  t.copyToTop(aName, '_inv_r');

  // Process bits 29 down to 0 (30 bits)
  const pMinus2 = Number(KB_P_MINUS_2);
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

// Legacy aliases
function fieldInv(t: KBTracker, aName: string, resultName: string): void {
  kbFieldInv(t, aName, resultName);
}
function fieldMulConst(t: KBTracker, aName: string, c: bigint, resultName: string): void {
  kbFieldMulConst(t, aName, c, resultName);
}

// ===========================================================================
// Public emit functions — entry points called from 05-stack-lower.ts
// ===========================================================================

/**
 * emitKBFieldAdd: Koala Bear field addition.
 * Stack in: [..., a, b] (b on top)
 * Stack out: [..., (a + b) mod p]
 */
export function emitKBFieldAdd(emit: (op: StackOp) => void): void {
  const t = new KBTracker(['a', 'b'], emit);
  fieldAdd(t, 'a', 'b', 'result');
  // Stack should now be: [result]
}

/**
 * emitKBFieldSub: Koala Bear field subtraction.
 * Stack in: [..., a, b] (b on top)
 * Stack out: [..., (a - b) mod p]
 */
export function emitKBFieldSub(emit: (op: StackOp) => void): void {
  const t = new KBTracker(['a', 'b'], emit);
  fieldSub(t, 'a', 'b', 'result');
}

/**
 * emitKBFieldMul: Koala Bear field multiplication.
 * Stack in: [..., a, b] (b on top)
 * Stack out: [..., (a * b) mod p]
 */
export function emitKBFieldMul(emit: (op: StackOp) => void): void {
  const t = new KBTracker(['a', 'b'], emit);
  fieldMul(t, 'a', 'b', 'result');
}

/**
 * emitKBFieldInv: Koala Bear field multiplicative inverse.
 * Stack in: [..., a]
 * Stack out: [..., a^(p-2) mod p]
 */
export function emitKBFieldInv(emit: (op: StackOp) => void): void {
  const t = new KBTracker(['a'], emit);
  fieldInv(t, 'a', 'result');
}

// ===========================================================================
// Quartic extension field operations (W = 3)
// ===========================================================================
// Extension: F[X]/(X^4 - 3).  Elements (a0, a1, a2, a3).
// Multiplication:
//   r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
//   r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
//   r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
//   r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
// ===========================================================================

const KB_W = 3n;

/**
 * Emit ext4 mul component 0: a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
 * Stack in: [a0, a1, a2, a3, b0, b1, b2, b3]
 * Stack out: [result]
 */
function emitExt4MulComponent(emit: (op: StackOp) => void, component: number): void {
  const t = new KBTracker(['a0', 'a1', 'a2', 'a3', 'b0', 'b1', 'b2', 'b3'], emit);

  // Each component of the ext4 multiplication
  switch (component) {
    case 0: {
      // r0 = a0*b0 + 3*(a1*b3 + a2*b2 + a3*b1)
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
      fieldMulConst(t, '_cross', KB_W, '_wcross'); // W * cross
      fieldAdd(t, '_t0', '_wcross', '_r');  // a0*b0 + W*cross
      break;
    }
    case 1: {
      // r1 = a0*b1 + a1*b0 + 3*(a2*b3 + a3*b2)
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
      fieldMulConst(t, '_cross', KB_W, '_wcross'); // W * cross
      fieldAdd(t, '_direct', '_wcross', '_r');
      break;
    }
    case 2: {
      // r2 = a0*b2 + a1*b1 + a2*b0 + 3*(a3*b3)
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
      fieldMulConst(t, '_t3', KB_W, '_wcross'); // W * a3*b3
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
 * in the quadratic extension F[X^2]/(X^4-W) = F'[Y]/(Y^2-W) where Y = X^2.
 *
 * norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
 * norm_1 = 2*a0*a2 - a1^2 - W*a3^2
 *
 * Quadratic inverse of (norm_0, norm_1):
 *   scalar = (norm_0^2 - W*norm_1^2)^(-1)
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
  const t = new KBTracker(['a0', 'a1', 'a2', 'a3'], emit);

  // Step 1: Compute norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
  t.copyToTop('a0', '_a0c');
  fieldSqr(t, '_a0c', '_a0sq');           // a0^2
  t.copyToTop('a2', '_a2c');
  fieldSqr(t, '_a2c', '_a2sq');           // a2^2
  fieldMulConst(t, '_a2sq', KB_W, '_wa2sq'); // W*a2^2
  fieldAdd(t, '_a0sq', '_wa2sq', '_n0a');    // a0^2 + W*a2^2
  t.copyToTop('a1', '_a1c');
  t.copyToTop('a3', '_a3c');
  fieldMul(t, '_a1c', '_a3c', '_a1a3');   // a1*a3
  fieldMulConst(t, '_a1a3', KB_W * 2n % KB_P, '_2wa1a3'); // 2*W*a1*a3
  fieldSub(t, '_n0a', '_2wa1a3', '_norm0'); // norm_0

  // Step 2: Compute norm_1 = 2*a0*a2 - a1^2 - W*a3^2
  t.copyToTop('a0', '_a0d');
  t.copyToTop('a2', '_a2d');
  fieldMul(t, '_a0d', '_a2d', '_a0a2');   // a0*a2
  fieldMulConst(t, '_a0a2', 2n, '_2a0a2'); // 2*a0*a2
  t.copyToTop('a1', '_a1d');
  fieldSqr(t, '_a1d', '_a1sq');           // a1^2
  fieldSub(t, '_2a0a2', '_a1sq', '_n1a'); // 2*a0*a2 - a1^2
  t.copyToTop('a3', '_a3d');
  fieldSqr(t, '_a3d', '_a3sq');           // a3^2
  fieldMulConst(t, '_a3sq', KB_W, '_wa3sq'); // W*a3^2
  fieldSub(t, '_n1a', '_wa3sq', '_norm1'); // norm_1

  // Step 3: Quadratic inverse: scalar = (norm_0^2 - W*norm_1^2)^(-1)
  t.copyToTop('_norm0', '_n0copy');
  fieldSqr(t, '_n0copy', '_n0sq');        // norm_0^2
  t.copyToTop('_norm1', '_n1copy');
  fieldSqr(t, '_n1copy', '_n1sq');        // norm_1^2
  fieldMulConst(t, '_n1sq', KB_W, '_wn1sq'); // W*norm_1^2
  fieldSub(t, '_n0sq', '_wn1sq', '_det'); // norm_0^2 - W*norm_1^2
  fieldInv(t, '_det', '_scalar');         // scalar = det^(-1)

  // Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
  t.copyToTop('_scalar', '_sc0');
  fieldMul(t, '_norm0', '_sc0', '_inv_n0'); // inv_n0 = norm_0 * scalar

  // -norm_1 = (p - norm_1) mod p
  t.copyToTop('_norm1', '_neg_n1_pre');
  t.pushInt('_pval', KB_P);
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
      fieldMulConst(t, '_ep1', KB_W, '_wep1'); // W*a2*inv_n1
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
      fieldMulConst(t, '_op1', KB_W, '_wop1'); // W*a3*inv_n1
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
export function emitKBExt4Mul0(emit: (op: StackOp) => void): void { emitExt4MulComponent(emit, 0); }
export function emitKBExt4Mul1(emit: (op: StackOp) => void): void { emitExt4MulComponent(emit, 1); }
export function emitKBExt4Mul2(emit: (op: StackOp) => void): void { emitExt4MulComponent(emit, 2); }
export function emitKBExt4Mul3(emit: (op: StackOp) => void): void { emitExt4MulComponent(emit, 3); }

// Ext4 inverse component emitters
export function emitKBExt4Inv0(emit: (op: StackOp) => void): void { emitExt4InvComponent(emit, 0); }
export function emitKBExt4Inv1(emit: (op: StackOp) => void): void { emitExt4InvComponent(emit, 1); }
export function emitKBExt4Inv2(emit: (op: StackOp) => void): void { emitExt4InvComponent(emit, 2); }
export function emitKBExt4Inv3(emit: (op: StackOp) => void): void { emitExt4InvComponent(emit, 3); }
