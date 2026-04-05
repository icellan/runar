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
 * emitBBFieldAdd: Baby Bear field addition.
 * Stack in: [..., a, b] (b on top)
 * Stack out: [..., (a + b) mod p]
 */
export function emitBBFieldAdd(emit: (op: StackOp) => void): void {
  const t = new BBTracker(['a', 'b'], emit);
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
  fieldSub(t, 'a', 'b', 'result');
}

/**
 * emitBBFieldMul: Baby Bear field multiplication.
 * Stack in: [..., a, b] (b on top)
 * Stack out: [..., (a * b) mod p]
 */
export function emitBBFieldMul(emit: (op: StackOp) => void): void {
  const t = new BBTracker(['a', 'b'], emit);
  fieldMul(t, 'a', 'b', 'result');
}

/**
 * emitBBFieldInv: Baby Bear field multiplicative inverse.
 * Stack in: [..., a]
 * Stack out: [..., a^(p-2) mod p]
 */
export function emitBBFieldInv(emit: (op: StackOp) => void): void {
  const t = new BBTracker(['a'], emit);
  fieldInv(t, 'a', 'result');
}
