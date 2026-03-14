/**
 * BN254 Fp2 extension field arithmetic -> Bitcoin Script codegen.
 *
 * Fp2 = Fp[u] / (u^2 + 1). Each element is a pair (c0, c1) representing
 * c0 + c1*u, where u^2 = -1.
 *
 * ## Stack convention
 *
 * An Fp2 element occupies 2 stack slots: [..., c0, c1] where c1 is on top.
 * All functions consume their inputs and leave results in the same format.
 *
 * ## Altstack usage
 *
 * All operations assume P is on the altstack (via `emitInitP`). Intermediate
 * values are temporarily stored on the altstack as needed, always restored
 * before returning. Altstack state on entry and exit: [..., P].
 *
 * ## Multiplication strategy
 *
 * Uses Karatsuba: 3 Fp multiplications instead of 4.
 *   t0 = a0*b0, t1 = a1*b1
 *   c0 = t0 - t1  (since u^2 = -1)
 *   c1 = (a0+a1)*(b0+b1) - t0 - t1
 */

import type { StackOp } from 'runar-ir-schema';
import {
  emitFpAdd, emitFpSub, emitFpMul, emitFpSqr, emitFpNeg, emitFpInv,
  emitPushFp,
} from './field-script.js';

// ---------------------------------------------------------------------------
// Stack helpers — reusable across extension field codegen
// ---------------------------------------------------------------------------

/** Emit PICK at given depth. depth=0 is DUP, depth=1 is OVER. */
export function emitPick(ops: StackOp[], depth: number): void {
  if (depth === 0) {
    ops.push({ op: 'opcode', code: 'OP_DUP' } as StackOp);
  } else if (depth === 1) {
    ops.push({ op: 'opcode', code: 'OP_OVER' } as StackOp);
  } else {
    ops.push({ op: 'push', value: BigInt(depth) } as StackOp);
    ops.push({ op: 'opcode', code: 'OP_PICK' } as StackOp);
  }
}

/** Emit ROLL at given depth. depth=0 is nop, depth=1 is SWAP, depth=2 is ROT. */
export function emitRoll(ops: StackOp[], depth: number): void {
  if (depth === 0) {
    return;
  } else if (depth === 1) {
    ops.push({ op: 'swap' } as StackOp);
  } else if (depth === 2) {
    ops.push({ op: 'opcode', code: 'OP_ROT' } as StackOp);
  } else {
    ops.push({ op: 'push', value: BigInt(depth) } as StackOp);
    ops.push({ op: 'opcode', code: 'OP_ROLL' } as StackOp);
  }
}

/** Save top of stack to altstack. */
export function emitToAlt(ops: StackOp[]): void {
  ops.push({ op: 'opcode', code: 'OP_TOALTSTACK' } as StackOp);
}

/** Restore from altstack. */
export function emitFromAlt(ops: StackOp[]): void {
  ops.push({ op: 'opcode', code: 'OP_FROMALTSTACK' } as StackOp);
}

/** Drop top of stack. */
export function emitDrop(ops: StackOp[]): void {
  ops.push({ op: 'drop' } as StackOp);
}

/** Duplicate top of stack. */
export function emitDup(ops: StackOp[]): void {
  ops.push({ op: 'opcode', code: 'OP_DUP' } as StackOp);
}

// ---------------------------------------------------------------------------
// Fp2 pair helpers: copy/roll Fp2 elements (2 stack slots)
// ---------------------------------------------------------------------------

/**
 * Copy an Fp2 element whose c1 (top component) is at `depth` slots from TOS.
 * c0 is at depth+1. Pushes (c0, c1) on top.
 */
export function emitPickFp2(ops: StackOp[], depth: number): void {
  emitPick(ops, depth + 1); // copy c0
  emitPick(ops, depth + 1); // copy c1 (depth shifted +1 by the c0 copy)
}

/**
 * Roll an Fp2 element whose c1 is at `depth` slots from TOS to the top.
 * c0 is at depth+1. Removes from original position.
 */
export function emitRollFp2(ops: StackOp[], depth: number): void {
  emitRoll(ops, depth + 1); // roll c0 to top
  emitRoll(ops, depth + 1); // roll c1 to top (was at depth, shifted +1 by push of c0)
}

/**
 * Save top Fp2 to altstack. Alt order: c1 pushed first, then c0 (LIFO).
 * Restore with emitFromAltFp2.
 */
export function emitToAltFp2(ops: StackOp[]): void {
  emitToAlt(ops); // push c1
  emitToAlt(ops); // push c0
}

/**
 * Restore Fp2 from altstack (reverse of emitToAltFp2).
 * Pops c0 then c1, leaving [..., c0, c1] on stack.
 */
export function emitFromAltFp2(ops: StackOp[]): void {
  emitFromAlt(ops); // pop c0
  emitFromAlt(ops); // pop c1
}

/** Drop the top Fp2 element (2 slots). */
export function emitDropFp2(ops: StackOp[]): void {
  emitDrop(ops);
  emitDrop(ops);
}

// ---------------------------------------------------------------------------
// Fp2 operations
// ---------------------------------------------------------------------------

/**
 * Push an Fp2 constant (c0, c1) onto the stack.
 * Stack: [...] -> [..., c0, c1]
 */
export function emitPushFp2(ops: StackOp[], c0: bigint, c1: bigint): void {
  emitPushFp(ops, c0);
  emitPushFp(ops, c1);
}

/**
 * Fp2 addition: (a0+b0, a1+b1)
 * Stack: [..., a0, a1, b0, b1] -> [..., c0, c1]
 *
 * NOTE: Does NOT use altstack for intermediates (only emitFp* use it for P).
 */
export function emitFp2Add(ops: StackOp[]): void {
  // Stack: [a0, a1, b0, b1]
  emitRoll(ops, 2);       // [a0, b0, b1, a1]
  emitFpAdd(ops);         // [a0, b0, c1]
  emitRoll(ops, 2);       // [b0, c1, a0]
  emitRoll(ops, 2);       // [c1, a0, b0]
  emitFpAdd(ops);         // [c1, c0]
  ops.push({ op: 'swap' } as StackOp); // [c0, c1]
}

/**
 * Fp2 subtraction: (a0-b0, a1-b1)
 * Stack: [..., a0, a1, b0, b1] -> [..., c0, c1]
 */
export function emitFp2Sub(ops: StackOp[]): void {
  // Stack: [a0, a1, b0, b1]
  emitRoll(ops, 2);       // [a0, b0, b1, a1]
  ops.push({ op: 'swap' } as StackOp); // [a0, b0, a1, b1]
  emitFpSub(ops);         // [a0, b0, c1]
  emitRoll(ops, 2);       // [b0, c1, a0]
  emitRoll(ops, 2);       // [c1, a0, b0]
  emitFpSub(ops);         // [c1, c0]
  ops.push({ op: 'swap' } as StackOp); // [c0, c1]
}

/**
 * Fp2 negation: (-a0, -a1)
 * Stack: [..., a0, a1] -> [..., -a0, -a1]
 */
export function emitFp2Neg(ops: StackOp[]): void {
  emitFpNeg(ops);                         // [a0, -a1]
  ops.push({ op: 'swap' } as StackOp);   // [-a1, a0]
  emitFpNeg(ops);                         // [-a1, -a0]
  ops.push({ op: 'swap' } as StackOp);   // [-a0, -a1]
}

/**
 * Fp2 conjugate: (a0, -a1)
 * Stack: [..., a0, a1] -> [..., a0, -a1]
 */
export function emitFp2Conj(ops: StackOp[]): void {
  emitFpNeg(ops);
}

/**
 * Fp2 multiplication using Karatsuba.
 *
 *   t0 = a0*b0, t1 = a1*b1
 *   c0 = t0 - t1  (since u^2 = -1)
 *   c1 = (a0+a1)*(b0+b1) - t0 - t1
 *
 * Stack: [..., a0, a1, b0, b1] -> [..., c0, c1]
 *
 * Uses only main stack for intermediates (no altstack except P caching).
 */
export function emitFp2Mul(ops: StackOp[]): void {
  // Stack: [a0, a1, b0, b1]

  // --- t0 = a0 * b0 ---
  emitPick(ops, 3);       // [a0, a1, b0, b1, a0]
  emitPick(ops, 2);       // [a0, a1, b0, b1, a0, b0]
  emitFpMul(ops);         // [a0, a1, b0, b1, t0]

  // --- t1 = a1 * b1 ---
  emitPick(ops, 3);       // [a0, a1, b0, b1, t0, a1]
  emitPick(ops, 2);       // [a0, a1, b0, b1, t0, a1, b1]
  emitFpMul(ops);         // [a0, a1, b0, b1, t0, t1]

  // --- c0 = t0 - t1 ---
  emitPick(ops, 1);       // [..., t0, t1, t0]
  emitPick(ops, 1);       // [..., t0, t1, t0, t1]
  emitFpSub(ops);         // [a0, a1, b0, b1, t0, t1, c0]

  // Move c0 down below originals: we need it at the bottom
  // Current: [a0, a1, b0, b1, t0, t1, c0]
  // We'll compute c1 next. First, save c0 below by rolling.
  emitRoll(ops, 6);       // [a1, b0, b1, t0, t1, c0, a0]
  emitRoll(ops, 6);       // [b0, b1, t0, t1, c0, a0, a1]
  emitFpAdd(ops);         // [b0, b1, t0, t1, c0, a0+a1]
  emitRoll(ops, 5);       // [b1, t0, t1, c0, a0+a1, b0]
  emitRoll(ops, 5);       // [t0, t1, c0, a0+a1, b0, b1]
  emitFpAdd(ops);         // [t0, t1, c0, a0+a1, b0+b1]
  emitFpMul(ops);         // [t0, t1, c0, (a0+a1)*(b0+b1)]

  // c1 = product - t0 - t1
  // Stack: [t0, t1, c0, product]
  emitRoll(ops, 3);       // [t1, c0, product, t0]
  emitFpSub(ops);         // [t1, c0, product-t0]
  emitRoll(ops, 2);       // [c0, product-t0, t1]
  emitFpSub(ops);         // [c0, c1]
}

/**
 * Fp2 squaring.
 *   c0 = (a0+a1)(a0-a1)
 *   c1 = 2*a0*a1
 *
 * Stack: [..., a0, a1] -> [..., c0, c1]
 */
export function emitFp2Sqr(ops: StackOp[]): void {
  // Stack: [a0, a1]

  // c1 = 2 * a0 * a1
  emitPick(ops, 1);       // [a0, a1, a0]
  emitPick(ops, 1);       // [a0, a1, a0, a1]
  emitFpMul(ops);         // [a0, a1, a0*a1]
  emitDup(ops);           // [a0, a1, a0*a1, a0*a1]
  emitFpAdd(ops);         // [a0, a1, c1]

  // Move c1 below, then compute c0 on top
  emitRoll(ops, 2);       // [a1, c1, a0]
  emitRoll(ops, 2);       // [c1, a0, a1]

  // c0 = (a0 + a1) * (a0 - a1)
  emitPick(ops, 1);       // [c1, a0, a1, a0]
  emitPick(ops, 1);       // [c1, a0, a1, a0, a1]
  emitFpAdd(ops);         // [c1, a0, a1, a0+a1]
  emitRoll(ops, 2);       // [c1, a1, a0+a1, a0]
  emitRoll(ops, 2);       // [c1, a0+a1, a0, a1]
  emitFpSub(ops);         // [c1, a0+a1, a0-a1]
  emitFpMul(ops);         // [c1, c0]

  ops.push({ op: 'swap' } as StackOp); // [c0, c1]
}

/**
 * Multiply Fp2 element by xi = 9 + u.
 *
 * (a0 + a1*u)(9 + u) = (9*a0 - a1) + (a0 + 9*a1)*u
 *
 * Stack: [..., a0, a1] -> [..., 9*a0-a1, a0+9*a1]
 */
export function emitFp2MulByXi(ops: StackOp[]): void {
  // Stack: [a0, a1]
  // Result: [9*a0 - a1, a0 + 9*a1]

  // 9*a0
  emitPick(ops, 1);       // [a0, a1, a0]
  emitPushFp(ops, 9n);    // [a0, a1, a0, 9]
  emitFpMul(ops);         // [a0, a1, 9*a0]

  // 9*a1
  emitPick(ops, 1);       // [a0, a1, 9*a0, a1]
  emitPushFp(ops, 9n);    // [a0, a1, 9*a0, a1, 9]
  emitFpMul(ops);         // [a0, a1, 9*a0, 9*a1]

  // c1 = a0 + 9*a1: bring a0 up
  emitRoll(ops, 3);       // [a1, 9*a0, 9*a1, a0]
  emitFpAdd(ops);         // [a1, 9*a0, c1]

  // c0 = 9*a0 - a1: roll 9*a0 and a1 into position
  emitRoll(ops, 2);       // [9*a0, c1, a1]
  emitRoll(ops, 2);       // [c1, a1, 9*a0]
  ops.push({ op: 'swap' } as StackOp); // [c1, 9*a0, a1]
  emitFpSub(ops);         // [c1, c0]
  ops.push({ op: 'swap' } as StackOp); // [c0, c1]
}

/**
 * Fp2 inverse: 1/(a0 + a1*u) = (a0 - a1*u) / (a0^2 + a1^2)
 *
 * Stack: [..., a0, a1] -> [..., inv0, inv1]
 */
export function emitFp2Inv(ops: StackOp[]): void {
  // Stack: [a0, a1]

  // norm = a0^2 + a1^2
  emitPick(ops, 1);       // [a0, a1, a0]
  emitFpSqr(ops);         // [a0, a1, a0^2]
  emitPick(ops, 1);       // [a0, a1, a0^2, a1]
  emitFpSqr(ops);         // [a0, a1, a0^2, a1^2]
  emitFpAdd(ops);         // [a0, a1, norm]

  // inv_norm = norm^{-1}
  emitFpInv(ops);         // [a0, a1, inv_norm]

  // c1 = -a1 * inv_norm
  emitDup(ops);           // [a0, a1, inv_norm, inv_norm]
  emitRoll(ops, 2);       // [a0, inv_norm, inv_norm, a1]
  emitFpNeg(ops);         // [a0, inv_norm, inv_norm, -a1]
  emitFpMul(ops);         // [a0, inv_norm, c1]

  // c0 = a0 * inv_norm
  emitRoll(ops, 2);       // [inv_norm, c1, a0]
  emitRoll(ops, 2);       // [c1, a0, inv_norm]
  emitFpMul(ops);         // [c1, c0]
  ops.push({ op: 'swap' } as StackOp); // [c0, c1]
}

/**
 * Multiply Fp2 element by an Fp scalar.
 *
 * (a0 + a1*u) * s = (a0*s) + (a1*s)*u
 *
 * Stack: [..., a0, a1, s] -> [..., a0*s, a1*s]
 */
export function emitFp2MulScalar(ops: StackOp[]): void {
  // Stack: [a0, a1, s]
  emitDup(ops);           // [a0, a1, s, s]
  emitRoll(ops, 2);       // [a0, s, s, a1]
  emitFpMul(ops);         // [a0, s, a1*s]
  emitToAlt(ops);         // [a0, s]        alt: [a1*s]
  emitFpMul(ops);         // [a0*s]
  emitFromAlt(ops);       // [a0*s, a1*s]
}
