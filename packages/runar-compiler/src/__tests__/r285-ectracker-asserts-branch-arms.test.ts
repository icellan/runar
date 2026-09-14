/**
 * R-285 (CL-GAP-075) — `ECTracker.emitIf` must check its arms against the
 * result it declares.
 *
 * The tracker's stack model is updated from the CALLER's `resultName`
 * argument: one name pushed, or none. Nothing verified that against the
 * opcodes the two arms emit. A branch whose arms leave a different depth than
 * `resultName` promises leaves `nm` off by a constant for the rest of the
 * method, and every `findDepth` after it feeds a PICK or ROLL that addresses
 * the wrong stack item — a different locking script, with no diagnostic.
 *
 * `emitEcMul` runs this path 257 times per scalar multiplication, and the
 * P-256 / P-384 and BN254 codegens reuse the same tracker.
 */
import { describe, it, expect } from 'vitest';
import { ECTracker } from '../passes/ec-codegen.js';
import type { StackOp } from '../ir/stack-ir.js';

/** A tracker holding two named items, discarding the ops it emits. */
function tracker(): ECTracker {
  return new ECTracker(['a', 'cond'], () => {});
}

const push = (v: bigint) => (emit: (op: StackOp) => void) =>
  emit({ op: 'push', value: v } as StackOp);
const pushTwice = (v: bigint) => (emit: (op: StackOp) => void) => {
  emit({ op: 'push', value: v } as StackOp);
  emit({ op: 'push', value: v } as StackOp);
};
const nothing = () => (_emit: (op: StackOp) => void) => {};

describe('ECTracker.emitIf', () => {
  it('accepts arms that both produce the declared result', () => {
    const t = tracker();
    expect(() => t.emitIf('cond', push(1n), push(2n), 'r')).not.toThrow();
    // Condition consumed, result pushed: 'a' plus the new 'r'.
    expect(t.nm).toEqual(['a', 'r']);
  });

  it('accepts stack-neutral arms when no result is declared', () => {
    const t = tracker();
    expect(() => t.emitIf('cond', nothing(), nothing(), null)).not.toThrow();
    expect(t.nm).toEqual(['a']);
  });

  it('rejects arms that disagree with each other', () => {
    const t = tracker();
    expect(() => t.emitIf('cond', pushTwice(1n), push(2n), 'r'))
      .toThrow(/different stack depths/);
  });

  it('rejects arms that agree with each other but not with the declared result', () => {
    const t = tracker();
    expect(() => t.emitIf('cond', pushTwice(1n), pushTwice(2n), 'r'))
      .toThrow(/declares result/);
  });

  it('rejects a producing pair declared as yielding nothing', () => {
    const t = tracker();
    expect(() => t.emitIf('cond', push(1n), push(2n), null))
      .toThrow(/declares no result/);
  });

  it('refuses an arm containing an opcode with no modelled stack effect', () => {
    // The check must not score an unrecognised opcode as neutral — that is how
    // a guard like this becomes vacuous.
    const t = tracker();
    const bogus = (emit: (op: StackOp) => void) =>
      emit({ op: 'opcode', code: 'OP_NONSENSE' } as StackOp);
    expect(() => t.emitIf('cond', bogus, bogus, null)).toThrow(/no stack effect modelled/);
  });
});
