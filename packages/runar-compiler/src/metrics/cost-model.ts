/**
 * Script-byte cost model for Stack IR.
 *
 * Optimizer passes need to compare two candidate lowerings by the metric that
 * actually matters — serialized locking-script bytes — before either one is
 * emitted. `OP_DUP` and a 33-byte constant push are one instruction each and
 * 1 vs 34 bytes; an instruction count cannot tell them apart.
 *
 * This module is deliberately NOT an approximation. Every push routes through
 * the same `push-encoding.ts` encoders that `06-emit.ts` uses, and the
 * structural cases mirror `emitStackOp` / `emitIf` one-for-one. The invariant
 *
 *     estimateScriptBytes(ops) === emitMethod({ ops, ... }).scriptHex.length / 2
 *
 * is asserted over the whole conformance corpus in
 * `__tests__/cost-model.test.ts`. If you change push encoding or the emit
 * switch, that sweep is what tells you this file went stale.
 */

import type { StackOp } from '../ir/index.js';
import { OPCODES } from '../passes/06-emit.js';
import { encodePushBigIntHex, encodePushBytesHex } from '../passes/push-encoding.js';

/**
 * Serialized byte cost of a single push value.
 *
 * Mirrors `encodePushValue` in `06-emit.ts`: booleans are the 1-byte OP_TRUE /
 * OP_FALSE, bigints go through the small-int opcodes where possible, and byte
 * arrays are MINIMALDATA-aware before falling back to a length-prefixed push.
 */
export function sizeOfPushValue(value: Uint8Array | bigint | boolean): number {
  if (typeof value === 'boolean') {
    return 1; // OP_TRUE (0x51) / OP_FALSE (0x00)
  }
  if (typeof value === 'bigint') {
    return encodePushBigIntHex(value).length / 2;
  }
  return encodePushBytesHex(value).length / 2;
}

/**
 * Serialized byte cost of one Stack IR operation, including nested `if` arms.
 *
 * Note on `pick` / `roll`: they cost ONE byte here. The depth operand is a
 * separate `push` op that the lowerer emits immediately before (see
 * `bringToTop` in `05-stack-lower.ts`), so charging the depth here would
 * double-count it.
 *
 * Throws on an unknown opcode mnemonic rather than costing it zero — a typo
 * in a codegen module should surface as a loud failure, not as a cost model
 * that quietly under-reports.
 */
export function sizeOfStackOp(op: StackOp): number {
  switch (op.op) {
    case 'push':
      return sizeOfPushValue(op.value);

    case 'dup':
    case 'swap':
    case 'roll':
    case 'pick':
    case 'drop':
    case 'nip':
    case 'over':
    case 'rot':
    case 'tuck':
      return 1;

    case 'opcode': {
      if (OPCODES[op.code] === undefined) {
        throw new Error(`cost-model: unknown opcode '${op.code}'`);
      }
      return 1;
    }

    case 'if': {
      // OP_IF + then + [OP_ELSE + else] + OP_ENDIF. The emitter writes
      // OP_ELSE only for a NON-EMPTY else arm (`emitIf` in 06-emit.ts).
      let total = 2; // OP_IF + OP_ENDIF
      total += estimateScriptBytes(op.then);
      if (op.else && op.else.length > 0) {
        total += 1 + estimateScriptBytes(op.else);
      }
      return total;
    }

    case 'placeholder':
    case 'push_codesep_index':
      // Both emit a single 0x00 byte that the SDK rewrites later.
      return 1;

    case 'raw_bytes':
      return op.bytes.length;
  }
}

/** Serialized byte cost of a Stack IR op sequence. */
export function estimateScriptBytes(ops: StackOp[]): number {
  let total = 0;
  for (const op of ops) {
    total += sizeOfStackOp(op);
  }
  return total;
}
