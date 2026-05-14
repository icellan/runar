/**
 * Rabin signature verification Bitcoin Script codegen.
 *
 * Splice into LoweringContext in 05-stack-lower.ts. Entry: lowerVerifyRabinSig()
 * in stack-lower → calls emitVerifyRabinSig().
 *
 * Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg)
 *
 * Input stack at entry (top-down): pubKey(0) padding(1) sig(2) msg(3)
 *   — i.e. bottom→top: msg sig padding pubKey
 * Output: <boolean>
 *
 * The opcode sequence is a fixed 10 opcodes:
 *   OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
 */

import type { StackOp } from '../ir/index.js';

type Emit = (op: StackOp) => void;

/**
 * Emit the Rabin signature verification opcode sequence.
 *
 * Stack before (bottom→top): msg sig padding pubKey
 * Script:
 *   OP_SWAP    -- msg sig pubKey padding
 *   OP_ROT     -- msg pubKey padding sig  (sig on top for squaring)
 *   OP_DUP OP_MUL  -- msg pubKey padding sig^2
 *   OP_ADD     -- msg pubKey (sig^2+padding)
 *   OP_SWAP    -- msg (sig^2+padding) pubKey
 *   OP_MOD     -- msg ((sig^2+padding) mod pubKey)
 *   OP_SWAP    -- ((sig^2+padding) mod pubKey) msg
 *   OP_SHA256  -- ((sig^2+padding) mod pubKey) SHA256(msg)
 *   OP_EQUAL   -- result
 * Stack after: <boolean>
 */
export function emitVerifyRabinSig(emit: Emit): void {
  emit({ op: 'opcode', code: 'OP_SWAP' });
  emit({ op: 'opcode', code: 'OP_ROT' });
  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'opcode', code: 'OP_MUL' });
  emit({ op: 'opcode', code: 'OP_ADD' });
  emit({ op: 'opcode', code: 'OP_SWAP' });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'opcode', code: 'OP_SWAP' });
  emit({ op: 'opcode', code: 'OP_SHA256' });
  emit({ op: 'opcode', code: 'OP_EQUAL' });
}
