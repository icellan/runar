/**
 * Rabin signature verification Bitcoin Script codegen.
 *
 * Splice into LoweringContext in 05-stack-lower.ts. Entry: lowerVerifyRabinSig()
 * in stack-lower → calls emitVerifyRabinSig().
 *
 * Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg)
 * AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010).
 *
 * Input stack at entry (top-down): pubKey(0) padding(1) sig(2) msg(3)
 *   — i.e. bottom→top: msg sig padding pubKey
 * Output: <boolean>
 *
 * The opcode sequence is a fixed 15 opcodes:
 *   OP_SWAP
 *   OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   // 0 <= padding < 65536 (BUG-010)
 *   OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
 */

import type { StackOp } from '../ir/index.js';

type Emit = (op: StackOp) => void;

/**
 * Upper bound (exclusive) on the Rabin `padding` parameter, enforced on-chain.
 * The legitimate signer (`packages/runar-go/rabin.go::RabinSign`) produces
 * `padding < 1000`; the on-chain bound is 65536 (16-bit) for slack.
 * See `_review/BUG-010-rfc.md`.
 */
export const RABIN_PADDING_LIMIT = 65536n;

/**
 * Emit the Rabin signature verification opcode sequence.
 *
 * Stack before (bottom→top): msg sig padding pubKey
 * Script:
 *   OP_SWAP                          -- msg sig pubKey padding
 *   OP_DUP                           -- msg sig pubKey padding padding   (BUG-010 check)
 *   OP_0                             -- ... padding padding 0
 *   <push 65536>                     -- ... padding padding 0 65536
 *   OP_WITHIN                        -- ... padding (0<=padding<65536)
 *   OP_VERIFY                        -- msg sig pubKey padding           (abort if out of range)
 *   OP_ROT                           -- msg pubKey padding sig
 *   OP_DUP OP_MUL                    -- msg pubKey padding sig^2
 *   OP_ADD                           -- msg pubKey (sig^2+padding)
 *   OP_SWAP                          -- msg (sig^2+padding) pubKey
 *   OP_MOD                           -- msg ((sig^2+padding) mod pubKey)
 *   OP_SWAP                          -- ((sig^2+padding) mod pubKey) msg
 *   OP_SHA256                        -- ((sig^2+padding) mod pubKey) SHA256(msg)
 *   OP_EQUAL                         -- result
 * Stack after: <boolean>
 */
export function emitVerifyRabinSig(emit: Emit): void {
  emit({ op: 'opcode', code: 'OP_SWAP' });
  // BUG-010 padding range check: assert 0 <= padding < 65536.
  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'opcode', code: 'OP_0' });
  emit({ op: 'push', value: RABIN_PADDING_LIMIT });
  emit({ op: 'opcode', code: 'OP_WITHIN' });
  emit({ op: 'opcode', code: 'OP_VERIFY' });
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
