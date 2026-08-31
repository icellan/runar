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
 * The opcode sequence is a fixed 18 ops:
 *   OP_SWAP
 *   OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   // 0 <= padding < 65536 (BUG-010)
 *   OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD
 *   OP_SWAP OP_SHA256 <push 0x00> OP_CAT OP_BIN2NUM OP_NUMEQUAL
 *
 * ENCODING (BUG-011): the final comparison must be NUMERIC, not byte-wise.
 * OP_MOD leaves its result in minimal Script-number encoding — 33 bytes
 * (trailing 0x00 sign byte) whenever the value's top magnitude byte has its
 * high bit set, which is true for ~50% of SHA-256 digests — while OP_SHA256
 * pushes exactly 32 raw bytes. A bare OP_EQUAL therefore refused ~half of
 * all HONEST signatures on a real Script VM (fails closed; no forgery risk).
 * The fix appends an explicit 0x00 sign byte to the digest (making it a
 * valid non-negative Script number for any digest), collapses it to minimal
 * form with OP_BIN2NUM, and compares with OP_NUMEQUAL.
 *
 * Why not OP_NUM2BIN width normalization: a 32-byte NUM2BIN aborts for any
 * digest >= 2^255 (the sign bit no longer fits), and a 33-byte NUM2BIN
 * aborts (not "false") for almost every INVALID signature, because the mod
 * result is then uniform in [0, n) with n > 2^256 — that abort would break
 * the any-of-N key pattern `verifyRabinSig(k1) || verifyRabinSig(k2)`,
 * where a mismatch against one key must yield false, not kill the script.
 * OP_NUMEQUAL never aborts on a well-formed operand and both operands here
 * are compiler-produced minimal numbers.
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
 *   <push 0x00> OP_CAT               -- ... SHA256(msg)||0x00   (33 B, explicit
 *                                       non-negative sign byte — BUG-011)
 *   OP_BIN2NUM                       -- ... num(SHA256(msg))    (minimal encoding)
 *   OP_NUMEQUAL                      -- result (numeric compare, never aborts)
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
  // BUG-011: digest-encoding normalization. The digest is a raw 32-byte push;
  // the OP_MOD result is a minimal Script number (33 bytes when the digest's
  // top byte has its high bit set). Append an explicit 0x00 sign byte so the
  // digest reads as a non-negative Script number regardless of its high bit,
  // collapse to minimal form, and compare NUMERICALLY. OP_EQUAL here rejected
  // ~50% of honest signatures on a real VM (byte-length mismatch).
  emit({ op: 'push', value: new Uint8Array([0x00]) });
  emit({ op: 'opcode', code: 'OP_CAT' });
  emit({ op: 'opcode', code: 'OP_BIN2NUM' });
  emit({ op: 'opcode', code: 'OP_NUMEQUAL' });
}
