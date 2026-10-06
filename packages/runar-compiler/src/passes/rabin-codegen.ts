/**
 * Rabin signature verification Bitcoin Script codegen.
 *
 * Splice into LoweringContext in 05-stack-lower.ts. Entry: lowerVerifyRabinSig()
 * in stack-lower → calls emitVerifyRabinSig().
 *
 * Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg) mod pubKey
 * AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010).
 *
 * Input stack at entry (top-down): pubKey(0) padding(1) sig(2) msg(3)
 *   — i.e. bottom→top: msg sig padding pubKey
 * Output: <boolean>
 *
 * The opcode sequence is a fixed 29 ops:
 *   <push 0x00> OP_CAT OP_BIN2NUM                   // pubKey as unsigned (F-144)
 *   OP_SWAP
 *   <push 0x00> OP_CAT OP_BIN2NUM                   // padding as unsigned (F-144)
 *   OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   // 0 <= padding < 65536 (BUG-010)
 *   OP_ROT
 *   <push 0x00> OP_CAT OP_BIN2NUM                   // sig as unsigned (F-144)
 *   OP_DUP OP_MUL OP_ADD OP_OVER OP_MOD
 *   OP_ROT OP_SHA256 <push 0x00> OP_CAT OP_BIN2NUM
 *   OP_ROT OP_MOD OP_NUMEQUAL                       // digest mod pubKey (F-047)
 *
 * OPERAND SIGN (F-144): every off-chain verifier reads padding (and the
 * native Go/Rust/Python/Ruby/Zig layers also sig and pubKey) as UNSIGNED
 * little-endian bytes, but OP_WITHIN / OP_MUL / OP_MOD read a Script number,
 * whose last byte's high bit is the sign. padding = 200 pushed as [0xC8] read
 * as -72 and aborted an honest spend. Each operand gets an explicit 0x00 sign
 * byte and OP_BIN2NUM, so a raw unsigned push means its unsigned value, and a
 * non-negative Script number (what the SDKs emit for a bigint) is unchanged.
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
 * F-144: read the stack top as an UNSIGNED little-endian integer. Appending a
 * 0x00 sign byte and collapsing with OP_BIN2NUM turns a raw unsigned push into
 * its unsigned value and leaves a non-negative Script number unchanged.
 */
function emitUnsignedOperand(emit: Emit): void {
  emit({ op: 'push', value: new Uint8Array([0x00]) });
  emit({ op: 'opcode', code: 'OP_CAT' });
  emit({ op: 'opcode', code: 'OP_BIN2NUM' });
}

/**
 * Emit the Rabin signature verification opcode sequence.
 *
 * Stack before (bottom→top): msg sig padding pubKey
 * Script:
 *   <push 0x00> OP_CAT OP_BIN2NUM    -- msg sig padding pubKey   (unsigned, F-144)
 *   OP_SWAP                          -- msg sig pubKey padding
 *   <push 0x00> OP_CAT OP_BIN2NUM    -- msg sig pubKey padding   (unsigned, F-144)
 *   OP_DUP                           -- msg sig pubKey padding padding   (BUG-010 check)
 *   OP_0                             -- ... padding padding 0
 *   <push 65536>                     -- ... padding padding 0 65536
 *   OP_WITHIN                        -- ... padding (0<=padding<65536)
 *   OP_VERIFY                        -- msg sig pubKey padding           (abort if out of range)
 *   OP_ROT                           -- msg pubKey padding sig
 *   <push 0x00> OP_CAT OP_BIN2NUM    -- msg pubKey padding sig   (unsigned, F-144)
 *   OP_DUP OP_MUL                    -- msg pubKey padding sig^2
 *   OP_ADD                           -- msg pubKey (sig^2+padding)
 *   OP_OVER                          -- msg pubKey (sig^2+padding) pubKey
 *   OP_MOD                           -- msg pubKey lhs        (lhs = (sig^2+padding) mod pubKey)
 *   OP_ROT                           -- pubKey lhs msg
 *   OP_SHA256                        -- pubKey lhs SHA256(msg)
 *   <push 0x00> OP_CAT               -- ... SHA256(msg)||0x00   (33 B, explicit
 *                                       non-negative sign byte — BUG-011)
 *   OP_BIN2NUM                       -- pubKey lhs num(SHA256(msg))  (minimal encoding)
 *   OP_ROT                           -- lhs num(SHA256(msg)) pubKey
 *   OP_MOD                           -- lhs (num(SHA256(msg)) mod pubKey)   (F-047)
 *   OP_NUMEQUAL                      -- result (numeric compare, never aborts)
 * Stack after: <boolean>
 */
export function emitVerifyRabinSig(emit: Emit): void {
  emitUnsignedOperand(emit); // pubKey (F-144)
  emit({ op: 'opcode', code: 'OP_SWAP' });
  emitUnsignedOperand(emit); // padding (F-144)
  // BUG-010 padding range check: assert 0 <= padding < 65536.
  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'opcode', code: 'OP_0' });
  emit({ op: 'push', value: RABIN_PADDING_LIMIT });
  emit({ op: 'opcode', code: 'OP_WITHIN' });
  emit({ op: 'opcode', code: 'OP_VERIFY' });
  emit({ op: 'opcode', code: 'OP_ROT' });
  emitUnsignedOperand(emit); // sig (F-144)
  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'opcode', code: 'OP_MUL' });
  emit({ op: 'opcode', code: 'OP_ADD' });
  // F-047: keep pubKey on the stack (OP_OVER, not OP_SWAP) — the digest is
  // reduced by the same modulus below.
  emit({ op: 'opcode', code: 'OP_OVER' });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'opcode', code: 'OP_ROT' });
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
  // F-047: reduce the digest mod pubKey, matching every off-chain verifier
  // ((sig^2+padding) mod n == SHA256(msg) mod n). Without it any n <= digest
  // refused signatures the off-chain verifiers accept.
  emit({ op: 'opcode', code: 'OP_ROT' });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'opcode', code: 'OP_NUMEQUAL' });
}
