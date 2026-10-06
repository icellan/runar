//! Rabin signature verification codegen for Bitcoin Script.
//!
//! Port of `lowerVerifyRabinSig` from
//! `packages/runar-compiler/src/passes/rabin-codegen.ts`.
//!
//! `emit_verify_rabin_sig`: [msg, sig, padding, pubKey] -> [bool]
//!
//! Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg) mod pubKey
//! AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010).
//! The emission is a fixed 29-op sequence:
//!
//!   <push 0x00> OP_CAT OP_BIN2NUM                   // pubKey as unsigned (F-144)
//!   OP_SWAP
//!   <push 0x00> OP_CAT OP_BIN2NUM                   // padding as unsigned (F-144)
//!   OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   // 0 <= padding < 65536 (BUG-010)
//!   OP_ROT
//!   <push 0x00> OP_CAT OP_BIN2NUM                   // sig as unsigned (F-144)
//!   OP_DUP OP_MUL OP_ADD OP_OVER OP_MOD
//!   OP_ROT OP_SHA256 <push 0x00> OP_CAT OP_BIN2NUM
//!   OP_ROT OP_MOD OP_NUMEQUAL                       // digest mod pubKey (F-047)
//!
//! OPERAND SIGN (F-144): off-chain verifiers read padding (and the native
//! Go/Rust/Python/Ruby/Zig layers also sig and pubKey) as UNSIGNED
//! little-endian bytes; OP_WITHIN / OP_MUL / OP_MOD read a Script number,
//! whose last byte's high bit is the sign. Each operand gets an explicit
//! 0x00 sign byte and OP_BIN2NUM, so a raw unsigned push keeps its unsigned
//! value and a non-negative Script number is unchanged.
//!
//! ENCODING (BUG-011): the final comparison is NUMERIC, not byte-wise.
//! OP_MOD leaves a minimal Script number (33 bytes with a trailing 0x00 sign
//! byte whenever the digest's top byte has its high bit set — ~50% of
//! messages) while OP_SHA256 pushes exactly 32 raw bytes; a bare OP_EQUAL
//! refused ~half of all honest signatures on a real VM. The digest gets an
//! explicit 0x00 sign byte (OP_CAT), is collapsed to minimal form
//! (OP_BIN2NUM) and compared with OP_NUMEQUAL — which never aborts, keeping
//! the any-of-N pattern (false from one key's check, not a script kill).
//!
//! The caller must bring the 4 arguments to the top of the stack in
//! argument order (msg sig padding pubKey, pubKey on top) before calling.

use num_bigint::BigInt;
use super::stack::{PushValue, StackOp};

/// Exclusive upper bound on the Rabin `padding` parameter, enforced on-chain.
/// The legitimate signer (`packages/runar-go/rabin.go::RabinSign`) produces
/// `padding < 1000`; the on-chain bound is 65536 (16-bit) for slack.
/// See `_review/BUG-010-rfc.md`.
pub const RABIN_PADDING_LIMIT: i128 = 65536;

/// Emit the Rabin signature verification opcode sequence.
///
/// Stack on entry (bottom->top): msg sig padding pubKey
/// Stack on exit:                bool (1 = valid, 0 = invalid)
pub fn emit_verify_rabin_sig(emit: &mut dyn FnMut(StackOp)) {
    emit(StackOp::Push(PushValue::Bytes(vec![0x00]))); // F-144: pubKey as unsigned
    emit(StackOp::Opcode("OP_CAT".to_string()));
    emit(StackOp::Opcode("OP_BIN2NUM".to_string()));
    emit(StackOp::Opcode("OP_SWAP".to_string())); // msg sig pubKey padding
    emit(StackOp::Push(PushValue::Bytes(vec![0x00]))); // F-144: padding as unsigned
    emit(StackOp::Opcode("OP_CAT".to_string()));
    emit(StackOp::Opcode("OP_BIN2NUM".to_string()));
    // BUG-010 padding range check: assert 0 <= padding < 65536.
    emit(StackOp::Opcode("OP_DUP".to_string()));
    emit(StackOp::Opcode("OP_0".to_string()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(RABIN_PADDING_LIMIT))));
    emit(StackOp::Opcode("OP_WITHIN".to_string()));
    emit(StackOp::Opcode("OP_VERIFY".to_string()));
    emit(StackOp::Opcode("OP_ROT".to_string())); // msg pubKey padding sig
    emit(StackOp::Push(PushValue::Bytes(vec![0x00]))); // F-144: sig as unsigned
    emit(StackOp::Opcode("OP_CAT".to_string()));
    emit(StackOp::Opcode("OP_BIN2NUM".to_string()));
    emit(StackOp::Opcode("OP_DUP".to_string())); // msg pubKey padding sig sig
    emit(StackOp::Opcode("OP_MUL".to_string())); // msg pubKey padding sig^2
    emit(StackOp::Opcode("OP_ADD".to_string())); // msg pubKey (sig^2+padding)
    emit(StackOp::Opcode("OP_OVER".to_string())); // msg pubKey (sig^2+padding) pubKey (F-047: keep pubKey)
    emit(StackOp::Opcode("OP_MOD".to_string())); // msg pubKey lhs
    emit(StackOp::Opcode("OP_ROT".to_string())); // pubKey lhs msg
    emit(StackOp::Opcode("OP_SHA256".to_string())); // pubKey lhs SHA256(msg)
    // BUG-011 digest-encoding normalization: raw 32-byte digest -> minimal
    // non-negative Script number, then numeric compare (see module docs).
    emit(StackOp::Push(PushValue::Bytes(vec![0x00]))); // ... SHA256(msg) 0x00
    emit(StackOp::Opcode("OP_CAT".to_string())); // ... SHA256(msg)||0x00
    emit(StackOp::Opcode("OP_BIN2NUM".to_string())); // pubKey lhs num(SHA256(msg))
    // F-047: reduce the digest mod pubKey, matching every off-chain verifier.
    emit(StackOp::Opcode("OP_ROT".to_string())); // lhs num(SHA256(msg)) pubKey
    emit(StackOp::Opcode("OP_MOD".to_string())); // lhs (num(SHA256(msg)) mod pubKey)
    emit(StackOp::Opcode("OP_NUMEQUAL".to_string())); // bool
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-frozen golden: the fixed 29-op Rabin verification sequence
    /// (BUG-010 range check + BUG-011 digest-encoding normalization +
    /// F-047 digest reduction mod pubKey + F-144 unsigned operands).
    #[test]
    fn emit_verify_rabin_sig_byte_frozen_golden() {
        let mut ops: Vec<StackOp> = Vec::new();
        emit_verify_rabin_sig(&mut |op| ops.push(op));

        assert_eq!(ops.len(), 29, "opcode count");

        let expected_opcodes: &[(usize, &str)] = &[
            // indices 0, 4, 13 are the F-144 0x00 sign-byte pushes, checked below.
            (1, "OP_CAT"),
            (2, "OP_BIN2NUM"),
            (3, "OP_SWAP"),
            (5, "OP_CAT"),
            (6, "OP_BIN2NUM"),
            (7, "OP_DUP"),
            (8, "OP_0"),
            // index 9 is the push of 65536, checked separately below.
            (10, "OP_WITHIN"),
            (11, "OP_VERIFY"),
            (12, "OP_ROT"),
            (14, "OP_CAT"),
            (15, "OP_BIN2NUM"),
            (16, "OP_DUP"),
            (17, "OP_MUL"),
            (18, "OP_ADD"),
            (19, "OP_OVER"),
            (20, "OP_MOD"),
            (21, "OP_ROT"),
            (22, "OP_SHA256"),
            // index 23 is the push of 0x00, checked separately below.
            (24, "OP_CAT"),
            (25, "OP_BIN2NUM"),
            (26, "OP_ROT"),
            (27, "OP_MOD"),
            (28, "OP_NUMEQUAL"),
        ];

        for &(i, code) in expected_opcodes {
            match &ops[i] {
                StackOp::Opcode(c) => assert_eq!(c, code, "opcode {i}"),
                other => panic!("op {i}: expected Opcode, got {other:?}"),
            }
        }

        match &ops[9] {
            StackOp::Push(PushValue::Int(v)) => {
                assert_eq!(v, &BigInt::from(RABIN_PADDING_LIMIT), "padding-limit push");
            }
            other => panic!("op 9: expected Push(Int(65536)), got {other:?}"),
        }

        // F-144 operand sign bytes (0, 4, 13) and the BUG-011 digest sign byte (23).
        for i in [0usize, 4, 13, 23] {
            match &ops[i] {
                StackOp::Push(PushValue::Bytes(b)) => {
                    assert_eq!(b, &vec![0x00u8], "sign-byte push at {i}");
                }
                other => panic!("op {i}: expected Push(Bytes([0x00])), got {other:?}"),
            }
        }
    }
}
