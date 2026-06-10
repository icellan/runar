//! Rabin signature verification codegen for Bitcoin Script.
//!
//! Port of `lowerVerifyRabinSig` from
//! `packages/runar-compiler/src/passes/rabin-codegen.ts`.
//!
//! `emit_verify_rabin_sig`: [msg, sig, padding, pubKey] -> [bool]
//!
//! Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg)
//! AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010).
//! The emission is a fixed 15-opcode sequence:
//!
//!   OP_SWAP
//!   OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   // 0 <= padding < 65536 (BUG-010)
//!   OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
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
    emit(StackOp::Opcode("OP_SWAP".to_string())); // msg sig pubKey padding
    // BUG-010 padding range check: assert 0 <= padding < 65536.
    emit(StackOp::Opcode("OP_DUP".to_string()));
    emit(StackOp::Opcode("OP_0".to_string()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(RABIN_PADDING_LIMIT))));
    emit(StackOp::Opcode("OP_WITHIN".to_string()));
    emit(StackOp::Opcode("OP_VERIFY".to_string()));
    emit(StackOp::Opcode("OP_ROT".to_string())); // msg pubKey padding sig
    emit(StackOp::Opcode("OP_DUP".to_string())); // msg pubKey padding sig sig
    emit(StackOp::Opcode("OP_MUL".to_string())); // msg pubKey padding sig^2
    emit(StackOp::Opcode("OP_ADD".to_string())); // msg pubKey (sig^2+padding)
    emit(StackOp::Opcode("OP_SWAP".to_string())); // msg (sig^2+padding) pubKey
    emit(StackOp::Opcode("OP_MOD".to_string())); // msg ((sig^2+padding) mod pubKey)
    emit(StackOp::Opcode("OP_SWAP".to_string())); // ((sig^2+padding) mod pubKey) msg
    emit(StackOp::Opcode("OP_SHA256".to_string())); // ((sig^2+padding) mod pubKey) SHA256(msg)
    emit(StackOp::Opcode("OP_EQUAL".to_string())); // bool
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-frozen golden: the fixed 15-opcode Rabin verification sequence
    /// (10 original + 5 BUG-010 range-check ops).
    #[test]
    fn emit_verify_rabin_sig_byte_frozen_golden() {
        let mut ops: Vec<StackOp> = Vec::new();
        emit_verify_rabin_sig(&mut |op| ops.push(op));

        assert_eq!(ops.len(), 15, "opcode count");

        let expected_opcodes: &[(usize, &str)] = &[
            (0, "OP_SWAP"),
            (1, "OP_DUP"),
            (2, "OP_0"),
            // index 3 is the push of 65536, checked separately below.
            (4, "OP_WITHIN"),
            (5, "OP_VERIFY"),
            (6, "OP_ROT"),
            (7, "OP_DUP"),
            (8, "OP_MUL"),
            (9, "OP_ADD"),
            (10, "OP_SWAP"),
            (11, "OP_MOD"),
            (12, "OP_SWAP"),
            (13, "OP_SHA256"),
            (14, "OP_EQUAL"),
        ];

        for &(i, code) in expected_opcodes {
            match &ops[i] {
                StackOp::Opcode(c) => assert_eq!(c, code, "opcode {i}"),
                other => panic!("op {i}: expected Opcode, got {other:?}"),
            }
        }

        match &ops[3] {
            StackOp::Push(PushValue::Int(v)) => {
                assert_eq!(v, &BigInt::from(RABIN_PADDING_LIMIT), "padding-limit push");
            }
            other => panic!("op 3: expected Push(Int(65536)), got {other:?}"),
        }
    }
}
