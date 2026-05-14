//! Rabin signature verification codegen for Bitcoin Script.
//!
//! Port of `lowerVerifyRabinSig` from
//! `packages/runar-compiler/src/passes/rabin-codegen.ts`.
//!
//! `emit_verify_rabin_sig`: [msg, sig, padding, pubKey] -> [bool]
//!
//! Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg).
//! The emission is a fixed 10-opcode sequence:
//!
//!   OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
//!
//! The caller must bring the 4 arguments to the top of the stack in
//! argument order (msg sig padding pubKey, pubKey on top) before calling.

use super::stack::StackOp;

/// Emit the Rabin signature verification opcode sequence.
///
/// Stack on entry (bottom->top): msg sig padding pubKey
/// Stack on exit:                bool (1 = valid, 0 = invalid)
pub fn emit_verify_rabin_sig(emit: &mut dyn FnMut(StackOp)) {
    emit(StackOp::Opcode("OP_SWAP".to_string())); // msg sig pubKey padding
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

    /// Byte-frozen golden: the fixed 10-opcode Rabin verification sequence.
    #[test]
    fn emit_verify_rabin_sig_byte_frozen_golden() {
        let golden = [
            "OP_SWAP",
            "OP_ROT",
            "OP_DUP",
            "OP_MUL",
            "OP_ADD",
            "OP_SWAP",
            "OP_MOD",
            "OP_SWAP",
            "OP_SHA256",
            "OP_EQUAL",
        ];

        let mut ops: Vec<StackOp> = Vec::new();
        emit_verify_rabin_sig(&mut |op| ops.push(op));

        assert_eq!(ops.len(), golden.len(), "opcode count");
        for (i, op) in ops.iter().enumerate() {
            match op {
                StackOp::Opcode(code) => assert_eq!(code, golden[i], "opcode {i}"),
                other => panic!("op {i}: expected Opcode, got {other:?}"),
            }
        }
    }
}
