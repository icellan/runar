//! Script-byte cost model for Stack IR.
//!
//! Port of `packages/runar-compiler/src/metrics/cost-model.ts`. Optimizer passes
//! need to compare two candidate lowerings by the metric that actually matters —
//! serialized locking-script bytes — before either one is emitted. `OP_DUP` and
//! a 33-byte constant push are one instruction each and 1 vs 34 bytes; an
//! instruction count cannot tell them apart.
//!
//! This is deliberately NOT an approximation: every push routes through the same
//! encoders `emit.rs` uses, so
//!
//! ```text
//! estimate_script_bytes(ops) == emit_method(..).script_hex.len() / 2
//! ```
//!
//! holds exactly. `cost_model_tests.rs` asserts that over every crypto emitter.

use num_bigint::BigInt;

use super::emit::{encode_push_int, encode_push_data};
use super::opcodes::opcode_byte;
use super::stack::{PushValue, StackOp};

/// Serialized byte cost of a single push value.
///
/// Mirrors `encode_push_value` in `emit.rs`: booleans are the 1-byte OP_TRUE /
/// OP_FALSE, integers go through the small-int opcodes where possible, and byte
/// slices are MINIMALDATA-aware before falling back to a length-prefixed push.
pub fn size_of_push_value(value: &PushValue) -> usize {
    match value {
        PushValue::Bool(_) => 1,
        PushValue::Int(n) => encode_push_int(n).0.len() / 2,
        PushValue::Bytes(b) => encode_push_data(b).len(),
    }
}

/// `size_of_push_value` for a bare integer, which is what the constant pool and
/// the comb width search compare against.
pub fn size_of_push_int(n: &BigInt) -> usize {
    encode_push_int(n).0.len() / 2
}

/// Serialized byte cost of one Stack IR operation, including nested `if` arms.
///
/// Note on `Pick` / `Roll`: they cost ONE byte here. The depth operand is a
/// separate `Push` op that the tracker emits immediately before, so charging the
/// depth here would double-count it.
///
/// Panics on an unknown opcode mnemonic rather than costing it zero — a typo in
/// a codegen module should surface loudly, not as a cost model that quietly
/// under-reports.
pub fn size_of_stack_op(op: &StackOp) -> usize {
    match op {
        StackOp::Push(v) => size_of_push_value(v),

        StackOp::Dup
        | StackOp::Swap
        | StackOp::Roll { .. }
        | StackOp::Pick { .. }
        | StackOp::Drop
        | StackOp::Nip
        | StackOp::Over
        | StackOp::Rot
        | StackOp::Tuck => 1,

        StackOp::Opcode(code) => {
            if opcode_byte(code).is_none() {
                panic!("cost-model: unknown opcode '{}'", code);
            }
            1
        }

        // OP_IF + then + [OP_ELSE + else] + OP_ENDIF. The emitter writes
        // OP_ELSE only for a NON-EMPTY else arm.
        StackOp::If { then_ops, else_ops } => {
            let mut total = 2;
            total += estimate_script_bytes(then_ops);
            if !else_ops.is_empty() {
                total += 1 + estimate_script_bytes(else_ops);
            }
            total
        }

        // Both emit a single 0x00 byte that the SDK rewrites later.
        StackOp::Placeholder { .. } | StackOp::PushCodeSepIndex => 1,

        StackOp::RawBytes { bytes, .. } => bytes.len(),
    }
}

/// Serialized byte cost of a Stack IR sequence.
pub fn estimate_script_bytes(ops: &[StackOp]) -> usize {
    ops.iter().map(size_of_stack_op).sum()
}
