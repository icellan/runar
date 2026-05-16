//! Peephole optimizer -- runs on Stack IR before emission.
//!
//! Scans for short sequences of stack operations that can be replaced with
//! fewer or cheaper opcodes. Applies rules iteratively until a fixed point
//! is reached. Mirrors the TypeScript peephole optimizer.

use super::stack::{PushValue, StackOp};

const MAX_ITERATIONS: usize = 100;

/// Apply peephole optimization to a list of stack ops.
pub fn optimize_stack_ops(ops: &[StackOp]) -> Vec<StackOp> {
    // First, recursively optimize nested if-blocks
    let mut current: Vec<StackOp> = ops.iter().map(optimize_nested_if).collect();

    for _ in 0..MAX_ITERATIONS {
        let (result, changed) = apply_one_pass(&current);
        if !changed {
            break;
        }
        current = result;
    }

    current
}

fn optimize_nested_if(op: &StackOp) -> StackOp {
    match op {
        StackOp::If {
            then_ops,
            else_ops,
        } => {
            let optimized_then = optimize_stack_ops(then_ops);
            let optimized_else = if else_ops.is_empty() {
                Vec::new()
            } else {
                optimize_stack_ops(else_ops)
            };
            StackOp::If {
                then_ops: optimized_then,
                else_ops: optimized_else,
            }
        }
        other => other.clone(),
    }
}

fn apply_one_pass(ops: &[StackOp]) -> (Vec<StackOp>, bool) {
    let mut result = Vec::new();
    let mut changed = false;
    let mut i = 0;

    while i < ops.len() {
        // Try 4-op window
        if i + 3 < ops.len() {
            if let Some(replacement) =
                match_window_4(&ops[i], &ops[i + 1], &ops[i + 2], &ops[i + 3])
            {
                result.extend(replacement);
                i += 4;
                changed = true;
                continue;
            }
        }
        // Try 3-op window
        if i + 2 < ops.len() {
            if let Some(replacement) = match_window_3(&ops[i], &ops[i + 1], &ops[i + 2]) {
                result.extend(replacement);
                i += 3;
                changed = true;
                continue;
            }
        }
        // Existing 2-op window
        if i + 1 < ops.len() {
            if let Some(replacement) = match_window_2(&ops[i], &ops[i + 1]) {
                result.extend(replacement);
                i += 2;
                changed = true;
                continue;
            }
        }

        result.push(ops[i].clone());
        i += 1;
    }

    (result, changed)
}

/// Reports whether an op is an opaque `raw_bytes` span emitted by a
/// `raw_script` ANF node. `raw_bytes` is a hard peephole barrier — no
/// optimization window may span or rewrite across it, because the bytes are
/// opaque and not guaranteed to form a well-formed opcode stream.
fn is_raw_bytes(op: &StackOp) -> bool {
    matches!(op, StackOp::RawBytes { .. })
}

fn match_window_3(a: &StackOp, b: &StackOp, c: &StackOp) -> Option<Vec<StackOp>> {
    if is_raw_bytes(a) || is_raw_bytes(b) || is_raw_bytes(c) {
        return None;
    }

    // Constant folding: PUSH(a) PUSH(b) ADD → PUSH(a+b)
    if let (StackOp::Push(PushValue::Int(va)), StackOp::Push(PushValue::Int(vb))) = (a, b) {
        if is_opcode(c, "OP_ADD") {
            return Some(vec![StackOp::Push(PushValue::Int(va + vb))]);
        }
        if is_opcode(c, "OP_SUB") {
            return Some(vec![StackOp::Push(PushValue::Int(va - vb))]);
        }
        if is_opcode(c, "OP_MUL") {
            return Some(vec![StackOp::Push(PushValue::Int(va * vb))]);
        }
    }
    None
}

fn match_window_4(
    a: &StackOp,
    b: &StackOp,
    c: &StackOp,
    d: &StackOp,
) -> Option<Vec<StackOp>> {
    if is_raw_bytes(a) || is_raw_bytes(b) || is_raw_bytes(c) || is_raw_bytes(d) {
        return None;
    }

    // Chain folding: PUSH(a) ADD PUSH(b) ADD → PUSH(a+b) ADD
    if let StackOp::Push(PushValue::Int(va)) = a {
        if is_opcode(b, "OP_ADD") {
            if let StackOp::Push(PushValue::Int(vb)) = c {
                if is_opcode(d, "OP_ADD") {
                    return Some(vec![
                        StackOp::Push(PushValue::Int(va + vb)),
                        StackOp::Opcode("OP_ADD".to_string()),
                    ]);
                }
            }
        }
        if is_opcode(b, "OP_SUB") {
            if let StackOp::Push(PushValue::Int(vb)) = c {
                if is_opcode(d, "OP_SUB") {
                    return Some(vec![
                        StackOp::Push(PushValue::Int(va + vb)),
                        StackOp::Opcode("OP_SUB".to_string()),
                    ]);
                }
            }
        }
    }
    None
}

fn match_window_2(a: &StackOp, b: &StackOp) -> Option<Vec<StackOp>> {
    if is_raw_bytes(a) || is_raw_bytes(b) {
        return None;
    }

    // PUSH x, DROP -> remove both
    if matches!(a, StackOp::Push(_)) && matches!(b, StackOp::Drop) {
        return Some(vec![]);
    }

    // DUP, DROP -> remove both
    if matches!(a, StackOp::Dup) && matches!(b, StackOp::Drop) {
        return Some(vec![]);
    }

    // SWAP, SWAP -> remove both
    if matches!(a, StackOp::Swap) && matches!(b, StackOp::Swap) {
        return Some(vec![]);
    }

    // PUSH 1, OP_ADD -> OP_1ADD
    if is_push_int(a, 1) && is_opcode(b, "OP_ADD") {
        return Some(vec![StackOp::Opcode("OP_1ADD".to_string())]);
    }

    // PUSH 1, OP_SUB -> OP_1SUB
    if is_push_int(a, 1) && is_opcode(b, "OP_SUB") {
        return Some(vec![StackOp::Opcode("OP_1SUB".to_string())]);
    }

    // PUSH 0, OP_ADD -> remove both
    if is_push_int(a, 0) && is_opcode(b, "OP_ADD") {
        return Some(vec![]);
    }

    // PUSH 0, OP_SUB -> remove both
    if is_push_int(a, 0) && is_opcode(b, "OP_SUB") {
        return Some(vec![]);
    }

    // OP_NOT, OP_NOT -> remove both
    if is_opcode(a, "OP_NOT") && is_opcode(b, "OP_NOT") {
        return Some(vec![]);
    }

    // OP_NEGATE, OP_NEGATE -> remove both
    if is_opcode(a, "OP_NEGATE") && is_opcode(b, "OP_NEGATE") {
        return Some(vec![]);
    }

    // OP_EQUAL, OP_VERIFY -> OP_EQUALVERIFY
    if is_opcode(a, "OP_EQUAL") && is_opcode(b, "OP_VERIFY") {
        return Some(vec![StackOp::Opcode("OP_EQUALVERIFY".to_string())]);
    }

    // OP_CHECKSIG, OP_VERIFY -> OP_CHECKSIGVERIFY
    if is_opcode(a, "OP_CHECKSIG") && is_opcode(b, "OP_VERIFY") {
        return Some(vec![StackOp::Opcode("OP_CHECKSIGVERIFY".to_string())]);
    }

    // OP_NUMEQUAL, OP_VERIFY -> OP_NUMEQUALVERIFY
    if is_opcode(a, "OP_NUMEQUAL") && is_opcode(b, "OP_VERIFY") {
        return Some(vec![StackOp::Opcode("OP_NUMEQUALVERIFY".to_string())]);
    }

    // OP_CHECKMULTISIG, OP_VERIFY -> OP_CHECKMULTISIGVERIFY
    if is_opcode(a, "OP_CHECKMULTISIG") && is_opcode(b, "OP_VERIFY") {
        return Some(vec![StackOp::Opcode(
            "OP_CHECKMULTISIGVERIFY".to_string(),
        )]);
    }

    // OP_DUP, OP_DROP -> remove both
    if is_opcode(a, "OP_DUP") && is_opcode(b, "OP_DROP") {
        return Some(vec![]);
    }

    // OP_OVER, OP_OVER -> OP_2DUP
    if matches!(a, StackOp::Over) && matches!(b, StackOp::Over) {
        return Some(vec![StackOp::Opcode("OP_2DUP".to_string())]);
    }

    // OP_DROP, OP_DROP -> OP_2DROP
    if matches!(a, StackOp::Drop) && matches!(b, StackOp::Drop) {
        return Some(vec![StackOp::Opcode("OP_2DROP".to_string())]);
    }

    // PUSH(0) + Roll{depth:0} → remove both
    if is_push_int(a, 0) && matches!(b, StackOp::Roll { depth: 0 }) {
        return Some(vec![]);
    }

    // PUSH(1) + Roll{depth:1} → Swap
    if is_push_int(a, 1) && matches!(b, StackOp::Roll { depth: 1 }) {
        return Some(vec![StackOp::Swap]);
    }

    // PUSH(2) + Roll{depth:2} → Rot
    if is_push_int(a, 2) && matches!(b, StackOp::Roll { depth: 2 }) {
        return Some(vec![StackOp::Rot]);
    }

    // PUSH(0) + Pick{depth:0} → Dup
    if is_push_int(a, 0) && matches!(b, StackOp::Pick { depth: 0 }) {
        return Some(vec![StackOp::Dup]);
    }

    // PUSH(1) + Pick{depth:1} → Over
    if is_push_int(a, 1) && matches!(b, StackOp::Pick { depth: 1 }) {
        return Some(vec![StackOp::Over]);
    }

    // Also match Push + Opcode("OP_ROLL"/"OP_PICK") (used by SLH-DSA codegen)
    if is_push_int(a, 0) && is_opcode(b, "OP_ROLL") {
        return Some(vec![]);
    }
    if is_push_int(a, 1) && is_opcode(b, "OP_ROLL") {
        return Some(vec![StackOp::Swap]);
    }
    if is_push_int(a, 2) && is_opcode(b, "OP_ROLL") {
        return Some(vec![StackOp::Rot]);
    }
    if is_push_int(a, 0) && is_opcode(b, "OP_PICK") {
        return Some(vec![StackOp::Dup]);
    }
    if is_push_int(a, 1) && is_opcode(b, "OP_PICK") {
        return Some(vec![StackOp::Over]);
    }

    // SHA256 + SHA256 → HASH256
    if is_opcode(a, "OP_SHA256") && is_opcode(b, "OP_SHA256") {
        return Some(vec![StackOp::Opcode("OP_HASH256".to_string())]);
    }

    // PUSH 0 + NUMEQUAL → NOT
    if is_push_int(a, 0) && is_opcode(b, "OP_NUMEQUAL") {
        return Some(vec![StackOp::Opcode("OP_NOT".to_string())]);
    }

    None
}

fn is_push_int(op: &StackOp, n: i128) -> bool {
    matches!(op, StackOp::Push(PushValue::Int(v)) if *v == n)
}

fn is_opcode(op: &StackOp, code: &str) -> bool {
    matches!(op, StackOp::Opcode(c) if c == code)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // 2-op optimizations
    // -----------------------------------------------------------------------

    #[test]
    fn test_swap_swap_removed() {
        let ops = vec![StackOp::Swap, StackOp::Swap];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "SWAP SWAP should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_dup_drop_removed() {
        let ops = vec![StackOp::Dup, StackOp::Drop];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "DUP DROP should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_push_drop_removed() {
        let ops = vec![StackOp::Push(PushValue::Int(42)), StackOp::Drop];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "PUSH DROP should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_not_not_removed() {
        let ops = vec![
            StackOp::Opcode("OP_NOT".to_string()),
            StackOp::Opcode("OP_NOT".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "NOT NOT should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_negate_negate_removed() {
        let ops = vec![
            StackOp::Opcode("OP_NEGATE".to_string()),
            StackOp::Opcode("OP_NEGATE".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "NEGATE NEGATE should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_equal_verify_combined() {
        let ops = vec![
            StackOp::Opcode("OP_EQUAL".to_string()),
            StackOp::Opcode("OP_VERIFY".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_EQUALVERIFY"));
    }

    #[test]
    fn test_numequal_verify_combined() {
        let ops = vec![
            StackOp::Opcode("OP_NUMEQUAL".to_string()),
            StackOp::Opcode("OP_VERIFY".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_NUMEQUALVERIFY"));
    }

    #[test]
    fn test_checksig_verify_combined() {
        let ops = vec![
            StackOp::Opcode("OP_CHECKSIG".to_string()),
            StackOp::Opcode("OP_VERIFY".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_CHECKSIGVERIFY"));
    }

    #[test]
    fn test_push1_add_becomes_1add() {
        let ops = vec![
            StackOp::Push(PushValue::Int(1)),
            StackOp::Opcode("OP_ADD".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_1ADD"));
    }

    #[test]
    fn test_push1_sub_becomes_1sub() {
        let ops = vec![
            StackOp::Push(PushValue::Int(1)),
            StackOp::Opcode("OP_SUB".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_1SUB"));
    }

    #[test]
    fn test_push0_add_removed() {
        let ops = vec![
            StackOp::Push(PushValue::Int(0)),
            StackOp::Opcode("OP_ADD".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "PUSH(0) ADD should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_push0_sub_removed() {
        let ops = vec![
            StackOp::Push(PushValue::Int(0)),
            StackOp::Opcode("OP_SUB".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "PUSH(0) SUB should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_over_over_becomes_2dup() {
        let ops = vec![StackOp::Over, StackOp::Over];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_2DUP"));
    }

    #[test]
    fn test_drop_drop_becomes_2drop() {
        let ops = vec![StackOp::Drop, StackOp::Drop];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_2DROP"));
    }

    #[test]
    fn test_sha256_sha256_becomes_hash256() {
        let ops = vec![
            StackOp::Opcode("OP_SHA256".to_string()),
            StackOp::Opcode("OP_SHA256".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_HASH256"));
    }

    #[test]
    fn test_push0_numequal_becomes_not() {
        let ops = vec![
            StackOp::Push(PushValue::Int(0)),
            StackOp::Opcode("OP_NUMEQUAL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_NOT"));
    }

    // -----------------------------------------------------------------------
    // PUSH + ROLL/PICK typed struct form
    // -----------------------------------------------------------------------

    #[test]
    fn test_push0_roll_struct_removed() {
        let ops = vec![
            StackOp::Push(PushValue::Int(0)),
            StackOp::Roll { depth: 0 },
        ];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "PUSH(0) Roll{{0}} should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_push1_roll_struct_becomes_swap() {
        let ops = vec![
            StackOp::Push(PushValue::Int(1)),
            StackOp::Roll { depth: 1 },
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Swap));
    }

    #[test]
    fn test_push2_roll_struct_becomes_rot() {
        let ops = vec![
            StackOp::Push(PushValue::Int(2)),
            StackOp::Roll { depth: 2 },
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Rot));
    }

    #[test]
    fn test_push0_pick_struct_becomes_dup() {
        let ops = vec![
            StackOp::Push(PushValue::Int(0)),
            StackOp::Pick { depth: 0 },
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Dup));
    }

    #[test]
    fn test_push1_pick_struct_becomes_over() {
        let ops = vec![
            StackOp::Push(PushValue::Int(1)),
            StackOp::Pick { depth: 1 },
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Over));
    }

    // -----------------------------------------------------------------------
    // Opcode("OP_ROLL") / Opcode("OP_PICK") string form (SLH-DSA codegen)
    // -----------------------------------------------------------------------

    #[test]
    fn test_push0_opcode_roll_string_removed() {
        let ops = vec![
            StackOp::Push(PushValue::Int(0)),
            StackOp::Opcode("OP_ROLL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "PUSH(0) Opcode(OP_ROLL) should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_push1_opcode_roll_string_becomes_swap() {
        let ops = vec![
            StackOp::Push(PushValue::Int(1)),
            StackOp::Opcode("OP_ROLL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Swap));
    }

    #[test]
    fn test_push2_opcode_roll_string_becomes_rot() {
        let ops = vec![
            StackOp::Push(PushValue::Int(2)),
            StackOp::Opcode("OP_ROLL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Rot));
    }

    #[test]
    fn test_push0_opcode_pick_string_becomes_dup() {
        let ops = vec![
            StackOp::Push(PushValue::Int(0)),
            StackOp::Opcode("OP_PICK".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Dup));
    }

    #[test]
    fn test_push1_opcode_pick_string_becomes_over() {
        let ops = vec![
            StackOp::Push(PushValue::Int(1)),
            StackOp::Opcode("OP_PICK".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Over));
    }

    // -----------------------------------------------------------------------
    // 3-op optimizations (constant folding)
    // -----------------------------------------------------------------------

    #[test]
    fn test_constant_fold_add() {
        let ops = vec![
            StackOp::Push(PushValue::Int(3)),
            StackOp::Push(PushValue::Int(7)),
            StackOp::Opcode("OP_ADD".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Push(PushValue::Int(10))));
    }

    #[test]
    fn test_constant_fold_sub() {
        let ops = vec![
            StackOp::Push(PushValue::Int(10)),
            StackOp::Push(PushValue::Int(3)),
            StackOp::Opcode("OP_SUB".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Push(PushValue::Int(7))));
    }

    #[test]
    fn test_constant_fold_mul() {
        let ops = vec![
            StackOp::Push(PushValue::Int(4)),
            StackOp::Push(PushValue::Int(5)),
            StackOp::Opcode("OP_MUL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Push(PushValue::Int(20))));
    }

    // -----------------------------------------------------------------------
    // 4-op optimizations (chain folding)
    // -----------------------------------------------------------------------

    #[test]
    fn test_chain_fold_add_add() {
        // x PUSH(3) ADD PUSH(7) ADD -> x PUSH(10) ADD
        let ops = vec![
            StackOp::Dup, // stand-in for some value on stack
            StackOp::Push(PushValue::Int(3)),
            StackOp::Opcode("OP_ADD".to_string()),
            StackOp::Push(PushValue::Int(7)),
            StackOp::Opcode("OP_ADD".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 3, "expected DUP PUSH(10) ADD, got {:?}", result);
        assert!(matches!(&result[0], StackOp::Dup));
        assert!(matches!(&result[1], StackOp::Push(PushValue::Int(10))));
        assert!(matches!(&result[2], StackOp::Opcode(c) if c == "OP_ADD"));
    }

    #[test]
    fn test_chain_fold_sub_sub() {
        let ops = vec![
            StackOp::Dup,
            StackOp::Push(PushValue::Int(2)),
            StackOp::Opcode("OP_SUB".to_string()),
            StackOp::Push(PushValue::Int(3)),
            StackOp::Opcode("OP_SUB".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 3, "expected DUP PUSH(5) SUB, got {:?}", result);
        assert!(matches!(&result[1], StackOp::Push(PushValue::Int(5))));
        assert!(matches!(&result[2], StackOp::Opcode(c) if c == "OP_SUB"));
    }

    // -----------------------------------------------------------------------
    // Non-optimizable sequences pass through unchanged
    // -----------------------------------------------------------------------

    #[test]
    fn test_non_optimizable_single_op_passthrough() {
        let ops = vec![StackOp::Dup];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Dup));
    }

    #[test]
    fn test_non_optimizable_sequence_passthrough() {
        let ops = vec![
            StackOp::Dup,
            StackOp::Opcode("OP_HASH160".to_string()),
            StackOp::Opcode("OP_EQUALVERIFY".to_string()),
            StackOp::Opcode("OP_CHECKSIG".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 4, "non-optimizable sequence should pass through unchanged");
        assert!(matches!(&result[0], StackOp::Dup));
        assert!(matches!(&result[1], StackOp::Opcode(c) if c == "OP_HASH160"));
        assert!(matches!(&result[2], StackOp::Opcode(c) if c == "OP_EQUALVERIFY"));
        assert!(matches!(&result[3], StackOp::Opcode(c) if c == "OP_CHECKSIG"));
    }

    #[test]
    fn test_large_push_with_roll_not_simplified() {
        // PUSH(5) + OP_ROLL should NOT be simplified (only 0/1/2 are special-cased)
        let ops = vec![
            StackOp::Push(PushValue::Int(5)),
            StackOp::Opcode("OP_ROLL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 2, "PUSH(5) OP_ROLL should pass through unchanged");
    }

    #[test]
    fn test_empty_input() {
        let ops: Vec<StackOp> = vec![];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // Nested IF optimization
    // -----------------------------------------------------------------------

    #[test]
    fn test_nested_if_optimized() {
        let ops = vec![StackOp::If {
            then_ops: vec![
                StackOp::Opcode("OP_EQUAL".to_string()),
                StackOp::Opcode("OP_VERIFY".to_string()),
            ],
            else_ops: vec![StackOp::Swap, StackOp::Swap],
        }];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        if let StackOp::If { then_ops, else_ops } = &result[0] {
            assert_eq!(then_ops.len(), 1, "then branch should be optimized");
            assert!(matches!(&then_ops[0], StackOp::Opcode(c) if c == "OP_EQUALVERIFY"));
            assert!(else_ops.is_empty(), "else branch SWAP SWAP should be eliminated");
        } else {
            panic!("expected If, got {:?}", result[0]);
        }
    }

    // -----------------------------------------------------------------------
    // Iterative convergence
    // -----------------------------------------------------------------------

    #[test]
    fn test_iterative_optimization() {
        // After first pass: PUSH(0) ADD is removed, leaving DUP DROP which is
        // removed on the second pass
        let ops = vec![
            StackOp::Dup,
            StackOp::Push(PushValue::Int(0)),
            StackOp::Opcode("OP_ADD".to_string()),
            StackOp::Drop,
        ];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "iterative optimization should remove DUP (PUSH0 ADD -> empty) DROP -> DUP DROP -> empty, got {:?}", result);
    }
}
