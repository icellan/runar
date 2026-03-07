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

fn match_window_3(a: &StackOp, b: &StackOp, c: &StackOp) -> Option<Vec<StackOp>> {
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
