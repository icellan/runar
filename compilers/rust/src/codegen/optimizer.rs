//! Peephole optimizer -- runs on Stack IR before emission.
//!
//! Scans for short sequences of stack operations that can be replaced with
//! fewer or cheaper opcodes. Applies rules iteratively until a fixed point
//! is reached. Mirrors the TypeScript peephole optimizer.

use num_bigint::BigInt;
use super::stack::{PushValue, StackOp};

const MAX_ITERATIONS: usize = 100;

/// Apply peephole optimization to a list of stack ops.
/// Optimize `ops`, nested if-blocks bottom-up: every if-arm before the list
/// holding it.
///
/// N-264: bottom-up on an explicit stack, not by recursion. Private methods are
/// inlined, so a chain of D helpers that each call the next under K nested ifs
/// nests D*K if-ops here, too deep to recurse on. Each list is optimized
/// exactly as the recursive version optimized it.
pub fn optimize_stack_ops(ops: &[StackOp]) -> Vec<StackOp> {
    /// An op list being rebuilt: its next op, the rebuilt ops so far, and —
    /// while an if-op's else-arm is being optimized — that if-op's finished
    /// then-arm.
    struct Frame<'o> {
        ops: &'o [StackOp],
        next: usize,
        out: Vec<StackOp>,
        then_done: Option<Vec<StackOp>>,
    }
    fn new_frame(ops: &[StackOp]) -> Frame<'_> {
        Frame { ops, next: 0, out: Vec::with_capacity(ops.len()), then_done: None }
    }
    let mut stack: Vec<Frame> = vec![new_frame(ops)];
    // A just-optimized arm, on its way to the if-op that holds it.
    let mut arm: Option<Vec<StackOp>> = None;
    loop {
        let top = stack.len() - 1;
        if let Some(done) = arm.take() {
            let frame = &mut stack[top];
            let else_ops = match &frame.ops[frame.next - 1] {
                StackOp::If { else_ops, .. } => else_ops,
                _ => unreachable!("an arm returns to its if-op"),
            };
            match frame.then_done.take() {
                Some(then_ops) => frame.out.push(StackOp::If {
                    then_ops,
                    else_ops: done,
                    then_locs: Vec::new(),
                    else_locs: Vec::new(),
                }),
                None if else_ops.is_empty() => frame.out.push(StackOp::If {
                    then_ops: done,
                    else_ops: Vec::new(),
                    then_locs: Vec::new(),
                    else_locs: Vec::new(),
                }),
                None => {
                    frame.then_done = Some(done);
                    let child = new_frame(else_ops);
                    stack.push(child);
                }
            }
            continue;
        }
        let frame = &mut stack[top];
        if frame.next < frame.ops.len() {
            let op = &frame.ops[frame.next];
            frame.next += 1;
            match op {
                StackOp::If { then_ops, .. } => {
                    let child = new_frame(then_ops);
                    stack.push(child);
                }
                other => frame.out.push(other.clone()),
            }
            continue;
        }
        let done = stack.pop().unwrap();
        let optimized = optimize_one_level(done.out);
        if stack.is_empty() {
            return optimized;
        }
        arm = Some(optimized);
    }
}

/// The fixed-point rule loop over one op list whose if-arms are done.
fn optimize_one_level(mut current: Vec<StackOp>) -> Vec<StackOp> {
    for _ in 0..MAX_ITERATIONS {
        let (result, changed) = apply_one_pass(current);
        current = result;
        if !changed {
            break;
        }
    }

    current
}

/// Peephole-optimize a parallel `(ops, source_locs)` pair, preserving the
/// source location of the FIRST input op in every collapsed window. The
/// returned `source_locs` is the same length as the returned ops — callers
/// can drop the old `method.source_locs` and replace it wholesale.
///
/// GAP-002: previously the source_locs array was wiped to all-`None` after
/// the peephole pass because there was no parallel-tracking variant of
/// `optimize_stack_ops`. The wipe meant `artifact.sourceMap` was always
/// empty on the Rust tier. This wrapper restores that mapping.
pub fn optimize_stack_ops_with_locs(
    ops: &[StackOp],
    source_locs: &[Option<crate::ir::SourceLocation>],
) -> (Vec<StackOp>, Vec<Option<crate::ir::SourceLocation>>) {
    // N-222: the same bottom-up, explicit-stack walk as `optimize_stack_ops`
    // (N-264), but every list — the top level AND each if-arm — is optimized
    // together with its locations, so an arm op keeps its own statement's
    // location instead of losing it. A list whose locations are missing or of
    // the wrong length is treated as unlocated, as the top level always was.
    type Loc = Option<crate::ir::SourceLocation>;
    struct Frame<'o> {
        ops: &'o [StackOp],
        locs: Vec<Loc>,
        next: usize,
        out: Vec<StackOp>,
        out_locs: Vec<Loc>,
        then_done: Option<(Vec<StackOp>, Vec<Loc>)>,
    }
    fn new_frame<'o>(ops: &'o [StackOp], locs: &[Loc]) -> Frame<'o> {
        Frame {
            ops,
            locs: if locs.len() == ops.len() { locs.to_vec() } else { vec![None; ops.len()] },
            next: 0,
            out: Vec::with_capacity(ops.len()),
            out_locs: Vec::with_capacity(ops.len()),
            then_done: None,
        }
    }
    let mut stack: Vec<Frame> = vec![new_frame(ops, source_locs)];
    let mut arm: Option<(Vec<StackOp>, Vec<Loc>)> = None;
    loop {
        let top = stack.len() - 1;
        if let Some((done, done_locs)) = arm.take() {
            let frame = &mut stack[top];
            let frame_ops = frame.ops;
            let idx = frame.next - 1;
            let (else_ops, else_locs) = match &frame_ops[idx] {
                StackOp::If { else_ops, else_locs, .. } => (else_ops, else_locs),
                _ => unreachable!("an arm returns to its if-op"),
            };
            let if_loc = frame.locs[idx].clone();
            match frame.then_done.take() {
                Some((then_ops, then_locs)) => {
                    frame.out.push(StackOp::If { then_ops, else_ops: done, then_locs, else_locs: done_locs });
                    frame.out_locs.push(if_loc);
                }
                None if else_ops.is_empty() => {
                    frame.out.push(StackOp::If {
                        then_ops: done,
                        else_ops: Vec::new(),
                        then_locs: done_locs,
                        else_locs: Vec::new(),
                    });
                    frame.out_locs.push(if_loc);
                }
                None => {
                    frame.then_done = Some((done, done_locs));
                    let child = new_frame(else_ops, else_locs);
                    stack.push(child);
                }
            }
            continue;
        }
        let frame = &mut stack[top];
        if frame.next < frame.ops.len() {
            let frame_ops = frame.ops;
            let i = frame.next;
            frame.next += 1;
            match &frame_ops[i] {
                StackOp::If { then_ops, then_locs, .. } => {
                    let child = new_frame(then_ops, then_locs);
                    stack.push(child);
                }
                other => {
                    frame.out.push(other.clone());
                    frame.out_locs.push(frame.locs[i].clone());
                }
            }
            continue;
        }
        let done = stack.pop().unwrap();
        let optimized = optimize_one_level_with_locs(done.out, done.out_locs);
        if stack.is_empty() {
            return optimized;
        }
        arm = Some(optimized);
    }
}

/// The fixed-point rule loop over one located op list whose if-arms are done.
fn optimize_one_level_with_locs(
    mut ops: Vec<StackOp>,
    mut locs: Vec<Option<crate::ir::SourceLocation>>,
) -> (Vec<StackOp>, Vec<Option<crate::ir::SourceLocation>>) {
    for _ in 0..MAX_ITERATIONS {
        let (result_ops, result_locs, changed) = apply_one_pass_with_locs(ops, &locs);
        ops = result_ops;
        locs = result_locs;
        if !changed {
            break;
        }
    }
    (ops, locs)
}

/// N-264: takes `ops` by value and MOVES each unmatched op into the result.
/// Cloning one deep-cloned an if-op's whole subtree, recursively.
fn apply_one_pass_with_locs(
    mut ops: Vec<StackOp>,
    source_locs: &[Option<crate::ir::SourceLocation>],
) -> (Vec<StackOp>, Vec<Option<crate::ir::SourceLocation>>, bool) {
    let mut result_ops = Vec::new();
    let mut result_locs = Vec::new();
    let mut changed = false;
    let mut i = 0;

    while i < ops.len() {
        // 4-op window
        if i + 3 < ops.len() {
            if let Some(replacement) =
                match_window_4(&ops[i], &ops[i + 1], &ops[i + 2], &ops[i + 3])
            {
                let head_loc = source_locs.get(i).cloned().flatten();
                let n = replacement.len();
                result_ops.extend(replacement);
                for _ in 0..n {
                    result_locs.push(head_loc.clone());
                }
                i += 4;
                changed = true;
                continue;
            }
        }
        // 3-op window
        if i + 2 < ops.len() {
            if let Some(replacement) = match_window_3(&ops[i], &ops[i + 1], &ops[i + 2]) {
                let head_loc = source_locs.get(i).cloned().flatten();
                let n = replacement.len();
                result_ops.extend(replacement);
                for _ in 0..n {
                    result_locs.push(head_loc.clone());
                }
                i += 3;
                changed = true;
                continue;
            }
        }
        // 2-op window
        if i + 1 < ops.len() {
            if let Some(replacement) = match_window_2(&ops[i], &ops[i + 1]) {
                let head_loc = source_locs.get(i).cloned().flatten();
                let n = replacement.len();
                result_ops.extend(replacement);
                for _ in 0..n {
                    result_locs.push(head_loc.clone());
                }
                i += 2;
                changed = true;
                continue;
            }
        }

        // Every later window starts past `i`, so the placeholder is never read.
        result_ops.push(std::mem::replace(&mut ops[i], StackOp::Drop));
        result_locs.push(source_locs.get(i).cloned().flatten());
        i += 1;
    }

    (result_ops, result_locs, changed)
}

/// N-264: takes `ops` by value; see `apply_one_pass_with_locs`.
fn apply_one_pass(mut ops: Vec<StackOp>) -> (Vec<StackOp>, bool) {
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

        // Every later window starts past `i`, so the placeholder is never read.
        result.push(std::mem::replace(&mut ops[i], StackOp::Drop));
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

/// Opcodes whose result is guaranteed to be a CANONICAL boolean -- the minimal
/// script-number encoding of 0 (the empty element) or 1 (`{0x01}`), and nothing
/// else. This is the precondition for the `OP_NOT OP_NOT` elimination below:
/// `x OP_NOT OP_NOT` is boolean *normalisation*, not identity, so deleting the
/// pair is only value-preserving when `x` is already canonical.
///
/// Every entry pushes `CScriptNum(0|1).getvch()` (or `vchFalse`/`vchTrue`) in
/// the reference interpreter. Stack-shuffling ops (`OP_DUP`/`OP_PICK`/
/// `OP_ROLL`/`OP_SWAP`/...) are deliberately absent: they forward a value whose
/// provenance this local window cannot see.
const CANONICAL_BOOL_OPCODES: &[&str] = &[
    "OP_EQUAL",
    "OP_NUMEQUAL",
    "OP_NUMNOTEQUAL",
    "OP_LESSTHAN",
    "OP_GREATERTHAN",
    "OP_LESSTHANOREQUAL",
    "OP_GREATERTHANOREQUAL",
    "OP_BOOLAND",
    "OP_BOOLOR",
    "OP_WITHIN",
    "OP_NOT",
    "OP_0NOTEQUAL",
    "OP_CHECKSIG",
    "OP_CHECKMULTISIG",
];

/// True when `op` provably leaves a canonical boolean (0 or 1) on the stack.
fn produces_canonical_bool(op: &StackOp) -> bool {
    use num_traits::ToPrimitive;
    match op {
        StackOp::Opcode(code) => CANONICAL_BOOL_OPCODES.contains(&code.as_str()),
        StackOp::Push(PushValue::Bool(_)) => true,
        StackOp::Push(PushValue::Int(v)) => matches!(v.to_i128(), Some(0) | Some(1)),
        _ => false,
    }
}

fn match_window_3(a: &StackOp, b: &StackOp, c: &StackOp) -> Option<Vec<StackOp>> {
    if is_raw_bytes(a) || is_raw_bytes(b) || is_raw_bytes(c) {
        return None;
    }

    // <canonical-bool producer>, OP_NOT, OP_NOT → <canonical-bool producer>
    //
    // `OP_NOT OP_NOT` is boolean NORMALISATION, not numeric identity: for any
    // non-canonical operand (say 5) the pair yields 1, while deleting it leaves
    // 5. Truthiness is preserved, the VALUE is not -- and a downstream
    // `OP_EQUAL` / `OP_NUMEQUAL` / state serialisation consumes the value, so
    // the two programs disagree on accept/reject.
    //
    // The window therefore includes the PRODUCER of the value being negated and
    // only fires when that producer provably yields a canonical 0/1 (C17). This
    // matters because the `PUSH 0; OP_NUMEQUAL → OP_NOT` rule in
    // `match_window_2` synthesises a fresh `OP_NOT` sitting on top of an
    // ARBITRARY script number: for `x !== 0n` the lowerer emits
    // `PUSH x; PUSH 0; OP_NUMEQUAL; OP_NOT`, which the old unguarded 2-op rule
    // collapsed all the way down to `PUSH x`. With the guard the pair survives
    // as `PUSH x; OP_NOT; OP_NOT` -- still one byte shorter than the input, and
    // value-exact.
    if produces_canonical_bool(a) && is_opcode(b, "OP_NOT") && is_opcode(c, "OP_NOT") {
        return Some(vec![a.clone()]);
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

    // NOTE (F-001): no `PUSH 0, OP_ADD`, `PUSH 0, OP_SUB` or
    // `OP_NEGATE, OP_NEGATE -> []` rule. x+0, x-0 and -(-x) are identities over
    // integers, not over stack elements: the opcode decodes its operand as a
    // CScriptNum (rejecting a non-minimal encoding under strict rules) and
    // pushes back the minimal re-encoding. Deleting it changes accept/reject
    // and the value for a witness-supplied operand.

    // NOTE: `OP_NOT, OP_NOT -> []` used to live here as an unguarded 2-op rule.
    // It is unsound (C17) and now lives in `match_window_3`, which takes the
    // PRODUCER of the negated value into the window.

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
    use num_traits::ToPrimitive;
    matches!(op, StackOp::Push(PushValue::Int(v)) if v.to_i128() == Some(n))
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

    /// Test matcher: true if `op` is `PushValue::Int(n)` holding the given i128.
    fn is_push_int_eq(op: &StackOp, n: i128) -> bool {
        use num_traits::ToPrimitive;
        matches!(op, StackOp::Push(PushValue::Int(v)) if v.to_i128() == Some(n))
    }

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
        let ops = vec![StackOp::Push(PushValue::Int(BigInt::from(42))), StackOp::Drop];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "PUSH DROP should be eliminated, got {:?}", result);
    }

    /// NEGATIVE case for the C17 guard: a genuinely canonical producer still
    /// gets its `OP_NOT OP_NOT` pair removed, so the rule is not dead.
    #[test]
    fn test_not_not_removed_after_canonical_bool_producer() {
        for producer in [
            "OP_NUMEQUAL",
            "OP_EQUAL",
            "OP_LESSTHAN",
            "OP_BOOLAND",
            "OP_WITHIN",
            "OP_NOT",
            "OP_0NOTEQUAL",
            "OP_CHECKSIG",
        ] {
            let ops = vec![
                StackOp::Opcode(producer.to_string()),
                StackOp::Opcode("OP_NOT".to_string()),
                StackOp::Opcode("OP_NOT".to_string()),
            ];
            let result = optimize_stack_ops(&ops);
            assert_eq!(result.len(), 1, "{producer} NOT NOT should collapse, got {result:?}");
            assert!(matches!(&result[0], StackOp::Opcode(c) if c == producer));
        }

        // Literal canonical booleans qualify too.
        for lit in [
            StackOp::Push(PushValue::Bool(true)),
            StackOp::Push(PushValue::Int(BigInt::from(0))),
            StackOp::Push(PushValue::Int(BigInt::from(1))),
        ] {
            let ops = vec![
                lit.clone(),
                StackOp::Opcode("OP_NOT".to_string()),
                StackOp::Opcode("OP_NOT".to_string()),
            ];
            let result = optimize_stack_ops(&ops);
            assert_eq!(result.len(), 1, "{lit:?} NOT NOT should collapse, got {result:?}");
        }
    }

    /// C17: `OP_NOT OP_NOT` is boolean normalisation, not numeric identity.
    /// Without a provably-canonical producer in the window the pair MUST
    /// survive, otherwise `x !== 0n` compiles to `x` and valid spends are
    /// rejected.
    #[test]
    fn test_not_not_kept_without_canonical_producer() {
        // Bare pair: the negated value came from outside the window.
        let bare = vec![
            StackOp::Opcode("OP_NOT".to_string()),
            StackOp::Opcode("OP_NOT".to_string()),
        ];
        assert_eq!(optimize_stack_ops(&bare).len(), 2, "bare NOT NOT must survive");

        // Non-canonical producers: an arbitrary script number, a byte string,
        // and stack-shuffling ops whose provenance the window cannot see.
        for producer in [
            StackOp::Push(PushValue::Int(BigInt::from(5))),
            StackOp::Push(PushValue::Bytes(vec![0xde, 0xad])),
            StackOp::Dup,
            StackOp::Swap,
            StackOp::Opcode("OP_ADD".to_string()),
            StackOp::Opcode("OP_SHA256".to_string()),
        ] {
            let ops = vec![
                producer.clone(),
                StackOp::Opcode("OP_NOT".to_string()),
                StackOp::Opcode("OP_NOT".to_string()),
            ];
            let result = optimize_stack_ops(&ops);
            assert_eq!(
                result.len(),
                3,
                "NOT NOT must survive after non-canonical producer {producer:?}, got {result:?}"
            );
        }
    }

    /// End-to-end shape of the C17 bug: `x !== 0n` lowers to
    /// `PUSH 0; OP_NUMEQUAL; OP_NOT`. The `PUSH 0; OP_NUMEQUAL → OP_NOT` rule
    /// fires first and yields `OP_NOT; OP_NOT` on top of the witness value; the
    /// unguarded rule then deleted both, turning `x !== 0n` into `x`. The pair
    /// must survive.
    #[test]
    fn test_ne_zero_does_not_collapse_to_operand() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(0))),
            StackOp::Opcode("OP_NUMEQUAL".to_string()),
            StackOp::Opcode("OP_NOT".to_string()),
            StackOp::Push(PushValue::Bool(true)),
            StackOp::Opcode("OP_NUMEQUAL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        let codes: Vec<String> = result
            .iter()
            .map(|op| match op {
                StackOp::Opcode(c) => c.clone(),
                StackOp::Push(PushValue::Bool(b)) => format!("PUSH({b})"),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(
            codes,
            vec!["OP_NOT", "OP_NOT", "PUSH(true)", "OP_NUMEQUAL"],
            "x !== 0n must keep its OP_NOT pair"
        );
    }

    // F-001: -(-x) = x over integers, but OP_NEGATE decodes its operand as a
    // CScriptNum (rejecting a non-minimal encoding under strict rules) and
    // re-encodes it minimally; deleting the pair changes accept/reject and
    // value for a witness operand. Proves the pair survives; does not execute.
    #[test]
    fn test_negate_negate_kept() {
        let ops = vec![
            StackOp::Opcode("OP_NEGATE".to_string()),
            StackOp::Opcode("OP_NEGATE".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(format!("{:?}", result), format!("{:?}", ops), "NEGATE NEGATE must survive (F-001)");
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
            StackOp::Push(PushValue::Int(BigInt::from(1))),
            StackOp::Opcode("OP_ADD".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_1ADD"));
    }

    #[test]
    fn test_push1_sub_becomes_1sub() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(1))),
            StackOp::Opcode("OP_SUB".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_1SUB"));
    }

    // F-001: PUSH(0) ADD / PUSH(0) SUB must survive — OP_ADD / OP_SUB
    // validate and normalise their operand (see test_negate_negate_kept).
    #[test]
    fn test_push0_add_kept() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(0))),
            StackOp::Opcode("OP_ADD".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(format!("{:?}", result), format!("{:?}", ops), "PUSH(0) ADD must survive (F-001)");
    }

    #[test]
    fn test_push0_sub_kept() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(0))),
            StackOp::Opcode("OP_SUB".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(format!("{:?}", result), format!("{:?}", ops), "PUSH(0) SUB must survive (F-001)");
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
            StackOp::Push(PushValue::Int(BigInt::from(0))),
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
            StackOp::Push(PushValue::Int(BigInt::from(0))),
            StackOp::Roll { depth: 0 },
        ];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "PUSH(0) Roll{{0}} should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_push1_roll_struct_becomes_swap() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(1))),
            StackOp::Roll { depth: 1 },
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Swap));
    }

    #[test]
    fn test_push2_roll_struct_becomes_rot() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(2))),
            StackOp::Roll { depth: 2 },
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Rot));
    }

    #[test]
    fn test_push0_pick_struct_becomes_dup() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(0))),
            StackOp::Pick { depth: 0 },
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Dup));
    }

    #[test]
    fn test_push1_pick_struct_becomes_over() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(1))),
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
            StackOp::Push(PushValue::Int(BigInt::from(0))),
            StackOp::Opcode("OP_ROLL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "PUSH(0) Opcode(OP_ROLL) should be eliminated, got {:?}", result);
    }

    #[test]
    fn test_push1_opcode_roll_string_becomes_swap() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(1))),
            StackOp::Opcode("OP_ROLL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Swap));
    }

    #[test]
    fn test_push2_opcode_roll_string_becomes_rot() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(2))),
            StackOp::Opcode("OP_ROLL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Rot));
    }

    #[test]
    fn test_push0_opcode_pick_string_becomes_dup() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(0))),
            StackOp::Opcode("OP_PICK".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], StackOp::Dup));
    }

    #[test]
    fn test_push1_opcode_pick_string_becomes_over() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(1))),
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
            StackOp::Push(PushValue::Int(BigInt::from(3))),
            StackOp::Push(PushValue::Int(BigInt::from(7))),
            StackOp::Opcode("OP_ADD".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(is_push_int_eq(&result[0], 10));
    }

    #[test]
    fn test_constant_fold_sub() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(10))),
            StackOp::Push(PushValue::Int(BigInt::from(3))),
            StackOp::Opcode("OP_SUB".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(is_push_int_eq(&result[0], 7));
    }

    #[test]
    fn test_constant_fold_mul() {
        let ops = vec![
            StackOp::Push(PushValue::Int(BigInt::from(4))),
            StackOp::Push(PushValue::Int(BigInt::from(5))),
            StackOp::Opcode("OP_MUL".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        assert!(is_push_int_eq(&result[0], 20));
    }

    // -----------------------------------------------------------------------
    // 4-op optimizations (chain folding)
    // -----------------------------------------------------------------------

    #[test]
    fn test_chain_fold_add_add() {
        // x PUSH(3) ADD PUSH(7) ADD -> x PUSH(10) ADD
        let ops = vec![
            StackOp::Dup, // stand-in for some value on stack
            StackOp::Push(PushValue::Int(BigInt::from(3))),
            StackOp::Opcode("OP_ADD".to_string()),
            StackOp::Push(PushValue::Int(BigInt::from(7))),
            StackOp::Opcode("OP_ADD".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 3, "expected DUP PUSH(10) ADD, got {:?}", result);
        assert!(matches!(&result[0], StackOp::Dup));
        assert!(is_push_int_eq(&result[1], 10));
        assert!(matches!(&result[2], StackOp::Opcode(c) if c == "OP_ADD"));
    }

    #[test]
    fn test_chain_fold_sub_sub() {
        let ops = vec![
            StackOp::Dup,
            StackOp::Push(PushValue::Int(BigInt::from(2))),
            StackOp::Opcode("OP_SUB".to_string()),
            StackOp::Push(PushValue::Int(BigInt::from(3))),
            StackOp::Opcode("OP_SUB".to_string()),
        ];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 3, "expected DUP PUSH(5) SUB, got {:?}", result);
        assert!(is_push_int_eq(&result[1], 5));
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
            StackOp::Push(PushValue::Int(BigInt::from(5))),
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
            then_locs: Vec::new(),
            else_locs: Vec::new(),
        }];
        let result = optimize_stack_ops(&ops);
        assert_eq!(result.len(), 1);
        if let StackOp::If { then_ops, else_ops, .. } = &result[0] {
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
        // After first pass: PUSH(7) DROP is removed, leaving DUP DROP which is
        // removed on the second pass. (Was PUSH(0) ADD, which F-001 no longer
        // eliminates.)
        let ops = vec![
            StackOp::Dup,
            StackOp::Push(PushValue::Int(BigInt::from(7))),
            StackOp::Drop,
            StackOp::Drop,
        ];
        let result = optimize_stack_ops(&ops);
        assert!(result.is_empty(), "iterative optimization should remove DUP (PUSH7 DROP -> empty) DROP -> DUP DROP -> empty, got {:?}", result);
    }
}
