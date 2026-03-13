//! Comprehensive peephole optimizer tests for the Rust compiler.
//!
//! Mirrors the coverage in compilers/go/codegen/optimizer_test.go (59+ tests)
//! and compilers/python/tests/test_optimizer.py (40+ tests).
//!
//! These are integration-level tests that call the public `optimize_stack_ops`
//! function via the crate's public API.

use runar_compiler_rust::codegen::optimizer::optimize_stack_ops;
use runar_compiler_rust::codegen::stack::{PushValue, StackOp};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn push_int(n: i128) -> StackOp {
    StackOp::Push(PushValue::Int(n))
}

fn opcode(code: &str) -> StackOp {
    StackOp::Opcode(code.to_string())
}

fn push_bool(b: bool) -> StackOp {
    StackOp::Push(PushValue::Bool(b))
}

fn push_bytes(data: &[u8]) -> StackOp {
    StackOp::Push(PushValue::Bytes(data.to_vec()))
}

// ---------------------------------------------------------------------------
// 2-op window: SWAP SWAP -> removed
// ---------------------------------------------------------------------------

#[test]
fn test_swap_swap_removed() {
    let ops = vec![StackOp::Swap, StackOp::Swap];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "SWAP SWAP should be removed entirely, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 2-op window: DUP DROP -> removed
// ---------------------------------------------------------------------------

#[test]
fn test_dup_drop_removed() {
    let ops = vec![StackOp::Dup, StackOp::Drop];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "DUP DROP should be removed entirely, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 2-op window: OP_DUP OP_DROP (string opcode form) -> removed
// ---------------------------------------------------------------------------

#[test]
fn test_opcode_dup_drop_removed() {
    let ops = vec![opcode("OP_DUP"), opcode("OP_DROP")];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "OP_DUP OP_DROP (opcode string form) should be removed entirely, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH x DROP -> removed (dead value elimination)
// ---------------------------------------------------------------------------

#[test]
fn test_push_int_drop_removed() {
    let ops = vec![push_int(99), StackOp::Drop];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "PUSH(99) DROP should be removed entirely, got {:?}",
        result
    );
}

#[test]
fn test_push_bool_true_drop_removed() {
    let ops = vec![push_bool(true), StackOp::Drop];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "PUSH(true) DROP should be removed entirely, got {:?}",
        result
    );
}

#[test]
fn test_push_bool_false_drop_removed() {
    let ops = vec![push_bool(false), StackOp::Drop];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "PUSH(false) DROP should be removed entirely, got {:?}",
        result
    );
}

#[test]
fn test_push_bytes_drop_removed() {
    let ops = vec![push_bytes(&[0xde, 0xad, 0xbe, 0xef]), StackOp::Drop];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "PUSH(<bytes>) DROP should be removed entirely, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 2-op window: DROP DROP -> OP_2DROP
// ---------------------------------------------------------------------------

#[test]
fn test_double_drop_becomes_2drop() {
    let ops = vec![StackOp::Drop, StackOp::Drop];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "DROP DROP should collapse to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_2DROP"),
        "expected OP_2DROP, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: OVER OVER -> OP_2DUP
// ---------------------------------------------------------------------------

#[test]
fn test_double_over_becomes_2dup() {
    let ops = vec![StackOp::Over, StackOp::Over];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "OVER OVER should collapse to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_2DUP"),
        "expected OP_2DUP, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: NOT NOT -> removed
// ---------------------------------------------------------------------------

#[test]
fn test_double_not_removed() {
    let ops = vec![opcode("OP_NOT"), opcode("OP_NOT")];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "OP_NOT OP_NOT should be removed entirely, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 2-op window: NEGATE NEGATE -> removed
// ---------------------------------------------------------------------------

#[test]
fn test_double_negate_removed() {
    let ops = vec![opcode("OP_NEGATE"), opcode("OP_NEGATE")];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "OP_NEGATE OP_NEGATE should be removed entirely, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(1) ADD -> OP_1ADD
// ---------------------------------------------------------------------------

#[test]
fn test_push1_add_becomes_1add() {
    let ops = vec![push_int(1), opcode("OP_ADD")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(1) ADD should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_1ADD"),
        "expected OP_1ADD, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(1) SUB -> OP_1SUB
// ---------------------------------------------------------------------------

#[test]
fn test_push1_sub_becomes_1sub() {
    let ops = vec![push_int(1), opcode("OP_SUB")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(1) SUB should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_1SUB"),
        "expected OP_1SUB, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) ADD -> removed (additive identity)
// ---------------------------------------------------------------------------

#[test]
fn test_push0_add_removed() {
    let ops = vec![push_int(0), opcode("OP_ADD")];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "PUSH(0) OP_ADD should be removed (additive identity), got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) SUB -> removed (subtractive identity)
// ---------------------------------------------------------------------------

#[test]
fn test_push0_sub_removed() {
    let ops = vec![push_int(0), opcode("OP_SUB")];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "PUSH(0) OP_SUB should be removed (subtractive identity), got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 2-op window: EQUAL VERIFY -> EQUALVERIFY
// ---------------------------------------------------------------------------

#[test]
fn test_equal_verify_becomes_equalverify() {
    let ops = vec![opcode("OP_EQUAL"), opcode("OP_VERIFY")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "EQUAL VERIFY should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_EQUALVERIFY"),
        "expected OP_EQUALVERIFY, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: CHECKSIG VERIFY -> CHECKSIGVERIFY
// ---------------------------------------------------------------------------

#[test]
fn test_checksig_verify_becomes_checksigverify() {
    let ops = vec![opcode("OP_CHECKSIG"), opcode("OP_VERIFY")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "CHECKSIG VERIFY should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_CHECKSIGVERIFY"),
        "expected OP_CHECKSIGVERIFY, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: NUMEQUAL VERIFY -> NUMEQUALVERIFY
// ---------------------------------------------------------------------------

#[test]
fn test_numequal_verify_becomes_numequalverify() {
    let ops = vec![opcode("OP_NUMEQUAL"), opcode("OP_VERIFY")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "NUMEQUAL VERIFY should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_NUMEQUALVERIFY"),
        "expected OP_NUMEQUALVERIFY, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: CHECKMULTISIG VERIFY -> CHECKMULTISIGVERIFY
// ---------------------------------------------------------------------------

#[test]
fn test_checkmultisig_verify_becomes_checkmultisigverify() {
    let ops = vec![opcode("OP_CHECKMULTISIG"), opcode("OP_VERIFY")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "CHECKMULTISIG VERIFY should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_CHECKMULTISIGVERIFY"),
        "expected OP_CHECKMULTISIGVERIFY, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: SHA256 SHA256 -> HASH256
// ---------------------------------------------------------------------------

#[test]
fn test_sha256_sha256_becomes_hash256() {
    let ops = vec![opcode("OP_SHA256"), opcode("OP_SHA256")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "SHA256 SHA256 should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_HASH256"),
        "expected OP_HASH256, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) NUMEQUAL -> NOT
// ---------------------------------------------------------------------------

#[test]
fn test_push0_numequal_becomes_not() {
    let ops = vec![push_int(0), opcode("OP_NUMEQUAL")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(0) NUMEQUAL should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_NOT"),
        "expected OP_NOT, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) ROLL (typed struct) -> removed
// ---------------------------------------------------------------------------

#[test]
fn test_push0_roll_struct_removed() {
    let ops = vec![push_int(0), StackOp::Roll { depth: 0 }];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "PUSH(0) Roll{{depth:0}} should be removed (roll 0 is no-op), got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(1) ROLL (typed struct) -> SWAP
// ---------------------------------------------------------------------------

#[test]
fn test_push1_roll_struct_becomes_swap() {
    let ops = vec![push_int(1), StackOp::Roll { depth: 1 }];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(1) Roll{{depth:1}} should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Swap),
        "expected Swap, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(2) ROLL (typed struct) -> ROT
// ---------------------------------------------------------------------------

#[test]
fn test_push2_roll_struct_becomes_rot() {
    let ops = vec![push_int(2), StackOp::Roll { depth: 2 }];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(2) Roll{{depth:2}} should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Rot),
        "expected Rot, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) PICK (typed struct) -> DUP
// ---------------------------------------------------------------------------

#[test]
fn test_push0_pick_struct_becomes_dup() {
    let ops = vec![push_int(0), StackOp::Pick { depth: 0 }];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(0) Pick{{depth:0}} should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Dup),
        "expected Dup, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(1) PICK (typed struct) -> OVER
// ---------------------------------------------------------------------------

#[test]
fn test_push1_pick_struct_becomes_over() {
    let ops = vec![push_int(1), StackOp::Pick { depth: 1 }];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(1) Pick{{depth:1}} should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Over),
        "expected Over, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) Opcode("OP_ROLL") (SLH-DSA string form) -> removed
// ---------------------------------------------------------------------------

#[test]
fn test_push0_opcode_roll_string_removed() {
    let ops = vec![push_int(0), opcode("OP_ROLL")];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "PUSH(0) Opcode(OP_ROLL) should be removed, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(1) Opcode("OP_ROLL") (SLH-DSA string form) -> SWAP
// ---------------------------------------------------------------------------

#[test]
fn test_push1_opcode_roll_string_becomes_swap() {
    let ops = vec![push_int(1), opcode("OP_ROLL")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(1) Opcode(OP_ROLL) should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Swap),
        "expected Swap, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(2) Opcode("OP_ROLL") -> ROT
// ---------------------------------------------------------------------------

#[test]
fn test_push2_opcode_roll_string_becomes_rot() {
    let ops = vec![push_int(2), opcode("OP_ROLL")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(2) Opcode(OP_ROLL) should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Rot),
        "expected Rot, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) Opcode("OP_PICK") -> DUP
// ---------------------------------------------------------------------------

#[test]
fn test_push0_opcode_pick_string_becomes_dup() {
    let ops = vec![push_int(0), opcode("OP_PICK")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(0) Opcode(OP_PICK) should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Dup),
        "expected Dup, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(1) Opcode("OP_PICK") -> OVER
// ---------------------------------------------------------------------------

#[test]
fn test_push1_opcode_pick_string_becomes_over() {
    let ops = vec![push_int(1), opcode("OP_PICK")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(1) Opcode(OP_PICK) should reduce to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Over),
        "expected Over, got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 3-op window (constant folding): PUSH(a) PUSH(b) ADD -> PUSH(a+b)
// ---------------------------------------------------------------------------

#[test]
fn test_const_fold_add() {
    let ops = vec![push_int(3), push_int(7), opcode("OP_ADD")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(3) PUSH(7) ADD should fold to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Push(PushValue::Int(10))),
        "expected PUSH(10), got {:?}",
        result[0]
    );
}

#[test]
fn test_const_fold_add_large_values() {
    let ops = vec![push_int(1000), push_int(999), opcode("OP_ADD")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1);
    assert!(
        matches!(&result[0], StackOp::Push(PushValue::Int(1999))),
        "expected PUSH(1999), got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 3-op window (constant folding): PUSH(a) PUSH(b) SUB -> PUSH(a-b)
// ---------------------------------------------------------------------------

#[test]
fn test_const_fold_sub() {
    let ops = vec![push_int(10), push_int(4), opcode("OP_SUB")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(10) PUSH(4) SUB should fold to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Push(PushValue::Int(6))),
        "expected PUSH(6), got {:?}",
        result[0]
    );
}

#[test]
fn test_const_fold_sub_produces_negative() {
    let ops = vec![push_int(3), push_int(10), opcode("OP_SUB")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1);
    assert!(
        matches!(&result[0], StackOp::Push(PushValue::Int(-7))),
        "expected PUSH(-7), got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 3-op window (constant folding): PUSH(a) PUSH(b) MUL -> PUSH(a*b)
// ---------------------------------------------------------------------------

#[test]
fn test_const_fold_mul() {
    let ops = vec![push_int(5), push_int(6), opcode("OP_MUL")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "PUSH(5) PUSH(6) MUL should fold to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Push(PushValue::Int(30))),
        "expected PUSH(30), got {:?}",
        result[0]
    );
}

// ---------------------------------------------------------------------------
// 3-op window: DIV is NOT constant-folded (not in the rules)
// ---------------------------------------------------------------------------

#[test]
fn test_const_fold_div_not_applied() {
    let ops = vec![push_int(10), push_int(2), opcode("OP_DIV")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(
        result.len(),
        3,
        "PUSH PUSH DIV should NOT be constant-folded (3 ops unchanged), got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// 4-op window (chain folding): PUSH(a) ADD PUSH(b) ADD -> PUSH(a+b) ADD
// ---------------------------------------------------------------------------

#[test]
fn test_chain_fold_add_add() {
    let ops = vec![push_int(3), opcode("OP_ADD"), push_int(5), opcode("OP_ADD")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 2, "PUSH(3) ADD PUSH(5) ADD should chain-fold to 2 ops, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Push(PushValue::Int(8))),
        "expected PUSH(8), got {:?}",
        result[0]
    );
    assert!(
        matches!(&result[1], StackOp::Opcode(c) if c == "OP_ADD"),
        "expected OP_ADD, got {:?}",
        result[1]
    );
}

// ---------------------------------------------------------------------------
// 4-op window (chain folding): PUSH(a) SUB PUSH(b) SUB -> PUSH(a+b) SUB
// ---------------------------------------------------------------------------

#[test]
fn test_chain_fold_sub_sub() {
    let ops = vec![push_int(2), opcode("OP_SUB"), push_int(3), opcode("OP_SUB")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 2, "PUSH(2) SUB PUSH(3) SUB should chain-fold to 2 ops, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Push(PushValue::Int(5))),
        "expected PUSH(5), got {:?}",
        result[0]
    );
    assert!(
        matches!(&result[1], StackOp::Opcode(c) if c == "OP_SUB"),
        "expected OP_SUB, got {:?}",
        result[1]
    );
}

// ---------------------------------------------------------------------------
// Non-optimizable sequences — pass through unchanged
// ---------------------------------------------------------------------------

#[test]
fn test_single_opcode_unchanged() {
    let ops = vec![opcode("OP_ADD")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "single opcode should pass through unchanged");
    assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_ADD"));
}

#[test]
fn test_single_push_unchanged() {
    let ops = vec![push_int(42)];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "single push should pass through unchanged");
    assert!(matches!(&result[0], StackOp::Push(PushValue::Int(42))));
}

#[test]
fn test_unrelated_pair_unchanged() {
    let ops = vec![opcode("OP_ADD"), opcode("OP_SUB")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 2, "ADD SUB pair has no rule and should pass through unchanged");
    assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_ADD"));
    assert!(matches!(&result[1], StackOp::Opcode(c) if c == "OP_SUB"));
}

#[test]
fn test_empty_input() {
    let ops: Vec<StackOp> = vec![];
    let result = optimize_stack_ops(&ops);
    assert!(result.is_empty(), "empty input should produce empty output");
}

#[test]
fn test_p2pkh_sequence_unchanged() {
    // OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG — no rules apply
    let ops = vec![
        opcode("OP_DUP"),
        opcode("OP_HASH160"),
        opcode("OP_EQUALVERIFY"),
        opcode("OP_CHECKSIG"),
    ];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 4, "P2PKH sequence should pass through unchanged, got {:?}", result);
    assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_DUP"));
    assert!(matches!(&result[1], StackOp::Opcode(c) if c == "OP_HASH160"));
    assert!(matches!(&result[2], StackOp::Opcode(c) if c == "OP_EQUALVERIFY"));
    assert!(matches!(&result[3], StackOp::Opcode(c) if c == "OP_CHECKSIG"));
}

#[test]
fn test_large_roll_not_simplified() {
    // Only PUSH(0/1/2) + ROLL have rules; PUSH(5) ROLL should pass through
    let ops = vec![push_int(5), opcode("OP_ROLL")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 2, "PUSH(5) OP_ROLL should pass through unchanged, got {:?}", result);
}

#[test]
fn test_swap_then_different_op_unchanged() {
    let ops = vec![StackOp::Swap, opcode("OP_ADD")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 2, "SWAP ADD has no rule and should pass through unchanged");
}

#[test]
fn test_dup_then_add_unchanged() {
    let ops = vec![StackOp::Dup, opcode("OP_ADD")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 2, "DUP ADD has no rule and should pass through unchanged");
}

// ---------------------------------------------------------------------------
// String-form OP_ROLL/OP_PICK as raw opcode strings (SLH-DSA emits these)
// Two identical OP_ROLL opcode strings don't match any rule
// ---------------------------------------------------------------------------

#[test]
fn test_opcode_string_roll_roll_unchanged() {
    // Two OP_ROLL string opcodes don't match the "SWAP SWAP" rule
    // (which matches StackOp::Swap, not StackOp::Opcode("OP_ROLL"))
    let ops = vec![opcode("OP_ROLL"), opcode("OP_ROLL")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 2, "OP_ROLL OP_ROLL string form should NOT match any 2-op rule");
    assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_ROLL"));
    assert!(matches!(&result[1], StackOp::Opcode(c) if c == "OP_ROLL"));
}

#[test]
fn test_opcode_string_roll_passthrough_sequence() {
    // Verify SLH-DSA style sequences pass through without crashing
    let ops = vec![
        opcode("OP_DUP"),
        opcode("OP_ROLL"),
        opcode("OP_PICK"),
        opcode("OP_ADD"),
    ];
    let result = optimize_stack_ops(&ops);
    // OP_DUP alone, OP_ROLL and OP_PICK string forms don't match typed ops
    // The OP_ROLL + OP_PICK pair also has no rule
    // Net: should produce original 4 ops (no rule reduces these)
    assert!(result.len() <= 4, "SLH-DSA opcode string sequence should not crash");
    assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_DUP"));
}

// ---------------------------------------------------------------------------
// Multi-pass convergence
// ---------------------------------------------------------------------------

#[test]
fn test_multi_pass_optimization() {
    // Pass 1: PUSH(0) ADD -> removed, leaving: SWAP SWAP OP_CHECKSIG
    // Pass 2: SWAP SWAP -> removed, leaving: OP_CHECKSIG
    let ops = vec![
        push_int(0),
        opcode("OP_ADD"),
        StackOp::Swap,
        StackOp::Swap,
        opcode("OP_CHECKSIG"),
    ];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "multi-pass should converge to 1 op, got {:?}", result);
    assert!(
        matches!(&result[0], StackOp::Opcode(c) if c == "OP_CHECKSIG"),
        "expected OP_CHECKSIG, got {:?}",
        result[0]
    );
}

#[test]
fn test_swap_swap_in_middle_of_sequence() {
    // ADD SWAP SWAP SUB -> ADD SUB (SWAP SWAP in the middle is eliminated)
    let ops = vec![
        opcode("OP_ADD"),
        StackOp::Swap,
        StackOp::Swap,
        opcode("OP_SUB"),
    ];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 2, "SWAP SWAP in middle should be eliminated, got {:?}", result);
    assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_ADD"));
    assert!(matches!(&result[1], StackOp::Opcode(c) if c == "OP_SUB"));
}

#[test]
fn test_iterative_convergence_dup_push0_add_drop() {
    // DUP PUSH(0) ADD DROP
    // Pass 1: PUSH(0) ADD -> removed, leaving: DUP DROP
    // Pass 2: DUP DROP -> removed, leaving: empty
    let ops = vec![
        StackOp::Dup,
        push_int(0),
        opcode("OP_ADD"),
        StackOp::Drop,
    ];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "DUP PUSH(0) ADD DROP should converge to empty, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// Nested if-block optimization — rules apply inside then/else branches
// ---------------------------------------------------------------------------

#[test]
fn test_then_branch_optimized() {
    // if { SWAP SWAP } else {} -> if { } else {}
    let ops = vec![StackOp::If {
        then_ops: vec![StackOp::Swap, StackOp::Swap],
        else_ops: vec![],
    }];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "if op should remain, got {:?}", result);
    if let StackOp::If { then_ops, else_ops } = &result[0] {
        assert!(
            then_ops.is_empty(),
            "then branch SWAP SWAP should be eliminated, got {:?}",
            then_ops
        );
        assert!(else_ops.is_empty());
    } else {
        panic!("expected If, got {:?}", result[0]);
    }
}

#[test]
fn test_else_branch_optimized() {
    // if { OP_ADD } else { OP_CHECKSIG OP_VERIFY } -> if { OP_ADD } else { OP_CHECKSIGVERIFY }
    let ops = vec![StackOp::If {
        then_ops: vec![opcode("OP_ADD")],
        else_ops: vec![opcode("OP_CHECKSIG"), opcode("OP_VERIFY")],
    }];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1);
    if let StackOp::If { then_ops, else_ops } = &result[0] {
        assert_eq!(then_ops.len(), 1);
        assert!(matches!(&then_ops[0], StackOp::Opcode(c) if c == "OP_ADD"));
        assert_eq!(
            else_ops.len(),
            1,
            "CHECKSIG VERIFY in else branch should become CHECKSIGVERIFY, got {:?}",
            else_ops
        );
        assert!(
            matches!(&else_ops[0], StackOp::Opcode(c) if c == "OP_CHECKSIGVERIFY"),
            "expected OP_CHECKSIGVERIFY in else, got {:?}",
            else_ops[0]
        );
    } else {
        panic!("expected If, got {:?}", result[0]);
    }
}

#[test]
fn test_both_branches_optimized() {
    // if { DUP DROP } else { OP_NOT OP_NOT } -> if { } else { }
    let ops = vec![StackOp::If {
        then_ops: vec![StackOp::Dup, StackOp::Drop],
        else_ops: vec![opcode("OP_NOT"), opcode("OP_NOT")],
    }];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1);
    if let StackOp::If { then_ops, else_ops } = &result[0] {
        assert!(then_ops.is_empty(), "DUP DROP in then should be eliminated, got {:?}", then_ops);
        assert!(else_ops.is_empty(), "NOT NOT in else should be eliminated, got {:?}", else_ops);
    } else {
        panic!("expected If, got {:?}", result[0]);
    }
}

#[test]
fn test_then_branch_with_constant_fold() {
    // if { PUSH(3) PUSH(4) ADD } else {} -> if { PUSH(7) } else {}
    let ops = vec![StackOp::If {
        then_ops: vec![push_int(3), push_int(4), opcode("OP_ADD")],
        else_ops: vec![],
    }];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1);
    if let StackOp::If { then_ops, else_ops } = &result[0] {
        assert_eq!(then_ops.len(), 1, "PUSH(3) PUSH(4) ADD should fold to PUSH(7), got {:?}", then_ops);
        assert!(matches!(&then_ops[0], StackOp::Push(PushValue::Int(7))));
        assert!(else_ops.is_empty());
    } else {
        panic!("expected If, got {:?}", result[0]);
    }
}

#[test]
fn test_nested_if_complex() {
    // Outer sequence containing both an If and a trailing SWAP SWAP
    // if { OP_EQUAL OP_VERIFY } else { OP_NOT OP_NOT }  followed by SWAP SWAP
    // -> if { OP_EQUALVERIFY } else {} followed by nothing
    let ops = vec![
        StackOp::If {
            then_ops: vec![opcode("OP_EQUAL"), opcode("OP_VERIFY")],
            else_ops: vec![opcode("OP_NOT"), opcode("OP_NOT")],
        },
        StackOp::Swap,
        StackOp::Swap,
    ];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 1, "trailing SWAP SWAP should be removed, got {:?}", result);
    if let StackOp::If { then_ops, else_ops } = &result[0] {
        assert_eq!(
            then_ops.len(),
            1,
            "EQUAL VERIFY in then should fuse to EQUALVERIFY, got {:?}",
            then_ops
        );
        assert!(matches!(&then_ops[0], StackOp::Opcode(c) if c == "OP_EQUALVERIFY"));
        assert!(else_ops.is_empty(), "NOT NOT in else should be eliminated, got {:?}", else_ops);
    } else {
        panic!("expected If, got {:?}", result[0]);
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_push_zero_not_confused_with_other_push() {
    // PUSH(0) OP_NUMEQUAL -> OP_NOT, but PUSH(1) OP_NUMEQUAL should NOT match
    let ops = vec![push_int(1), opcode("OP_NUMEQUAL")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 2, "PUSH(1) NUMEQUAL has no rule (only PUSH(0)), got {:?}", result);
}

#[test]
fn test_only_push1_triggers_1add_not_push2() {
    // Only PUSH(1) + ADD -> 1ADD; PUSH(2) + ADD should not be simplified
    let ops = vec![push_int(2), opcode("OP_ADD")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 2, "PUSH(2) ADD has no 2-op rule, got {:?}", result);
}

#[test]
fn test_push_negative_one_drop_removed() {
    // Negative push values are still Push ops and should be eliminated with DROP
    let ops = vec![push_int(-1), StackOp::Drop];
    let result = optimize_stack_ops(&ops);
    assert!(
        result.is_empty(),
        "PUSH(-1) DROP should be removed entirely, got {:?}",
        result
    );
}

#[test]
fn test_long_sequence_partial_optimization() {
    // A sequence where only part is optimizable
    // OP_ADD  SWAP SWAP  OP_SUB  SWAP SWAP  OP_MUL
    // -> OP_ADD OP_SUB OP_MUL (SWAP SWAP pairs removed)
    let ops = vec![
        opcode("OP_ADD"),
        StackOp::Swap,
        StackOp::Swap,
        opcode("OP_SUB"),
        StackOp::Swap,
        StackOp::Swap,
        opcode("OP_MUL"),
    ];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 3, "both SWAP SWAP pairs should be removed, got {:?}", result);
    assert!(matches!(&result[0], StackOp::Opcode(c) if c == "OP_ADD"));
    assert!(matches!(&result[1], StackOp::Opcode(c) if c == "OP_SUB"));
    assert!(matches!(&result[2], StackOp::Opcode(c) if c == "OP_MUL"));
}

#[test]
fn test_chain_fold_add_with_context() {
    // Real-world pattern: some_op PUSH(3) ADD PUSH(7) ADD
    // The context (DUP) before should not affect the folding of the 4-op window
    let ops = vec![
        StackOp::Dup,
        push_int(3),
        opcode("OP_ADD"),
        push_int(7),
        opcode("OP_ADD"),
    ];
    let result = optimize_stack_ops(&ops);
    assert_eq!(result.len(), 3, "DUP PUSH(3) ADD PUSH(7) ADD -> DUP PUSH(10) ADD, got {:?}", result);
    assert!(matches!(&result[0], StackOp::Dup));
    assert!(matches!(&result[1], StackOp::Push(PushValue::Int(10))));
    assert!(matches!(&result[2], StackOp::Opcode(c) if c == "OP_ADD"));
}

// ---------------------------------------------------------------------------
// O32: division NOT constant-folded
// PUSH(6) PUSH(2) OP_DIV → unchanged (division is not folded)
// ---------------------------------------------------------------------------

#[test]
fn test_o32_division_not_constant_folded() {
    let ops = vec![push_int(6), push_int(2), opcode("OP_DIV")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(
        result.len(),
        3,
        "PUSH(6) PUSH(2) OP_DIV should NOT be constant-folded (3 ops unchanged), got {:?}",
        result
    );
    assert!(
        matches!(&result[0], StackOp::Push(PushValue::Int(6))),
        "first op should still be PUSH(6), got {:?}",
        result[0]
    );
    assert!(
        matches!(&result[1], StackOp::Push(PushValue::Int(2))),
        "second op should still be PUSH(2), got {:?}",
        result[1]
    );
    assert!(
        matches!(&result[2], StackOp::Opcode(c) if c == "OP_DIV"),
        "third op should still be OP_DIV, got {:?}",
        result[2]
    );
}

// ---------------------------------------------------------------------------
// O33: negative constant fold result
// PUSH(3) PUSH(10) OP_SUB → PUSH(-7)
// Bitcoin Script SUB computes: second_pushed - first_pushed = 3 - 10 = -7
// (the second item pushed is the minuend, first is the subtrahend)
// ---------------------------------------------------------------------------

#[test]
fn test_o33_negative_constant_fold_result() {
    // In Bitcoin Script, SUB pops b (top) then a (below), computes a - b.
    // With PUSH(3) PUSH(10) SUB: a=3, b=10, result = 3 - 10 = -7
    let ops = vec![push_int(3), push_int(10), opcode("OP_SUB")];
    let result = optimize_stack_ops(&ops);
    assert_eq!(
        result.len(),
        1,
        "PUSH(3) PUSH(10) OP_SUB should constant-fold to 1 op, got {:?}",
        result
    );
    assert!(
        matches!(&result[0], StackOp::Push(PushValue::Int(-7))),
        "PUSH(3) PUSH(10) OP_SUB should fold to PUSH(-7) (3 - 10 = -7), got {:?}",
        result[0]
    );
}
