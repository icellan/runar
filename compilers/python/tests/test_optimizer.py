"""Tests for the peephole optimizer.

Covers 2-op, 3-op, and 4-op optimization windows, non-optimizable sequences,
string-form opcode handling, and recursive optimization of nested if-blocks.
"""

from __future__ import annotations

import pytest

from runar_compiler.codegen.optimizer import optimize_stack_ops
from runar_compiler.codegen.stack import StackOp, PushValue


# ---------------------------------------------------------------------------
# 2-op optimizations
# ---------------------------------------------------------------------------

class TestWindow2Optimizations:
    def test_swap_swap_removed(self):
        ops = [StackOp(op="swap"), StackOp(op="swap")]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_dup_drop_removed(self):
        ops = [StackOp(op="dup"), StackOp(op="drop")]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_push_drop_removed(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=99)),
            StackOp(op="drop"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_push_bool_drop_removed(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bool", bool_val=True)),
            StackOp(op="drop"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_double_drop_becomes_2drop(self):
        ops = [StackOp(op="drop"), StackOp(op="drop")]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "opcode"
        assert result[0].code == "OP_2DROP"

    def test_double_over_becomes_2dup(self):
        ops = [StackOp(op="over"), StackOp(op="over")]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "opcode"
        assert result[0].code == "OP_2DUP"

    def test_double_not_removed(self):
        ops = [
            StackOp(op="opcode", code="OP_NOT"),
            StackOp(op="opcode", code="OP_NOT"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_double_negate_removed(self):
        ops = [
            StackOp(op="opcode", code="OP_NEGATE"),
            StackOp(op="opcode", code="OP_NEGATE"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_push1_add_becomes_1add(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1)),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_1ADD"

    def test_push1_sub_becomes_1sub(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1)),
            StackOp(op="opcode", code="OP_SUB"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_1SUB"

    def test_push0_add_removed(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=0)),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_push0_sub_removed(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=0)),
            StackOp(op="opcode", code="OP_SUB"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_equal_verify_becomes_equalverify(self):
        ops = [
            StackOp(op="opcode", code="OP_EQUAL"),
            StackOp(op="opcode", code="OP_VERIFY"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_EQUALVERIFY"

    def test_checksig_verify_becomes_checksigverify(self):
        ops = [
            StackOp(op="opcode", code="OP_CHECKSIG"),
            StackOp(op="opcode", code="OP_VERIFY"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_CHECKSIGVERIFY"

    def test_numequal_verify_becomes_numequalverify(self):
        ops = [
            StackOp(op="opcode", code="OP_NUMEQUAL"),
            StackOp(op="opcode", code="OP_VERIFY"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_NUMEQUALVERIFY"

    def test_checkmultisig_verify_becomes_checkmultisigverify(self):
        ops = [
            StackOp(op="opcode", code="OP_CHECKMULTISIG"),
            StackOp(op="opcode", code="OP_VERIFY"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_CHECKMULTISIGVERIFY"

    def test_sha256_sha256_becomes_hash256(self):
        ops = [
            StackOp(op="opcode", code="OP_SHA256"),
            StackOp(op="opcode", code="OP_SHA256"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_HASH256"

    def test_push0_numequal_becomes_not(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=0)),
            StackOp(op="opcode", code="OP_NUMEQUAL"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_NOT"

    def test_push0_roll0_removed(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=0)),
            StackOp(op="roll", depth=0),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_push1_roll1_becomes_swap(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1)),
            StackOp(op="roll", depth=1),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "swap"

    def test_push2_roll2_becomes_rot(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=2)),
            StackOp(op="roll", depth=2),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "rot"

    def test_push0_pick0_becomes_dup(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=0)),
            StackOp(op="pick", depth=0),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "dup"

    def test_push1_pick1_becomes_over(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1)),
            StackOp(op="pick", depth=1),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "over"

    def test_opcode_dup_opcode_drop_removed(self):
        """OP_DUP + OP_DROP string-form opcodes are also eliminated."""
        ops = [
            StackOp(op="opcode", code="OP_DUP"),
            StackOp(op="opcode", code="OP_DROP"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_push_negative_one_drop_removed(self):
        """PUSH(-1) DROP should be eliminated (negative int push is still a push).
        Mirrors Rust test_push_negative_one_drop_removed."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=-1)),
            StackOp(op="drop"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_only_push1_triggers_1add_not_push2(self):
        """PUSH(2) ADD should NOT become OP_1ADD — only PUSH(1) ADD triggers that rule.
        Mirrors Rust test_only_push1_triggers_1add_not_push2."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=2)),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# 3-op optimizations (constant folding)
# ---------------------------------------------------------------------------

class TestWindow3Optimizations:
    def test_push_push_add_folded(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=3)),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=7)),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "push"
        assert result[0].value.big_int == 10

    def test_push_push_sub_folded(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=10)),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=4)),
            StackOp(op="opcode", code="OP_SUB"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].value.big_int == 6

    def test_push_push_mul_folded(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=5)),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=6)),
            StackOp(op="opcode", code="OP_MUL"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].value.big_int == 30

    def test_const_fold_sub_produces_negative(self):
        """PUSH(3) PUSH(7) SUB -> PUSH(-4) (3 - 7 = -4, negative result is valid).
        Mirrors Rust test_const_fold_sub_produces_negative."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=3)),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=7)),
            StackOp(op="opcode", code="OP_SUB"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "push"
        assert result[0].value.big_int == -4

    def test_push_push_div_not_folded(self):
        """Division is not constant-folded (not in the rules)."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=10)),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=2)),
            StackOp(op="opcode", code="OP_DIV"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 3  # unchanged


# ---------------------------------------------------------------------------
# 4-op optimizations (chain folding)
# ---------------------------------------------------------------------------

class TestWindow4Optimizations:
    def test_push_add_push_add_chained(self):
        """PUSH a, OP_ADD, PUSH c, OP_ADD -> PUSH (a+c), OP_ADD."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=3)),
            StackOp(op="opcode", code="OP_ADD"),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=7)),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 2
        assert result[0].op == "push"
        assert result[0].value.big_int == 10
        assert result[1].op == "opcode"
        assert result[1].code == "OP_ADD"

    def test_push_sub_push_sub_chained(self):
        """PUSH a, OP_SUB, PUSH c, OP_SUB -> PUSH (a+c), OP_SUB."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=2)),
            StackOp(op="opcode", code="OP_SUB"),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=5)),
            StackOp(op="opcode", code="OP_SUB"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 2
        assert result[0].value.big_int == 7
        assert result[1].code == "OP_SUB"


# ---------------------------------------------------------------------------
# Non-optimizable sequences pass through unchanged
# ---------------------------------------------------------------------------

class TestNonOptimizable:
    def test_single_opcode_unchanged(self):
        ops = [StackOp(op="opcode", code="OP_ADD")]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_ADD"

    def test_unrelated_pair_unchanged(self):
        ops = [
            StackOp(op="opcode", code="OP_ADD"),
            StackOp(op="opcode", code="OP_SUB"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 2
        assert result[0].code == "OP_ADD"
        assert result[1].code == "OP_SUB"

    def test_swap_then_different_op_unchanged(self):
        ops = [
            StackOp(op="swap"),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 2

    def test_dup_then_add_unchanged(self):
        ops = [
            StackOp(op="dup"),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 2

    def test_empty_input(self):
        result = optimize_stack_ops([])
        assert len(result) == 0

    def test_single_push_unchanged(self):
        ops = [StackOp(op="push", value=PushValue(kind="bigint", big_int=42))]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].value.big_int == 42


# ---------------------------------------------------------------------------
# String-form opcode handling ("OP_ROLL" as raw opcode strings)
# ---------------------------------------------------------------------------

class TestStringFormOpcodes:
    def test_string_opcode_not_confused_with_stack_op(self):
        """An OP_ROLL as opcode string is not the same as a roll stack op."""
        ops = [
            StackOp(op="opcode", code="OP_ROLL"),
            StackOp(op="opcode", code="OP_ROLL"),
        ]
        result = optimize_stack_ops(ops)
        # Two OP_ROLL string opcodes don't match any rule
        assert len(result) == 2

    def test_string_opcode_verify_fuses(self):
        """OP_EQUAL string opcode + OP_VERIFY should still fuse."""
        ops = [
            StackOp(op="opcode", code="OP_EQUAL"),
            StackOp(op="opcode", code="OP_VERIFY"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_EQUALVERIFY"


# ---------------------------------------------------------------------------
# Recursive optimization of nested if-blocks
# ---------------------------------------------------------------------------

class TestNestedIfOptimization:
    def test_then_branch_optimized(self):
        ops = [
            StackOp(
                op="if",
                then=[StackOp(op="swap"), StackOp(op="swap")],
                else_ops=[],
            ),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "if"
        assert len(result[0].then) == 0

    def test_else_branch_optimized(self):
        ops = [
            StackOp(
                op="if",
                then=[StackOp(op="opcode", code="OP_ADD")],
                else_ops=[
                    StackOp(op="opcode", code="OP_CHECKSIG"),
                    StackOp(op="opcode", code="OP_VERIFY"),
                ],
            ),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert len(result[0].then) == 1
        assert result[0].then[0].code == "OP_ADD"
        assert len(result[0].else_ops) == 1
        assert result[0].else_ops[0].code == "OP_CHECKSIGVERIFY"

    def test_both_branches_optimized(self):
        ops = [
            StackOp(
                op="if",
                then=[
                    StackOp(op="dup"),
                    StackOp(op="drop"),
                ],
                else_ops=[
                    StackOp(op="opcode", code="OP_NOT"),
                    StackOp(op="opcode", code="OP_NOT"),
                ],
            ),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert len(result[0].then) == 0
        assert len(result[0].else_ops) == 0


# ---------------------------------------------------------------------------
# Iterative convergence
# ---------------------------------------------------------------------------

class TestAdditionalCoverage:
    def test_large_value_constant_fold(self):
        """PUSH(1000) PUSH(999) ADD -> PUSH(1999)."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1000)),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=999)),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "push"
        assert result[0].value.big_int == 1999

    def test_multiple_swap_swap_pairs_removed(self):
        """A long sequence with two SWAP SWAP pairs: both pairs are removed."""
        ops = [
            StackOp(op="opcode", code="OP_ADD"),
            StackOp(op="swap"),
            StackOp(op="swap"),
            StackOp(op="opcode", code="OP_MUL"),
            StackOp(op="swap"),
            StackOp(op="swap"),
            StackOp(op="opcode", code="OP_SUB"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 3
        assert result[0].code == "OP_ADD"
        assert result[1].code == "OP_MUL"
        assert result[2].code == "OP_SUB"

    def test_chain_fold_with_context(self):
        """DUP PUSH(3) ADD PUSH(7) ADD -> DUP PUSH(10) ADD (4-op chain fold on the tail)."""
        ops = [
            StackOp(op="dup"),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=3)),
            StackOp(op="opcode", code="OP_ADD"),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=7)),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        # The 4-op window (PUSH 3, ADD, PUSH 7, ADD) folds to (PUSH 10, ADD)
        assert len(result) == 3
        assert result[0].op == "dup"
        assert result[1].op == "push"
        assert result[1].value.big_int == 10
        assert result[2].code == "OP_ADD"


class TestStringFormFusing:
    def test_string_equalverify_fuses(self):
        """Opcode string 'OP_EQUAL' followed by OP_VERIFY (typed) should fuse to OP_EQUALVERIFY."""
        ops = [
            StackOp(op="opcode", code="OP_EQUAL"),
            StackOp(op="opcode", code="OP_VERIFY"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_EQUALVERIFY"

    def test_string_checksigverify_fuses(self):
        """Opcode string 'OP_CHECKSIG' + OP_VERIFY should fuse to OP_CHECKSIGVERIFY."""
        ops = [
            StackOp(op="opcode", code="OP_CHECKSIG"),
            StackOp(op="opcode", code="OP_VERIFY"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_CHECKSIGVERIFY"


class TestStringFormRollPick:
    # NOTE: The optimizer's _match_window2 only handles typed b.op=="roll" and
    # b.op=="pick" stack ops, NOT string-form OP_ROLL/OP_PICK opcodes. The SLH-DSA
    # codegen emits Opcode("OP_ROLL") strings, so these patterns should be handled.
    # These tests are marked xfail to document this source code gap.

    def test_push0_opcode_roll_string_removed(self):
        """Push(0) followed by Opcode('OP_ROLL') string form -> empty (roll 0 is no-op)."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=0)),
            StackOp(op="opcode", code="OP_ROLL"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_push1_opcode_roll_string_becomes_swap(self):
        """Push(1) followed by Opcode('OP_ROLL') string form -> SWAP."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1)),
            StackOp(op="opcode", code="OP_ROLL"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "swap"

    def test_push2_opcode_roll_string_becomes_rot(self):
        """Push(2) followed by Opcode('OP_ROLL') string form -> ROT."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=2)),
            StackOp(op="opcode", code="OP_ROLL"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "rot"

    def test_push0_opcode_pick_string_becomes_dup(self):
        """Push(0) followed by Opcode('OP_PICK') string form -> DUP."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=0)),
            StackOp(op="opcode", code="OP_PICK"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "dup"

    def test_push1_opcode_pick_string_becomes_over(self):
        """Push(1) followed by Opcode('OP_PICK') string form -> OVER."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1)),
            StackOp(op="opcode", code="OP_PICK"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "over"


# ---------------------------------------------------------------------------
# Gap tests: O32, O33
# ---------------------------------------------------------------------------

class TestOptimizerGaps:
    # O32: division NOT constant-folded
    def test_o32_division_not_constant_folded(self):
        """PUSH(6) PUSH(2) OP_DIV → sequence unchanged (division not folded)."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=6)),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=2)),
            StackOp(op="opcode", code="OP_DIV"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 3, (
            f"expected 3 ops (division not constant-folded), got {len(result)}: "
            f"{[op.op for op in result]}"
        )
        assert result[2].op == "opcode" and result[2].code == "OP_DIV", (
            f"expected OP_DIV unchanged, got: {result[2]}"
        )

    # O33: negative constant fold result for subtraction
    def test_o33_negative_constant_fold_sub(self):
        """PUSH(3) PUSH(10) OP_SUB → PUSH(-7).
        Bitcoin Script SUB pops TOS (10) then 2nd (3) and computes: 3 - 10 = -7."""
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=3)),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=10)),
            StackOp(op="opcode", code="OP_SUB"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1, (
            f"expected constant folding to produce 1 PUSH op, got {len(result)}: "
            f"{[op.op for op in result]}"
        )
        assert result[0].op == "push", f"expected push op, got: {result[0].op}"
        # In Bitcoin Script: a SUB b = second - top = 3 - 10 = -7
        assert result[0].value.big_int == -7, (
            f"expected PUSH(-7) for PUSH(3) PUSH(10) SUB (second - top = 3-10 = -7), "
            f"got: {result[0].value.big_int}"
        )


class TestIterativeConvergence:
    def test_multi_pass_optimization(self):
        """Optimizations that create new optimization opportunities converge."""
        # The 4-op chain folding rule matches PUSH 1, OP_ADD, PUSH 1, OP_ADD
        # and folds it to PUSH 2, OP_ADD (combining the two constants).
        # This is preferred over two separate OP_1ADD rewrites because the
        # 4-op window is checked before the 2-op window.
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1)),
            StackOp(op="opcode", code="OP_ADD"),
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1)),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 2
        assert result[0].op == "push"
        assert result[0].value.big_int == 2
        assert result[1].op == "opcode"
        assert result[1].code == "OP_ADD"

    def test_swap_swap_in_middle_of_sequence(self):
        """SWAP SWAP in the middle of a longer sequence is removed."""
        ops = [
            StackOp(op="opcode", code="OP_ADD"),
            StackOp(op="swap"),
            StackOp(op="swap"),
            StackOp(op="opcode", code="OP_SUB"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 2
        assert result[0].code == "OP_ADD"
        assert result[1].code == "OP_SUB"
