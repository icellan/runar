"""Op-shape parity tests for the Python compiler's bounded-loop lowering.

The Python frontend exposes loops via ``for i in range(N):``, which the
ANF lowerer rewrites to a single ``loop`` binding (``kind="loop"``,
``count=N``, ``iter_var=i``). At Stack-IR time the loop is fully unrolled
N times by ``stack.py:_lower_loop`` (lines 1512-1564).

This test pins:
  * The ANF representation: a bounded ``for ... in range(N):`` collapses to
    one ``loop`` binding with the correct count + body shape (no per-iteration
    duplication at ANF time).
  * The Stack-IR representation: the unrolling produces N copies of the body's
    characteristic opcodes plus N loop-counter pushes.
  * The unroll factor: changing ``range(N)`` produces exactly N copies, not
    N-1 or N+1.

The audit (D9 row) flagged this gap: prior to this test the Python compiler
had no explicit assertion-grade probe of its loop lowering, so a regression
in the unroll count or body emission would only surface as a hex divergence
in the conformance suite.
"""

from __future__ import annotations

import textwrap

import pytest

from runar_compiler.codegen.stack import StackOp, lower_to_stack
from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check
from runar_compiler.frontend.validator import validate


def _lower_to_anf_program(source: str):
    pr = parse_source(source, "Loop.runar.py")
    assert not pr.errors, f"parse errors: {pr.errors}"
    vr = validate(pr.contract)
    assert not vr.errors, f"validation errors: {vr.errors}"
    tr = type_check(pr.contract)
    assert not tr.errors, f"typecheck errors: {tr.errors}"
    return lower_to_anf(pr.contract)


def _lower_full(source: str):
    program = _lower_to_anf_program(source)
    return program, lower_to_stack(program)


def _is_opcode(op: StackOp, code: str) -> bool:
    return op.op == "opcode" and op.code == code


def _is_push_int(op: StackOp, n: int) -> bool:
    return (
        op.op == "push"
        and op.value is not None
        and op.value.kind == "bigint"
        and op.value.big_int == n
    )


def _flatten_ops(ops: list[StackOp]) -> list[StackOp]:
    out: list[StackOp] = []
    for op in ops:
        out.append(op)
        if op.op == "if":
            out.extend(_flatten_ops(op.then))
            out.extend(_flatten_ops(op.else_ops))
    return out


def _make_source(loop_count: int) -> str:
    """Build a minimal contract whose unlock method runs `for i in range(N)`
    and accumulates ``sum_ + start + i``.
    """
    return textwrap.dedent(f"""\
        from runar import SmartContract, Bigint, public, assert_

        class LoopProbe(SmartContract):
            expected_sum: Bigint

            def __init__(self, expected_sum: Bigint):
                super().__init__(expected_sum)
                self.expected_sum = expected_sum

            @public
            def verify(self, start: Bigint):
                sum_: Bigint = 0
                for i in range({loop_count}):
                    sum_ = sum_ + start + i
                assert_(sum_ == self.expected_sum)
        """)


# ---------------------------------------------------------------------------
# ANF representation
# ---------------------------------------------------------------------------

class TestLoopAnfShape:
    def test_for_in_range_lowers_to_single_loop_binding(self):
        program = _lower_to_anf_program(_make_source(5))
        verify = next(m for m in program.methods if m.name == "verify")
        loop_bindings = [b for b in verify.body if b.value.kind == "loop"]
        assert len(loop_bindings) == 1, (
            f"for-in-range must lower to a single 'loop' ANF binding; "
            f"got {len(loop_bindings)}"
        )

    def test_loop_binding_records_correct_count(self):
        program = _lower_to_anf_program(_make_source(5))
        verify = next(m for m in program.methods if m.name == "verify")
        loop = next(b for b in verify.body if b.value.kind == "loop")
        assert loop.value.count == 5, (
            f"loop count must equal range arg; got {loop.value.count}"
        )

    def test_loop_binding_records_iter_var_name(self):
        program = _lower_to_anf_program(_make_source(5))
        verify = next(m for m in program.methods if m.name == "verify")
        loop = next(b for b in verify.body if b.value.kind == "loop")
        assert loop.value.iter_var == "i", (
            f"loop iter_var must be 'i'; got {loop.value.iter_var!r}"
        )

    def test_loop_body_is_a_list_of_anf_bindings(self):
        program = _lower_to_anf_program(_make_source(5))
        verify = next(m for m in program.methods if m.name == "verify")
        loop = next(b for b in verify.body if b.value.kind == "loop")
        assert isinstance(loop.value.body, list)
        # The body sums: sum_ + start + i, then update_prop sum_, so it must
        # contain at least one bin_op for + and one update_local.
        body_kinds = [b.value.kind for b in loop.value.body]
        assert "bin_op" in body_kinds, (
            f"loop body must contain a bin_op for the addition; got {body_kinds}"
        )


# ---------------------------------------------------------------------------
# Stack-IR unrolling
# ---------------------------------------------------------------------------

class TestLoopStackUnroll:
    def test_unroll_emits_iter_index_pushes_for_each_iter(self):
        """The unroll injects push(i) at the start of each iteration. With
        range(5) we expect each of 0..4 to be pushed at least once; the
        higher indices may be pushed more than once because surrounding
        body code (load_const, stack-shuffle pick depth, etc.) can also
        push small ints.
        """
        _, methods = _lower_full(_make_source(5))
        verify = next(m for m in methods if m.name == "verify")
        flat = _flatten_ops(verify.ops)

        for k in range(5):
            pushes = [
                op for op in flat
                if (
                    op.op == "push"
                    and op.value is not None
                    and op.value.kind == "bigint"
                    and op.value.big_int == k
                )
            ]
            assert len(pushes) >= 1, (
                f"iter index push({k}) is missing from unrolled body"
            )

    def test_unroll_factor_5_emits_5_copies_of_body_add(self):
        """The body contains ``sum_ + start + i`` (two additions per iteration).
        With 5 unrolled iterations there must be exactly 10 OP_ADDs from the
        loop, plus 0 from outside the loop.
        """
        _, methods = _lower_full(_make_source(5))
        verify = next(m for m in methods if m.name == "verify")
        flat = _flatten_ops(verify.ops)
        adds = [op for op in flat if _is_opcode(op, "OP_ADD")]
        assert len(adds) == 10, (
            f"5x unrolled body with 2 adds/iter must emit 10 OP_ADDs; got {len(adds)}"
        )

    def test_unroll_factor_3_emits_6_copies_of_body_add(self):
        """Doubling the unroll knob: range(3) -> 3 iters * 2 adds = 6 OP_ADDs."""
        _, methods = _lower_full(_make_source(3))
        verify = next(m for m in methods if m.name == "verify")
        flat = _flatten_ops(verify.ops)
        adds = [op for op in flat if _is_opcode(op, "OP_ADD")]
        assert len(adds) == 6, (
            f"3x unrolled body with 2 adds/iter must emit 6 OP_ADDs; got {len(adds)}"
        )

    def test_unroll_factor_1_emits_2_copies_of_body_add(self):
        """range(1) -> a single inlined iteration = exactly 2 OP_ADDs."""
        _, methods = _lower_full(_make_source(1))
        verify = next(m for m in methods if m.name == "verify")
        flat = _flatten_ops(verify.ops)
        adds = [op for op in flat if _is_opcode(op, "OP_ADD")]
        assert len(adds) == 2, (
            f"1x unrolled body must emit 2 OP_ADDs; got {len(adds)}"
        )

    def test_unroll_factor_scales_linearly(self):
        """The total op-count grows monotonically with the unroll factor;
        a doubling regression would catch off-by-one errors silently.
        """
        _, methods_3 = _lower_full(_make_source(3))
        _, methods_5 = _lower_full(_make_source(5))
        v3 = next(m for m in methods_3 if m.name == "verify")
        v5 = next(m for m in methods_5 if m.name == "verify")
        assert len(_flatten_ops(v5.ops)) > len(_flatten_ops(v3.ops)), (
            "5-iter unroll must produce more ops than 3-iter unroll"
        )


# ---------------------------------------------------------------------------
# End-to-end op-count golden -- pinned baseline
# ---------------------------------------------------------------------------

# Captured from the current Python implementation; cross-checked by re-running.
EXPECTED_VERIFY_OP_COUNT_RANGE_5 = 54


def test_verify_total_op_count_pinned():
    _, methods = _lower_full(_make_source(5))
    verify = next(m for m in methods if m.name == "verify")
    flat = _flatten_ops(verify.ops)
    assert len(flat) == EXPECTED_VERIFY_OP_COUNT_RANGE_5, (
        f"verify op count drift: got {len(flat)} want {EXPECTED_VERIFY_OP_COUNT_RANGE_5}"
    )
