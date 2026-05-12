"""Byte-identical parity tests for the Python math builtin codegen.

Pins op count and the trailing/leading op-shape for every Rúnar math
builtin (E1–E16 in the language spec). The 16 builtins fall into two
groups:

* Mapped through ``BUILTIN_OPCODES`` in ``stack.py`` — ``abs``, ``min``,
  ``max``, ``within``, ``bool`` (these end in their characteristic
  opcode after stack-shuffling).
* Open-coded ``_lower_*`` helpers on ``StackContext`` —  ``safediv``,
  ``safemod``, ``clamp``, ``sign``, ``pow``, ``mulDiv``, ``percentOf``,
  ``sqrt``, ``gcd``, ``divmod``, ``log2``.

Each test drives ``lower_to_stack`` against a minimal ANF program of the
shape ``r = builtin(p0, p1, …); assert(r);`` and asserts on the exact
``StackOp`` sequence emitted for the unlock method. Goldens were captured
from this Python implementation and double-checked against ``pytest -q``;
any drift in a builtin's lowering will fail the matching per-builtin
test instead of surfacing only as a downstream conformance miss.

The lowering is exercised pre-peephole and pre-emit so that what we pin
here is the raw Stack-IR from ``stack_lower``, not whatever the
peephole optimizer happens to leave behind.
"""

from __future__ import annotations

from typing import Optional

import pytest

from runar_compiler.codegen.stack import (
    StackMethod,
    StackOp,
    lower_to_stack,
)
from runar_compiler.codegen.emit import emit_method
from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFParam,
    ANFProgram,
    ANFValue,
)


# ---------------------------------------------------------------------------
# Minimal ANF program builder
# ---------------------------------------------------------------------------

def _build_call_program(func_name: str, arity: int) -> ANFProgram:
    """Return an ANF program with a single ``unlock`` method of shape::

        r = func_name(p0, p1, …, p<arity-1>)
        assert(r)

    Each parameter is typed as ``bigint`` so the math builtins don't trip
    typecheck constraints (we go straight from ANF to stack-lowering, so
    the typecheck pass isn't actually executed; the field just keeps the
    ANF JSON faithful to what the frontend would produce).
    """
    body: list[ANFBinding] = []
    for i in range(arity):
        body.append(
            ANFBinding(
                name=f"a{i}",
                value=ANFValue(kind="load_param", name=f"p{i}"),
            )
        )
    body.append(
        ANFBinding(
            name="r",
            value=ANFValue(
                kind="call",
                func=func_name,
                args=[f"a{i}" for i in range(arity)],
            ),
        )
    )
    body.append(
        ANFBinding(
            name="_assert",
            value=ANFValue(kind="assert", value_ref="r"),
        )
    )
    method = ANFMethod(
        name="unlock",
        params=[ANFParam(name=f"p{i}", type="bigint") for i in range(arity)],
        body=body,
        is_public=True,
    )
    return ANFProgram(contract_name="MathProbe", properties=[], methods=[method])


def _unlock_ops(func_name: str, arity: int) -> list[StackOp]:
    program = _build_call_program(func_name, arity)
    methods = lower_to_stack(program)
    unlock = next(m for m in methods if m.name == "unlock")
    return unlock.ops


def _is_opcode(op: StackOp, code: str) -> bool:
    return op.op == "opcode" and op.code == code


def _is_push_int(op: StackOp, n: int) -> bool:
    return (
        op.op == "push"
        and op.value is not None
        and op.value.kind == "bigint"
        and op.value.big_int == n
    )


# ---------------------------------------------------------------------------
# Op-count goldens
# ---------------------------------------------------------------------------
#
# Counts captured from this Python implementation; cross-checked against
# the Java/Go reference at the same commit through the conformance suite.

_OP_COUNTS = [
    # name,       arity, expected_op_count
    ("abs",        1,    1),
    ("min",        2,    5),
    ("max",        2,    5),
    ("within",     3,    7),
    ("bool",       1,    1),
    ("safediv",    2,    8),
    ("safemod",    2,    8),
    ("clamp",      3,    8),
    ("sign",       1,    2),
    ("pow",        2,  168),
    ("mulDiv",     3,    8),
    ("percentOf",  2,    7),
    ("sqrt",       1,    2),
    ("gcd",        2,  777),
    ("divmod",     2,   10),
    ("log2",       1,  386),
]


@pytest.mark.parametrize("name,arity,expected", _OP_COUNTS)
def test_op_count(name: str, arity: int, expected: int) -> None:
    ops = _unlock_ops(name, arity)
    assert len(ops) == expected, (
        f"{name} op count drift: got {len(ops)} want {expected}"
    )


# ---------------------------------------------------------------------------
# Per-builtin op-shape goldens
# ---------------------------------------------------------------------------
#
# Each test pins the load-bearing tail (and where useful, the leading
# stack-shuffle prefix) so a wrong-opcode regression fails locally
# instead of surfacing only as a hex divergence in the conformance suite.

# -- BUILTIN_OPCODES table-driven lowerings ---------------------------------

def test_abs_emits_op_abs():
    ops = _unlock_ops("abs", 1)
    assert len(ops) == 1
    assert _is_opcode(ops[0], "OP_ABS")


def test_min_emits_op_min_after_shuffle():
    ops = _unlock_ops("min", 2)
    # Four stack-shuffle swaps then OP_MIN.
    for i in range(4):
        assert ops[i].op == "swap", f"min op[{i}] expected swap, got {ops[i].op}"
    assert _is_opcode(ops[4], "OP_MIN")


def test_max_emits_op_max_after_shuffle():
    ops = _unlock_ops("max", 2)
    for i in range(4):
        assert ops[i].op == "swap", f"max op[{i}] expected swap, got {ops[i].op}"
    assert _is_opcode(ops[4], "OP_MAX")


def test_within_emits_op_within_after_shuffle():
    ops = _unlock_ops("within", 3)
    for i in range(6):
        assert ops[i].op == "rot", f"within op[{i}] expected rot, got {ops[i].op}"
    assert _is_opcode(ops[6], "OP_WITHIN")


def test_bool_emits_op_0notequal():
    ops = _unlock_ops("bool", 1)
    assert len(ops) == 1
    assert _is_opcode(ops[0], "OP_0NOTEQUAL")


# -- safediv / safemod (open-coded with non-zero verify) -------------------

def test_safediv_verifies_divisor_then_divides():
    ops = _unlock_ops("safediv", 2)
    # Tail: DUP, 0NOTEQUAL, VERIFY, DIV.
    assert _is_opcode(ops[-4], "OP_DUP")
    assert _is_opcode(ops[-3], "OP_0NOTEQUAL")
    assert _is_opcode(ops[-2], "OP_VERIFY")
    assert _is_opcode(ops[-1], "OP_DIV")


def test_safemod_verifies_divisor_then_mods():
    ops = _unlock_ops("safemod", 2)
    # Tail: DUP, 0NOTEQUAL, VERIFY, MOD.
    assert _is_opcode(ops[-4], "OP_DUP")
    assert _is_opcode(ops[-3], "OP_0NOTEQUAL")
    assert _is_opcode(ops[-2], "OP_VERIFY")
    assert _is_opcode(ops[-1], "OP_MOD")


def test_safediv_and_safemod_share_prefix():
    """The non-zero divisor verification is identical for both."""
    div_ops = _unlock_ops("safediv", 2)
    mod_ops = _unlock_ops("safemod", 2)
    # All ops match except the final opcode (DIV vs MOD).
    assert len(div_ops) == len(mod_ops)
    for i in range(len(div_ops) - 1):
        assert div_ops[i].op == mod_ops[i].op
        assert div_ops[i].code == mod_ops[i].code


# -- clamp -----------------------------------------------------------------

def test_clamp_emits_max_then_min():
    ops = _unlock_ops("clamp", 3)
    # Tail: …, OP_MAX, swap, OP_MIN.
    assert _is_opcode(ops[-3], "OP_MAX")
    assert ops[-2].op == "swap"
    assert _is_opcode(ops[-1], "OP_MIN")


# -- sign ------------------------------------------------------------------

def test_sign_dispatches_through_if_branch():
    ops = _unlock_ops("sign", 1)
    assert _is_opcode(ops[0], "OP_DUP")
    assert ops[1].op == "if"
    # then-branch: DUP, ABS, swap, DIV (yields x/|x| ∈ {-1, +1}).
    then_ops = ops[1].then
    assert len(then_ops) == 4
    assert _is_opcode(then_ops[0], "OP_DUP")
    assert _is_opcode(then_ops[1], "OP_ABS")
    assert then_ops[2].op == "swap"
    assert _is_opcode(then_ops[3], "OP_DIV")


# -- pow -------------------------------------------------------------------

def test_pow_unrolls_32_iterations_with_nip_nip_tail():
    ops = _unlock_ops("pow", 2)
    # Trailing two ops are the result-extracting nips.
    assert ops[-1].op == "nip"
    assert ops[-2].op == "nip"

    # Each iteration emits 2-PICK + push(i) + GREATERTHAN + IF{over, MUL}.
    # That's 5 ops per iteration. Body span starts after the 5 leading
    # swaps + the first push(1) accumulator and the initial swap to put
    # base under exp (6 ops of preamble), and ends two ops before the end
    # (the two nips). Count the IF blocks to confirm 32 iterations.
    if_blocks = [op for op in ops if op.op == "if"]
    assert len(if_blocks) == 32, (
        f"pow expected 32 unrolled IF blocks, got {len(if_blocks)}"
    )
    # Each IF body must be exactly [over, OP_MUL].
    for blk in if_blocks:
        assert len(blk.then) == 2
        assert blk.then[0].op == "over"
        assert _is_opcode(blk.then[1], "OP_MUL")


# -- mulDiv ----------------------------------------------------------------

def test_mul_div_emits_mul_then_div():
    ops = _unlock_ops("mulDiv", 3)
    # Tail: …, OP_MUL, swap, OP_DIV.
    assert _is_opcode(ops[-3], "OP_MUL")
    assert ops[-2].op == "swap"
    assert _is_opcode(ops[-1], "OP_DIV")


# -- percentOf -------------------------------------------------------------

def test_percent_of_divides_by_10000_basis_points():
    ops = _unlock_ops("percentOf", 2)
    # Tail: …, OP_MUL, push(10000), OP_DIV.
    assert _is_opcode(ops[-3], "OP_MUL")
    assert _is_push_int(ops[-2], 10000), (
        "percentOf must divide by 10000 basis points"
    )
    assert _is_opcode(ops[-1], "OP_DIV")


# -- sqrt ------------------------------------------------------------------

def test_sqrt_runs_16_newton_iterations_under_if_guard():
    ops = _unlock_ops("sqrt", 1)
    assert _is_opcode(ops[0], "OP_DUP")
    assert ops[1].op == "if"

    then_ops = ops[1].then
    # 1 (DUP guess) + 16 × 6 (Newton step) + 1 (NIP) = 98.
    assert len(then_ops) == 98
    assert _is_opcode(then_ops[0], "OP_DUP")
    assert then_ops[-1].op == "nip"

    # Each Newton step: over, over, DIV, ADD, push(2), DIV.
    for i in range(16):
        base = 1 + i * 6
        assert then_ops[base + 0].op == "over"
        assert then_ops[base + 1].op == "over"
        assert _is_opcode(then_ops[base + 2], "OP_DIV")
        assert _is_opcode(then_ops[base + 3], "OP_ADD")
        assert _is_push_int(then_ops[base + 4], 2)
        assert _is_opcode(then_ops[base + 5], "OP_DIV")


# -- gcd -------------------------------------------------------------------

def test_gcd_unrolls_256_euclid_iterations_with_drop_tail():
    ops = _unlock_ops("gcd", 2)
    # Trailing op is drop (discards the now-zero second value).
    assert ops[-1].op == "drop"

    # 256 unrolled iterations, each emitting DUP + 0NOTEQUAL + IF{TUCK, MOD}.
    if_blocks = [op for op in ops if op.op == "if"]
    assert len(if_blocks) == 256, (
        f"gcd expected 256 unrolled IF blocks, got {len(if_blocks)}"
    )
    for blk in if_blocks:
        assert len(blk.then) == 2
        assert _is_opcode(blk.then[0], "OP_TUCK")
        assert _is_opcode(blk.then[1], "OP_MOD")


# -- divmod ----------------------------------------------------------------

def test_divmod_emits_2dup_div_rot_rot_mod_drop_tail():
    ops = _unlock_ops("divmod", 2)
    # Tail: 2DUP, DIV, ROT, ROT, MOD, drop.
    assert _is_opcode(ops[-6], "OP_2DUP")
    assert _is_opcode(ops[-5], "OP_DIV")
    assert _is_opcode(ops[-4], "OP_ROT")
    assert _is_opcode(ops[-3], "OP_ROT")
    assert _is_opcode(ops[-2], "OP_MOD")
    assert ops[-1].op == "drop"


# -- log2 ------------------------------------------------------------------

def test_log2_unrolls_64_iterations_under_if_guard():
    ops = _unlock_ops("log2", 1)
    # Counter pushed first.
    assert _is_push_int(ops[0], 0)
    # Trailing nip drops the consumed input, keeping the counter.
    assert ops[-1].op == "nip"

    if_blocks = [op for op in ops if op.op == "if"]
    assert len(if_blocks) == 64, (
        f"log2 expected 64 unrolled IF blocks, got {len(if_blocks)}"
    )
    # Each IF body: push(2), DIV, swap, OP_1ADD, swap.
    for blk in if_blocks:
        assert len(blk.then) == 5
        assert _is_push_int(blk.then[0], 2)
        assert _is_opcode(blk.then[1], "OP_DIV")
        assert blk.then[2].op == "swap"
        assert _is_opcode(blk.then[3], "OP_1ADD")
        assert blk.then[4].op == "swap"


# ---------------------------------------------------------------------------
# Determinism — same input must produce byte-identical ops.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,arity,_", _OP_COUNTS)
def test_lowering_is_deterministic(name: str, arity: int, _: int) -> None:
    a = _unlock_ops(name, arity)
    b = _unlock_ops(name, arity)
    assert len(a) == len(b)
    for i, (x, y) in enumerate(zip(a, b)):
        assert x.op == y.op, f"{name} op[{i}] kind drifts"
        assert x.code == y.code, f"{name} op[{i}] code drifts"


# ---------------------------------------------------------------------------
# End-to-end: every builtin must round-trip through the public emit API
# without raising and produce non-empty hex.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,arity,_", _OP_COUNTS)
def test_builtin_emits_to_hex(name: str, arity: int, _: int) -> None:
    ops = _unlock_ops(name, arity)
    method = StackMethod(name="unlock", ops=list(ops), max_stack_depth=0)
    res = emit_method(method)
    assert res.script_hex, f"{name} produced empty script hex"
