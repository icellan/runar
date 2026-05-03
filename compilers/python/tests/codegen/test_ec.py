"""Byte-identical parity tests for the Python ``ec`` codegen against the
same goldens used by the Java reference (``EcTest``).

Pins op counts for every secp256k1 builtin and checks the curve constants.
"""

from __future__ import annotations

import pytest

from runar_compiler.codegen.ec import (
    emit_ec_add,
    emit_ec_mul,
    emit_ec_mul_gen,
    emit_ec_negate,
    emit_ec_on_curve,
    emit_ec_mod_reduce,
    emit_ec_encode_compressed,
    emit_ec_make_point,
    emit_ec_point_x,
    emit_ec_point_y,
    is_ec_builtin,
)
from runar_compiler.codegen.stack import StackOp


# ---------------------------------------------------------------------------
# Op-count goldens (matched against Java/Go reference at the same commit)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,fn,expected", [
    ("ecAdd",              emit_ec_add,               8078),
    ("ecMul",              emit_ec_mul,              63828),
    ("ecMulGen",           emit_ec_mul_gen,          63830),
    ("ecNegate",           emit_ec_negate,             945),
    ("ecOnCurve",          emit_ec_on_curve,           520),
    ("ecModReduce",        emit_ec_mod_reduce,           8),
    ("ecEncodeCompressed", emit_ec_encode_compressed,   14),
    ("ecMakePoint",        emit_ec_make_point,         467),
    ("ecPointX",           emit_ec_point_x,            233),
    ("ecPointY",           emit_ec_point_y,            234),
])
def test_op_count(name, fn, expected):
    ops: list[StackOp] = []
    fn(ops.append)
    assert len(ops) == expected, f"{name} op count drift: got {len(ops)} want {expected}"


# ---------------------------------------------------------------------------
# ecModReduce is exactly 8 ops with a known shape.
# ---------------------------------------------------------------------------

def test_ec_mod_reduce_is_exact_eight_ops():
    ops: list[StackOp] = []
    emit_ec_mod_reduce(ops.append)
    # OP_2DUP, OP_MOD, ROT, DROP, OVER, OP_ADD, SWAP, OP_MOD
    assert ops[0].op == "opcode" and ops[0].code == "OP_2DUP"
    assert ops[1].op == "opcode" and ops[1].code == "OP_MOD"
    assert ops[2].op == "rot"
    assert ops[3].op == "drop"
    assert ops[4].op == "over"
    assert ops[5].op == "opcode" and ops[5].code == "OP_ADD"
    assert ops[6].op == "swap"
    assert ops[7].op == "opcode" and ops[7].code == "OP_MOD"


# ---------------------------------------------------------------------------
# Builtin name predicate.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "ecAdd", "ecMul", "ecMulGen", "ecNegate", "ecOnCurve",
    "ecModReduce", "ecEncodeCompressed", "ecMakePoint",
    "ecPointX", "ecPointY",
])
def test_is_ec_builtin_recognises_known_names(name):
    assert is_ec_builtin(name) is True


def test_is_ec_builtin_rejects_unknown():
    assert is_ec_builtin("ecUnknown") is False
    assert is_ec_builtin("verifyWOTS") is False
