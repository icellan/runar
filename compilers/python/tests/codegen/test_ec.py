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



def _count_op_tree(ops: list[StackOp]) -> int:
    """Total StackOps in ``ops``, INCLUDING the bodies of ``if`` ops.

    A flat ``len(ops)`` cannot see inside a branch, so any emitter whose work
    sits in an ``if`` body -- the scalar ladders emit 257 / 385 conditional
    additions, WOTS+ and SLH-DSA are almost entirely conditional -- reports a
    count that barely moves no matter what the branch contains. Adding +1.3 KB
    of script inside the ladder's last step left the ``p256Mul`` / ``p384Mul``
    goldens byte-identical. Recursing is what makes the golden a gate.
    """
    total = 0
    for op in ops:
        total += 1
        if op.op == "if":
            total += _count_op_tree(op.then)
            total += _count_op_tree(op.else_ops)
    return total


# ---------------------------------------------------------------------------
# Op-count goldens (matched against Java/Go reference at the same commit).
# Counts are op-TREE sizes: ``if`` bodies included, see ``_count_op_tree``.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,fn,expected", [
    # R-052 / CL-BUG-095, the Point WIDTH gate. A ``Point`` is 64 bytes by
    # definition and nothing checked it, so a surplus byte was split off and
    # silently dropped: ``ecOnCurve(G || 0xff)`` returned TRUE and
    # ``ecEncodeCompressed`` took its parity bit from the caller's extra byte.
    # The deltas below are all structural, which is what makes them portable to
    # the six other tiers byte-for-byte:
    #
    #   +3  per _ec_decompose_point call site -- OP_SIZE, push 64,
    #       OP_NUMEQUALVERIFY. ecAdd decomposes TWICE, hence +6; ecMul /
    #       ecMulGen / ecNegate once.
    #   +15 ecOnCurve -- 9 for the clamp-and-flag gate (it must stay a PREDICATE
    #       and answer ``false``, not abort, or ``if (ecOnCurve(p))`` stops
    #       being writable), +3 for the decompose gate, +1 for the extra
    #       OP_BOOLAND folding ``_len_ok`` in, +2 for rolling the two flags up.
    #   +3  ecPointX / ecPointY.
    #
    # ecEncodeCompressed stays at 16 and that is NOT an oversight: the gate adds
    # 3 ops while the fixed-offset parity read (push 31, OP_SPLIT, OP_NIP)
    # replaces a 6-op OP_SIZE/OP_SUB/OP_SPLIT/swap/drop sequence with 3. Net
    # zero ops, different bytes.
    #
    # R-053 / CL-BUG-096, the infinity-operand case of the affine adder:
    # +50 to ``ecAdd`` alone (emit_affine_infinity_select -- the pinf/qinf
    # zero tests, the usep/useq/user masks and the two three-way selects,
    # minus the four drops and two notinf OP_MULs it replaced). Nothing else
    # moves: the Jacobian ladders behind ecMul/ecMulGen never call the affine
    # adder, and ecOnCurve still rejects the all-zero point.
    # R-117, the COORDINATE-CANONICITY gate. ecAdd 8279 -> 8297 (+18), ecMul
    # 130518 -> 131073 (+8), ecMulGen +8, ecNegate 948 -> 956 (+8). emitCoordCanonVerify
    # is 8 ops per gated point -- copy x (pick), push p, OP_LESSTHAN, copy y (pick),
    # push p, OP_LESSTHAN, OP_BOOLAND, OP_VERIFY -- and ecAdd gates TWO points, so
    # +18 there rather than +16. The extra two are pick DEPTH, not extra work: this
    # tracker emits OP_DUP / OP_OVER for depth 0 / 1 and `push <n>, OP_PICK` for
    # anything deeper, and in ecAdd's FIRST gate the stack is [px, py, qx, qy], so
    # both of that gate's picks reach depth 3 and cost two ops each. Its second gate
    # sees [px, py, qx, qy] with qx / qy at depth 1, so both are a one-op OP_OVER.
    # 10 + 8 = 18, and ecMul / ecNegate gate a single point off a two-deep stack for
    # a flat 8. ecOnCurve / ecModReduce /
    # ecEncodeCompressed / ecMakePoint / ecPointX / ecPointY are all +0. The
    # predicates must stay TOTAL (they clamp and flag, they do not abort), and the
    # byte accessors have no selector to fool -- each returns a value derived
    # injectively from the bytes, so a non-canonical coordinate yields a DIFFERENT
    # number rather than a colliding one.
    ("ecAdd",              emit_ec_add,               8297),
    # R-157, the ecMul ON-CURVE-OR-INFINITY gate: ecMul 130526 -> 131073 (+547),
    # ecMulGen +547. The gate is the whole ecOnCurve body plus a copy/compare against
    # the all-zero blob and an OP_BOOLOR/OP_VERIFY, run once before the ladder. ecAdd
    # / ecNegate / ecOnCurve / ecMakePoint / ecPointX / ecPointY are all +0 — this
    # gate is on the SCALAR LADDER only, because it is the +3n construction inside
    # ecMul whose soundness needs ord(P) | n. affineAdd has no n-dependent trick and
    # is correct on whatever curve its operand lies on, so gating it would cost bytes
    # and break ecAdd(P, O), which R-053 requires.
    # ecMulGen pays the gate too even though its operand is the compiler-pushed
    # generator: it is emitted as `push G; swap; ecMul`, and exempting it would mean a
    # second ecMul spelling whose only difference is a check that can never fail.
    ("ecMul",              emit_ec_mul,             131073),
    ("ecMulGen",           emit_ec_mul_gen,         131075),
    ("ecNegate",           emit_ec_negate,             956),
    ("ecOnCurve",          emit_ec_on_curve,           548),
    ("ecModReduce",        emit_ec_mod_reduce,           8),
    ("ecEncodeCompressed", emit_ec_encode_compressed,   16),
    # R-156, the ecMakePoint FIELD-ELEMENT gate: 467 -> 477 (+10). Five ops per
    # coordinate -- OP_DUP, OP_0, push p, OP_WITHIN, OP_VERIFY -- and ecMakePoint has
    # two. Nothing else moves: this gate is on the two BIGINT arguments of the point
    # CONSTRUCTOR, which is a different surface from R-117's gate on the coordinates
    # of an existing Point. ecMakePoint is secp256k1-only; there is no p256MakePoint
    # or p384MakePoint to move.
    ("ecMakePoint",        emit_ec_make_point,         477),
    ("ecPointX",           emit_ec_point_x,            236),
    ("ecPointY",           emit_ec_point_y,            237),
])
def test_op_count(name, fn, expected):
    ops: list[StackOp] = []
    fn(ops.append)
    got = _count_op_tree(ops)
    assert got == expected, f"{name} op count drift: got {got} want {expected}"


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
