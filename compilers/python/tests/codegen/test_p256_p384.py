"""Byte-identical parity tests for the Python ``p256_p384`` codegen
against the same goldens used by the Java reference (``P256P384Test``).

Pins op counts for every NIST P-256 and P-384 builtin.
"""

from __future__ import annotations

import pytest

from runar_compiler.codegen.p256_p384 import (
    emit_p256_add, emit_p256_mul, emit_p256_mul_gen, emit_p256_negate,
    emit_p256_on_curve, emit_p256_encode_compressed, emit_verify_ecdsa_p256,
    emit_p384_add, emit_p384_mul, emit_p384_mul_gen, emit_p384_negate,
    emit_p384_on_curve, emit_p384_encode_compressed, emit_verify_ecdsa_p384,
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
# P-256 op-count goldens (op-TREE sizes: `if` bodies included)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,fn,expected", [
    # R-052 / CL-BUG-095 -- the Point WIDTH gate. A P256Point is 64 bytes and a
    # P384Point is 96, by definition, and NOTHING checked either, so
    # ``p256OnCurve(G || 0xff)`` returned TRUE and ``pNNNEncodeCompressed`` took
    # its parity bit from the caller's appended byte. Every delta is curve-
    # INDEPENDENT, which is what makes it a structural gate rather than a
    # per-bit loop -- the two curves pay exactly the same:
    #
    #   pNNNAdd               +6  -- two _c_decompose_point call sites, 3 ops
    #                                each (OP_SIZE, push 2*coord_bytes,
    #                                OP_NUMEQUALVERIFY).
    #   pNNNMul/MulGen/Negate +3  -- one call site.
    #   pNNNOnCurve          +15  -- 9 for the clamp-and-flag gate, 3 for the
    #                                decompose gate, 1 for the OP_BOOLAND
    #                                folding ``_len_ok`` into the verdict, 2 for
    #                                the rolls. It CLAMPS rather than aborts
    #                                because it is the predicate contracts gate
    #                                untrusted points on; ``false`` is the right
    #                                answer.
    #   verifyECDSA_PNNN     +12  -- four internal _c_decompose_point sites.
    #
    # pNNNEncodeCompressed stays at 16: +3 for the gate, -3 because the fixed-
    # offset parity read (push coord_bytes-1, OP_SPLIT, OP_NIP) replaces a 6-op
    # OP_SIZE/push/OP_SUB/OP_SPLIT/swap/drop sequence. Net zero ops, different
    # bytes.
    #
    # R-053 / CL-BUG-096 -- the infinity-operand case of the affine adder,
    # shared verbatim with secp256k1 because it is pure integer masking with no
    # field parameter. Curve-independent again:
    #
    #   pNNNAdd           +50  -- emit_affine_infinity_select replaces the four
    #                             drops and the two `notinf` OP_MULs.
    #   verifyECDSA_PNNN  +50  -- it calls _c_affine_add exactly once.
    #
    # pNNNMul / pNNNMulGen / pNNNOnCurve / pNNNNegate move by 0: the ladders run
    # in Jacobian coordinates and never reach the affine adder.
    ("p256Add",              emit_p256_add,               6719),
    ("p256Mul",              emit_p256_mul,             140039),
    ("p256MulGen",           emit_p256_mul_gen,         140041),
    ("p256Negate",           emit_p256_negate,             948),
    ("p256OnCurve",          emit_p256_on_curve,           574),
    ("p256EncodeCompressed", emit_p256_encode_compressed,   16),
    # 297273 -> 297331 (+58): the ECDSA verifier gained its argument-validation
    # gates -- two length gates on `_sig` / `_pk`, the 1 <= r,s <= n-1 range
    # gate, the SEC1 prefix-byte check inside decompression, and the ANDs that
    # fold all of it into one `_input_ok` flag.
    ("verifyECDSA_P256",     emit_verify_ecdsa_p256,    297393),
])
def test_p256_op_count(name, fn, expected):
    ops: list[StackOp] = []
    fn(ops.append)
    got = _count_op_tree(ops)
    assert got == expected, f"{name} op count drift: got {got} want {expected}"


# ---------------------------------------------------------------------------
# P-384 op-count goldens (op-TREE sizes: `if` bodies included)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,fn,expected", [
    ("p384Add",              emit_p384_add,              11525),
    ("p384Mul",              emit_p384_mul,             211181),
    ("p384MulGen",           emit_p384_mul_gen,         211183),
    ("p384Negate",           emit_p384_negate,            1396),
    # p384OnCurve / p384EncodeCompressed / verifyECDSA_P384 were missing from
    # this list while their P-256 peers were pinned, so the P-384 half of the
    # R-052 width gate had no golden at all. Same numbers the TS tier pins.
    ("p384OnCurve",          emit_p384_on_curve,           798),
    ("p384EncodeCompressed", emit_p384_encode_compressed,   16),
    ("verifyECDSA_P384",     emit_verify_ecdsa_p384,    453369),
])
def test_p384_op_count(name, fn, expected):
    ops: list[StackOp] = []
    fn(ops.append)
    got = _count_op_tree(ops)
    assert got == expected, f"{name} op count drift: got {got} want {expected}"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_p256_add_is_deterministic():
    a: list[StackOp] = []
    b: list[StackOp] = []
    emit_p256_add(a.append)
    emit_p256_add(b.append)
    assert len(a) == len(b)
    for i, (x, y) in enumerate(zip(a, b)):
        assert x.op == y.op
        assert x.code == y.code
