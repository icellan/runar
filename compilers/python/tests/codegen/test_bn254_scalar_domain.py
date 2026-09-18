"""Cross-tier pin for the ``bn254G1ScalarMul`` ladder.

``bn254G1ScalarMul`` is a contract-callable builtin in every tier (see
``frontend/typecheck.py``), and until this pin existed nothing outside the Go
tier had ever compared its emitted script against the reference. What the
comparison found: the scalar was never reduced mod r.

The ladder builds k' = k + 3r, seeds the accumulator at bit 255 rather than
stepping it, and iterates bits 254..0. That is sound ONLY while
2^255 <= k' < 2^256, i.e. while 2^255 - 3r <= k < 2^256 - 3r (about -0.3549*r
to 2.2902*r). Outside that window the ladder does not fail -- it applies the
multiplier 2^255 + ((k + 3r) mod 2^255), which is not congruent to k mod r.

Reducing also makes k = 0 mod r reachable, and there the final ladder step is
handed accumulator == -base. The mixed-add's H == 0 test cannot tell -base
from +base, so the last step additionally needs R == 0 (``strict``) or it
returns -2P where the answer is the point at infinity. Both halves are pinned
here.
"""

from __future__ import annotations

import hashlib

from runar_compiler.codegen.bn254 import emit_bn254_g1_scalar_mul
from runar_compiler.codegen.emit import emit_method
from runar_compiler.codegen.stack import StackMethod

# SHA-256 of the hex string of the raw (pre-peephole) ladder, taken from the Go
# reference compiler (codegen.EmitBN254G1ScalarMul -> codegen.Emit) and
# independently reproduced by the TypeScript tier. 42_910 ops, 134_245 bytes.
# R-141 moved it again: bn254G1ScalarMul now gates its base point's coordinates
# and inherits the OP_SIZE-64 verify that the decomposer gained, because the
# predicate used to certify (x+p) || y and a 65-byte blob as points.
# 42_910 ops / 134_245 bytes -> 42_921 ops / 134_321 bytes; the new digest was
# produced by Go and independently reproduced, byte for byte, by the
# TypeScript, Python and Ruby tiers before it was written down here.
BN254_SCALAR_MUL_SHA256 = (
    "a80bb1910366d399b7d6a6a35f7c8b51678d3655bf6008a6744b57aa2bded02c"
)

# r, spelled out so this file compares against the reference rather than
# against whatever the module currently believes.
BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def _ladder_ops() -> list:
    ops: list = []
    emit_bn254_g1_scalar_mul(ops.append)
    return ops


def _op_name(op) -> str:
    kind = getattr(op, "op", None)
    if kind == "opcode":
        return getattr(op, "code", "")
    if kind in ("rot", "drop", "over", "swap"):
        return "OP_" + kind.upper()
    if kind == "push":
        value = getattr(op, "value", None)
        if getattr(value, "kind", None) == "bigint" and getattr(value, "big_int", None) == BN254_R:
            return "PUSH_R"
    return "_"


def test_scalar_mul_matches_the_cross_tier_pin():
    ops = _ladder_ops()
    script_hex = emit_method(StackMethod(name="t", ops=ops)).script_hex
    digest = hashlib.sha256(script_hex.encode()).hexdigest()
    assert digest == BN254_SCALAR_MUL_SHA256, (
        "bn254G1ScalarMul diverged from the six-tier reference ladder "
        f"({len(script_hex) // 2} bytes emitted)"
    )


def test_scalar_is_reduced_mod_r_before_the_ladder():
    """((k mod r) + r) mod r, emitted exactly once, before the +3r offset.

    OP_MOD takes the sign of the DIVIDEND, so ``k mod r`` alone lands in
    (-r, r); the ``+ r, mod r`` normalises the negative half.
    """
    names = [_op_name(op) for op in _ladder_ops()]
    want = [
        "PUSH_R", "OP_2DUP", "OP_MOD", "OP_ROT", "OP_DROP",
        "OP_OVER", "OP_ADD", "OP_SWAP", "OP_MOD",
    ]
    hits = sum(
        1 for i in range(len(names) - len(want) + 1)
        if names[i:i + len(want)] == want
    )
    assert hits == 1, f"expected exactly one mod-r scalar reduce, found {hits}"


def test_only_the_last_ladder_step_is_strict():
    """The extra R == 0 test is paid at the final step and nowhere else.

    It costs two field multiplications plus an OP_BOOLAND (+23 bytes) at one
    step; paying it at all 255 would be ~5.8 KB spent re-deciding a branch that
    provably cannot fire earlier.
    """
    branches = [op.then for op in _ladder_ops() if getattr(op, "op", None) == "if"]
    assert len(branches) == 255, f"expected 255 conditional additions, got {len(branches)}"

    def boolands(ops) -> int:
        return sum(
            1 for o in ops
            if getattr(o, "op", None) == "opcode" and getattr(o, "code", "") == "OP_BOOLAND"
        )

    assert boolands(branches[254]) == boolands(branches[253]) + 1, (
        "the final step must combine H == 0 with R == 0"
    )
    for i, b in enumerate(branches[:254]):
        assert boolands(b) == boolands(branches[0]), f"step {i} must not pay the strict test"
