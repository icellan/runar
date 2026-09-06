"""Byte-identical parity tests for the Python ``slh_dsa`` codegen against
the same goldens used by the Java reference (``SlhDsaTest``).

Pins op counts for every FIPS 205 SLH-DSA-SHA2 parameter set the compiler
supports.
"""

from __future__ import annotations

import pytest

from runar_compiler.codegen.slh_dsa import emit_verify_slh_dsa, SLH_PARAMS
from runar_compiler.codegen.stack import StackOp


def _count_op_tree(ops: list[StackOp]) -> int:
    """Total StackOps in ``ops``, INCLUDING the bodies of ``if`` ops.

    A flat ``len(ops)`` cannot see inside a branch, and SLH-DSA verification is
    almost entirely conditional: 85,765 top-level ops for SHA2-128f hide
    514,147 in total. A golden over the flat count barely moves no matter what
    the branches contain. Recursing is what makes the golden a gate.
    """
    total = 0
    for op in ops:
        total += 1
        if op.op == "if":
            total += _count_op_tree(op.then)
            total += _count_op_tree(op.else_ops)
    return total



SUPPORTED_KEYS = [
    "SHA2_128s", "SHA2_128f",
    "SHA2_192s", "SHA2_192f",
    "SHA2_256s", "SHA2_256f",
]


# ---------------------------------------------------------------------------
# Op counts (golden values captured from the Python reference).
# Op-TREE sizes: `if` bodies included, see `_count_op_tree`.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key,expected", [
    # BUG-011: each verifySLHDSA_* prologue now emits an OP_SIZE exact-length
    # guard (5 additional ops per parameter set) before the existing FORS /
    # Merkle path expansion.
    #
    # SLH-DSA Hmsg/FORS codegen fix: (1) the Hmsg MGF1 last-block reversal drops
    # one OP_SWAP for every digest spanning >1 SHA-256 block (all sets except
    # 128s), and (2) the FORS index extraction now reads a 3-byte window when an
    # a-bit field straddles it (a=14 sets 192s/256s), adding ops there. New
    # counts match byte-for-byte against the regenerated goldens.
    #
    # #137 (FIPS-205 conformance) then added, per parameter set, exactly 6 + d:
    #   +6 once, in Hmsg -- the MGF1 seed must be prefixed with R || PK.seed
    #     (FIPS 205 Sec 11.2.1): 2 extra copy_to_top (2 ops each) + 2 OP_CAT.
    #   +1 per hypertree layer (d layers) -- wots_pkFromSig must restore the key
    #     pair address after set_type(WOTS_PK) (FIPS 205 Alg. 8 lines 8-11),
    #     turning a 1-op 4-zero-byte push into a 2-op push-depth + PICK.
    # d = 7, 22, 7, 22, 8, 17 for 128s, 128f, 192s, 192f, 256s, 256f.
    ("SHA2_128s", 179259),
    ("SHA2_128f", 514175),
    ("SHA2_192s", 256948),
    ("SHA2_192f", 741052),
    ("SHA2_256s", 350411),
    ("SHA2_256f", 699576),
])
def test_op_count(key, expected):
    ops: list[StackOp] = []
    emit_verify_slh_dsa(ops.append, key)
    got = _count_op_tree(ops)
    assert got == expected, (
        f"SLH-DSA-{key} op count drift: got {got} want {expected}"
    )


# ---------------------------------------------------------------------------
# All supported parameter sets must produce a non-empty op stream.
# ---------------------------------------------------------------------------

def test_all_param_keys_produce_ops():
    for key in SUPPORTED_KEYS:
        ops: list[StackOp] = []
        emit_verify_slh_dsa(ops.append, key)
        assert ops, f"no ops emitted for {key}"


# ---------------------------------------------------------------------------
# Distinct variants must produce distinct op streams.
# ---------------------------------------------------------------------------

def test_128s_and_128f_diverge():
    s_ops: list[StackOp] = []
    f_ops: list[StackOp] = []
    emit_verify_slh_dsa(s_ops.append, "SHA2_128s")
    emit_verify_slh_dsa(f_ops.append, "SHA2_128f")
    assert len(s_ops) != len(f_ops), (
        "SHA2_128s and SHA2_128f produced the same op count -- variants confused"
    )
    # 128f has wider chains -- substantially larger.
    assert len(f_ops) > len(s_ops)


# ---------------------------------------------------------------------------
# Unknown parameter keys are rejected.
# ---------------------------------------------------------------------------

def test_unknown_param_key_raises():
    with pytest.raises(RuntimeError):
        emit_verify_slh_dsa(lambda op: None, "BLAKE_2_42")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_emitter_is_deterministic():
    a: list[StackOp] = []
    b: list[StackOp] = []
    emit_verify_slh_dsa(a.append, "SHA2_128s")
    emit_verify_slh_dsa(b.append, "SHA2_128s")
    assert len(a) == len(b)
    for i, (x, y) in enumerate(zip(a, b)):
        assert x.op == y.op, f"op[{i}] kind drifts"
        assert x.code == y.code, f"op[{i}] code drifts"


# ---------------------------------------------------------------------------
# SLH_PARAMS table contains all six supported variants.
# ---------------------------------------------------------------------------

def test_slh_params_table_is_complete():
    for key in SUPPORTED_KEYS:
        assert key in SLH_PARAMS, f"missing SLH params: {key}"
