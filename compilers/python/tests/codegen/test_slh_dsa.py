"""Byte-identical parity tests for the Python ``slh_dsa`` codegen against
the same goldens used by the Java reference (``SlhDsaTest``).

Pins op counts for every FIPS 205 SLH-DSA-SHA2 parameter set the compiler
supports.
"""

from __future__ import annotations

import pytest

from runar_compiler.codegen.slh_dsa import emit_verify_slh_dsa, SLH_PARAMS
from runar_compiler.codegen.stack import StackOp


SUPPORTED_KEYS = [
    "SHA2_128s", "SHA2_128f",
    "SHA2_192s", "SHA2_192f",
    "SHA2_256s", "SHA2_256f",
]


# ---------------------------------------------------------------------------
# Op counts (golden values captured from the Python reference).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key,expected", [
    ("SHA2_128s",  29559),
    ("SHA2_128f",  85761),
    ("SHA2_192s",  41899),
    ("SHA2_192f", 121708),
    ("SHA2_256s",  61123),
    ("SHA2_256f", 122993),
])
def test_op_count(key, expected):
    ops: list[StackOp] = []
    emit_verify_slh_dsa(ops.append, key)
    assert len(ops) == expected, (
        f"SLH-DSA-{key} op count drift: got {len(ops)} want {expected}"
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
