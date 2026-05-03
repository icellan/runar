"""Byte-identical parity tests for the Python ``sha256`` codegen against
the same goldens used by the Java reference (``Sha256Test``).

These tests pin op counts and the leading op-shape so any drift in the
Python emitter is caught immediately. Goldens were captured from the
Python reference and cross-checked against Java/Go.
"""

from __future__ import annotations

import pytest

from runar_compiler.codegen.sha256 import (
    emit_sha256_compress,
    emit_sha256_finalize,
)
from runar_compiler.codegen.stack import StackMethod, StackOp
from runar_compiler.codegen.emit import emit_method


# ---------------------------------------------------------------------------
# Op-count goldens
# ---------------------------------------------------------------------------

def test_compress_op_count():
    ops: list[StackOp] = []
    emit_sha256_compress(ops.append)
    # Matches the Python/Go/Java reference counts on the same commit.
    assert len(ops) == 21292


def test_finalize_op_count():
    ops: list[StackOp] = []
    emit_sha256_finalize(ops.append)
    assert len(ops) == 63941


# ---------------------------------------------------------------------------
# Op-shape goldens
# ---------------------------------------------------------------------------

def test_compress_starts_with_swap_dup_toaltstack_x2():
    ops: list[StackOp] = []
    emit_sha256_compress(ops.append)
    assert ops[0].op == "swap"
    assert ops[1].op == "dup"
    assert ops[2].op == "opcode" and ops[2].code == "OP_TOALTSTACK"
    assert ops[3].op == "opcode" and ops[3].code == "OP_TOALTSTACK"

    # Then 15 × (push 4, OP_SPLIT) to unpack the 64-byte block into 16 words.
    for i in range(4, 34, 2):
        push = ops[i]
        split = ops[i + 1]
        assert push.op == "push", f"op[{i}] must be push"
        assert push.value is not None
        assert push.value.kind == "bigint"
        assert push.value.big_int == 4
        assert split.op == "opcode" and split.code == "OP_SPLIT"


def test_finalize_starts_with_push9_num2bin_push8_split():
    ops: list[StackOp] = []
    emit_sha256_finalize(ops.append)
    assert ops[0].op == "push"
    assert ops[0].value is not None and ops[0].value.big_int == 9
    assert ops[1].op == "opcode" and ops[1].code == "OP_NUM2BIN"
    assert ops[2].op == "push"
    assert ops[2].value is not None and ops[2].value.big_int == 8


# ---------------------------------------------------------------------------
# End-to-end emit through the public Emit API
# ---------------------------------------------------------------------------

def test_compress_emits_to_hex_with_known_prefix():
    ops: list[StackOp] = []
    emit_sha256_compress(ops.append)
    method = StackMethod(name="run", ops=ops, max_stack_depth=0)
    res = emit_method(method)
    assert res.script_hex
    # First 4 bytes (SWAP, DUP, OP_TOALTSTACK, OP_TOALTSTACK) = 7c 76 6b 6b.
    assert res.script_hex[:8] == "7c766b6b"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_emitter_is_deterministic():
    a: list[StackOp] = []
    b: list[StackOp] = []
    emit_sha256_compress(a.append)
    emit_sha256_compress(b.append)
    assert len(a) == len(b)
    for i, (x, y) in enumerate(zip(a, b)):
        assert x.op == y.op, f"op[{i}] kind drifts"
        assert x.code == y.code, f"op[{i}] code drifts"
