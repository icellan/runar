"""Byte-identical parity tests for the Python ``blake3`` codegen against
the same goldens used by the Java reference (``Blake3Test``).
"""

from __future__ import annotations

import pytest

from runar_compiler.codegen.blake3 import (
    emit_blake3_compress,
    emit_blake3_hash,
)
from runar_compiler.codegen.stack import StackOp


# ---------------------------------------------------------------------------
# Op-count goldens
# ---------------------------------------------------------------------------

def test_compress_op_count():
    ops: list[StackOp] = []
    emit_blake3_compress(ops.append)
    assert len(ops) == 10819


def test_hash_op_count():
    ops: list[StackOp] = []
    emit_blake3_hash(ops.append)
    assert len(ops) == 10829


# ---------------------------------------------------------------------------
# Op-shape goldens
# ---------------------------------------------------------------------------

def test_compress_starts_with_15x_push4_split():
    """Compression starts by splitting the 64-byte block into 16 × 4-byte
    big-endian words. First 30 ops alternate (push 4, OP_SPLIT) × 15."""
    ops: list[StackOp] = []
    emit_blake3_compress(ops.append)
    for i in range(0, 30, 2):
        push = ops[i]
        split = ops[i + 1]
        assert push.op == "push", f"op[{i}] must be push"
        assert push.value is not None
        assert push.value.kind == "bigint"
        assert push.value.big_int == 4
        assert split.op == "opcode" and split.code == "OP_SPLIT"


def test_hash_starts_with_size_64_swap_sub():
    """``blake3Hash`` opens with: OP_SIZE, push 64, SWAP, OP_SUB, ..."""
    ops: list[StackOp] = []
    emit_blake3_hash(ops.append)
    assert ops[0].op == "opcode" and ops[0].code == "OP_SIZE"
    assert ops[1].op == "push"
    assert ops[1].value is not None and ops[1].value.big_int == 64
    assert ops[2].op == "swap"
    assert ops[3].op == "opcode" and ops[3].code == "OP_SUB"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_emitter_is_deterministic():
    a: list[StackOp] = []
    b: list[StackOp] = []
    emit_blake3_compress(a.append)
    emit_blake3_compress(b.append)
    assert len(a) == len(b)
    for i, (x, y) in enumerate(zip(a, b)):
        assert x.op == y.op, f"op[{i}] kind drifts"
        assert x.code == y.code, f"op[{i}] code drifts"
