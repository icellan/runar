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
    assert len(ops) == 21298


def test_finalize_op_count():
    ops: list[StackOp] = []
    emit_sha256_finalize(ops.append)
    # GK-BUG-013: 63946 -> 63947 (the dropped 9th byte became <00> OP_EQUALVERIFY).
    assert len(ops) == 63947


# ---------------------------------------------------------------------------
# Op-shape goldens
# ---------------------------------------------------------------------------

def test_compress_starts_with_swap_dup_toaltstack_x2():
    ops: list[StackOp] = []
    emit_sha256_compress(ops.append)
    # F-114: block size guard (OP_SIZE 64 OP_EQUALVERIFY) before the SWAP,
    # state size guard (OP_SIZE 32 OP_EQUALVERIFY) right after it.
    assert ops[0].op == "opcode" and ops[0].code == "OP_SIZE"
    assert ops[1].op == "push" and ops[1].value is not None and ops[1].value.big_int == 64
    assert ops[2].op == "opcode" and ops[2].code == "OP_EQUALVERIFY"
    assert ops[3].op == "swap"
    assert ops[4].op == "opcode" and ops[4].code == "OP_SIZE"
    assert ops[5].op == "push" and ops[5].value is not None and ops[5].value.big_int == 32
    assert ops[6].op == "opcode" and ops[6].code == "OP_EQUALVERIFY"
    assert ops[7].op == "dup"
    assert ops[8].op == "opcode" and ops[8].code == "OP_TOALTSTACK"
    assert ops[9].op == "opcode" and ops[9].code == "OP_TOALTSTACK"

    # Then 15 × (push 4, OP_SPLIT) to unpack the 64-byte block into 16 words.
    for i in range(10, 40, 2):
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


def test_finalize_checks_the_ninth_byte_is_zero():
    # GK-BUG-013: the 9th NUM2BIN byte is the script-number sign (or the 2^64
    # byte). It must be 0x00 -- msgBitLen in [0, 2^64) -- not dropped.
    ops: list[StackOp] = []
    emit_sha256_finalize(ops.append)
    assert ops[3].op == "opcode" and ops[3].code == "OP_SPLIT"
    assert ops[4].op == "push" and ops[4].value is not None
    assert ops[4].value.kind == "bytes" and ops[4].value.bytes_val == b"\x00"
    assert ops[5].op == "opcode" and ops[5].code == "OP_EQUALVERIFY"
    assert all(op.op != "drop" for op in ops[:6])


# ---------------------------------------------------------------------------
# End-to-end emit through the public Emit API
# ---------------------------------------------------------------------------

def test_compress_emits_to_hex_with_known_prefix():
    ops: list[StackOp] = []
    emit_sha256_compress(ops.append)
    method = StackMethod(name="run", ops=ops, max_stack_depth=0)
    res = emit_method(method)
    assert res.script_hex
    # F-114 guards (SIZE <64> EQUALVERIFY, SWAP, SIZE <32> EQUALVERIFY) then
    # DUP, OP_TOALTSTACK, OP_TOALTSTACK = 82 0140 88 7c 82 0120 88 76 6b 6b.
    assert res.script_hex[:24] == "820140887c82012088766b6b"


def test_finalize_emits_the_sign_byte_check_as_a_one_byte_push():
    # GK-BUG-013: <9> NUM2BIN <8> SPLIT <00> EQUALVERIFY <4> SPLIT. The 0x00
    # must be the one-byte push 01 00 -- OP_0 would push the EMPTY string and
    # the equality would refuse every honest length.
    ops: list[StackOp] = []
    emit_sha256_finalize(ops.append)
    method = StackMethod(name="run", ops=ops, max_stack_depth=0)
    res = emit_method(method)
    assert res.script_hex[:18] == "5980587f010088547f"


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
