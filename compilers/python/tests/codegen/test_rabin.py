"""Byte-frozen golden test for the extracted Rabin codegen module.

``emit_verify_rabin_sig`` in ``runar_compiler.codegen.rabin`` lowers the
``verifyRabinSig`` builtin to a fixed 15-opcode sequence (post BUG-010):

    OP_SWAP
    OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   # 0 <= padding < 65536
    OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL

which computes ``(sig^2 + padding) mod pubKey == SHA256(msg)`` plus the
BUG-010 padding range check.

This test pins that exact sequence so a regression in the extracted module
fails locally instead of surfacing only as a hex divergence in the
conformance suite. See ``_review/BUG-010-rfc.md``.
"""

from __future__ import annotations

from runar_compiler.codegen.rabin import RABIN_PADDING_LIMIT, emit_verify_rabin_sig
from runar_compiler.codegen.stack import StackOp

# Position 9 is the push of 65536 (the BUG-010 padding limit) and 17 the
# F-368 pick-depth push of 3; None means "check push value at this index,
# not opcode code". Positions 0, 4 and 13 are the F-144 operand sign bytes,
# 28 the BUG-011 digest sign byte.
RABIN_GOLDEN: list[str | None] = [
    None,  # push 0x00 (F-144: pubKey as unsigned)
    "OP_CAT",
    "OP_BIN2NUM",
    "OP_SWAP",
    None,  # push 0x00 (F-144: padding as unsigned)
    "OP_CAT",
    "OP_BIN2NUM",
    "OP_DUP",
    "OP_0",
    None,  # push 65536
    "OP_WITHIN",
    "OP_VERIFY",
    "OP_ROT",
    None,  # push 0x00 (F-144: sig as unsigned)
    "OP_CAT",
    "OP_BIN2NUM",
    "OP_DUP",  # F-368: sig < pubKey
    None,  # push 3
    "OP_PICK",
    "OP_LESSTHAN",
    "OP_VERIFY",
    "OP_DUP",
    "OP_MUL",
    "OP_ADD",
    "OP_OVER",  # F-047: keep pubKey for the digest reduction
    "OP_MOD",
    "OP_ROT",
    "OP_SHA256",
    None,  # push 0x00 (BUG-011 digest sign byte)
    "OP_CAT",
    "OP_BIN2NUM",
    "OP_ROT",  # F-047
    "OP_MOD",  # F-047: SHA256(msg) mod pubKey
    "OP_NUMEQUAL",
]


def test_emit_verify_rabin_sig_byte_frozen_golden() -> None:
    ops: list[StackOp] = []
    emit_verify_rabin_sig(ops.append)

    assert len(ops) == len(RABIN_GOLDEN)
    for i, op in enumerate(ops):
        expected = RABIN_GOLDEN[i]
        if expected is None:
            assert op.op == "push", f"op {i}: expected push, got {op.op!r}"
            assert op.value is not None, f"op {i}: push must have value"
            if i == 9:
                assert op.value.kind == "bigint", f"op {i}: push kind"
                assert op.value.big_int == RABIN_PADDING_LIMIT, (
                    f"op {i}: BUG-010 padding limit"
                )
            elif i == 17:
                assert op.value.kind == "bigint", f"op {i}: push kind"
                assert op.value.big_int == 3, f"op {i}: F-368 pick depth"
            else:
                # F-144 operand sign bytes and the BUG-011 digest sign byte:
                # each makes the item below it read as a non-negative Script
                # number.
                assert op.value.kind == "bytes", f"op {i}: push kind"
                assert op.value.bytes_val == b"\x00", (
                    f"op {i}: sign byte"
                )
        else:
            assert op.op == "opcode", f"op {i}: expected opcode, got {op.op!r}"
            assert op.code == expected, f"op {i}: expected {expected!r}"
