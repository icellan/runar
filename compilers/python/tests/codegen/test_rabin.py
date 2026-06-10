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

# Position 3 is the push of 65536 (the BUG-010 padding limit); None means
# "check push value at this index, not opcode code".
RABIN_GOLDEN: list[str | None] = [
    "OP_SWAP",
    "OP_DUP",
    "OP_0",
    None,  # push 65536
    "OP_WITHIN",
    "OP_VERIFY",
    "OP_ROT",
    "OP_DUP",
    "OP_MUL",
    "OP_ADD",
    "OP_SWAP",
    "OP_MOD",
    "OP_SWAP",
    "OP_SHA256",
    "OP_EQUAL",
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
            assert op.value.kind == "bigint", f"op {i}: push kind"
            assert op.value.big_int == RABIN_PADDING_LIMIT, (
                f"op {i}: BUG-010 padding limit"
            )
        else:
            assert op.op == "opcode", f"op {i}: expected opcode, got {op.op!r}"
            assert op.code == expected, f"op {i}: expected {expected!r}"
