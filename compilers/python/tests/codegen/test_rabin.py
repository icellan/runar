"""Byte-frozen golden test for the extracted Rabin codegen module (GAP-M1).

``emit_verify_rabin_sig`` in ``runar_compiler.codegen.rabin`` lowers the
``verifyRabinSig`` builtin to a fixed 10-opcode sequence:

    OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL

which computes ``(sig^2 + padding) mod pubKey == SHA256(msg)``.

This test pins that exact sequence so a regression in the extracted module
fails locally instead of surfacing only as a hex divergence in the
conformance suite.
"""

from __future__ import annotations

from runar_compiler.codegen.rabin import emit_verify_rabin_sig
from runar_compiler.codegen.stack import StackOp

RABIN_GOLDEN = [
    "OP_SWAP",
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
        assert op.op == "opcode", f"op {i}: expected opcode, got {op.op!r}"
        assert op.code == RABIN_GOLDEN[i], f"op {i}: expected {RABIN_GOLDEN[i]!r}"
