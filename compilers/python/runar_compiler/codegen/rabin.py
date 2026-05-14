"""Rabin signature verification codegen for Bitcoin Script.

emit_verify_rabin_sig: [msg, sig, padding, pubKey] -> [bool]

Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg).
The emission is a fixed 10-opcode sequence:

    OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL

The caller must bring the 4 arguments to the top of the stack in argument
order (msg sig padding pubKey, pubKey on top) before calling.

Direct port of ``packages/runar-compiler/src/passes/rabin-codegen.ts``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp


# Lazy import to avoid a circular dependency with stack.py.
def _opcode(code: str) -> "StackOp":
    from runar_compiler.codegen.stack import StackOp
    return StackOp(op="opcode", code=code)


def emit_verify_rabin_sig(emit: Callable[["StackOp"], None]) -> None:
    """Emit the Rabin signature verification opcode sequence.

    Stack on entry (bottom->top): msg sig padding pubKey
    Stack on exit:                bool (1 = valid, 0 = invalid)
    """
    emit(_opcode("OP_SWAP"))    # msg sig pubKey padding
    emit(_opcode("OP_ROT"))     # msg pubKey padding sig
    emit(_opcode("OP_DUP"))     # msg pubKey padding sig sig
    emit(_opcode("OP_MUL"))     # msg pubKey padding sig^2
    emit(_opcode("OP_ADD"))     # msg pubKey (sig^2+padding)
    emit(_opcode("OP_SWAP"))    # msg (sig^2+padding) pubKey
    emit(_opcode("OP_MOD"))     # msg ((sig^2+padding) mod pubKey)
    emit(_opcode("OP_SWAP"))    # ((sig^2+padding) mod pubKey) msg
    emit(_opcode("OP_SHA256"))  # ((sig^2+padding) mod pubKey) SHA256(msg)
    emit(_opcode("OP_EQUAL"))   # bool
