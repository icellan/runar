"""Rabin signature verification codegen for Bitcoin Script.

emit_verify_rabin_sig: [msg, sig, padding, pubKey] -> [bool]

Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg)
AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010).
The emission is a fixed 15-opcode sequence:

    OP_SWAP
    OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   # 0 <= padding < 65536 (BUG-010)
    OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL

The caller must bring the 4 arguments to the top of the stack in argument
order (msg sig padding pubKey, pubKey on top) before calling.

Direct port of ``packages/runar-compiler/src/passes/rabin-codegen.ts``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp

# Exclusive upper bound on the Rabin `padding` parameter, enforced on-chain.
# The legitimate signer (``packages/runar-go/rabin.go::RabinSign``) produces
# ``padding < 1000``; the on-chain bound is 65536 (16-bit) for slack.
# See ``_review/BUG-010-rfc.md``.
RABIN_PADDING_LIMIT: int = 65536


# Lazy import to avoid a circular dependency with stack.py.
def _opcode(code: str) -> "StackOp":
    from runar_compiler.codegen.stack import StackOp
    return StackOp(op="opcode", code=code)


def _push_int(n: int) -> "StackOp":
    from runar_compiler.codegen.stack import StackOp, big_int_push
    return StackOp(op="push", value=big_int_push(n))


def emit_verify_rabin_sig(emit: Callable[["StackOp"], None]) -> None:
    """Emit the Rabin signature verification opcode sequence.

    Stack on entry (bottom->top): msg sig padding pubKey
    Stack on exit:                bool (1 = valid, 0 = invalid)
    """
    emit(_opcode("OP_SWAP"))                            # msg sig pubKey padding
    # BUG-010 padding range check: assert 0 <= padding < 65536.
    emit(_opcode("OP_DUP"))                             # ... padding padding
    emit(_opcode("OP_0"))                               # ... padding padding 0
    emit(_push_int(RABIN_PADDING_LIMIT))                # ... padding padding 0 65536
    emit(_opcode("OP_WITHIN"))                          # ... padding (0<=padding<65536)
    emit(_opcode("OP_VERIFY"))                          # ... padding
    emit(_opcode("OP_ROT"))                             # msg pubKey padding sig
    emit(_opcode("OP_DUP"))                             # msg pubKey padding sig sig
    emit(_opcode("OP_MUL"))                             # msg pubKey padding sig^2
    emit(_opcode("OP_ADD"))                             # msg pubKey (sig^2+padding)
    emit(_opcode("OP_SWAP"))                            # msg (sig^2+padding) pubKey
    emit(_opcode("OP_MOD"))                             # msg ((sig^2+padding) mod pubKey)
    emit(_opcode("OP_SWAP"))                            # ((sig^2+padding) mod pubKey) msg
    emit(_opcode("OP_SHA256"))                          # ((sig^2+padding) mod pubKey) SHA256(msg)
    emit(_opcode("OP_EQUAL"))                           # bool
