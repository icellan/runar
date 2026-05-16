"""WOTS+ (Winternitz One-Time Signature, post-quantum) Bitcoin Script codegen
for the Runar Python stack lowerer.

Splice into LoweringContext in stack.py. All helpers self-contained.
Entry: _lower_verify_wots() -> calls emit_verify_wots().

Parameters: w=16, n=32 (SHA-256), len=67 chains (64 message + 3 checksum).
pubkey is 64 bytes: pubSeed(32) || pkRoot(32).

Stack on entry: [..., msg, sig, pubkey] (pubkey on top).
Stack on exit:  [..., bool] (1 = valid, 0 = invalid).

Direct port of ``compilers/go/codegen/wots.go``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp, PushValue


# ---------------------------------------------------------------------------
# Lazy imports to avoid circular dependency with stack.py
# ---------------------------------------------------------------------------

def _make_stack_op(*, op: str, **kwargs) -> "StackOp":
    from runar_compiler.codegen.stack import StackOp
    if "else_" in kwargs:
        kwargs["else_ops"] = kwargs.pop("else_")
    return StackOp(op=op, **kwargs)


def _make_push_value(*, kind: str, **kwargs) -> "PushValue":
    from runar_compiler.codegen.stack import PushValue
    if "bytes_" in kwargs:
        kwargs["bytes_val"] = kwargs.pop("bytes_")
    return PushValue(kind=kind, **kwargs)


def _big_int_push(n: int) -> "PushValue":
    from runar_compiler.codegen.stack import big_int_push
    return big_int_push(n)


# ---------------------------------------------------------------------------
# One WOTS+ chain
# ---------------------------------------------------------------------------

def _emit_wots_one_chain(emit: Callable, chain_index: int) -> None:
    """Emit one WOTS+ chain verification.

    Entry stack: pubSeed(bottom) sig csum endpt digit(top)
    Exit stack:  pubSeed(bottom) sigRest newCsum newEndpt
    """
    # Save steps_copy = 15 - digit to alt
    emit(_make_stack_op(op="opcode", code="OP_DUP"))
    emit(_make_stack_op(op="push", value=_big_int_push(15)))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_SUB"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

    # Save endpt, csum to alt
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

    # Split 32B sig element
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="push", value=_big_int_push(32)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
    emit(_make_stack_op(op="swap"))

    # Hash loop
    for j in range(15):
        adrs_bytes = bytes([chain_index, j])
        emit(_make_stack_op(op="opcode", code="OP_DUP"))
        emit(_make_stack_op(op="opcode", code="OP_0NOTEQUAL"))
        emit(_make_stack_op(
            op="if",
            then=[
                _make_stack_op(op="opcode", code="OP_1SUB"),
            ],
            else_ops=[
                _make_stack_op(op="swap"),
                _make_stack_op(op="push", value=_big_int_push(2)),
                _make_stack_op(op="opcode", code="OP_PICK"),
                _make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=adrs_bytes)),
                _make_stack_op(op="opcode", code="OP_CAT"),
                _make_stack_op(op="swap"),
                _make_stack_op(op="opcode", code="OP_CAT"),
                _make_stack_op(op="opcode", code="OP_SHA256"),
                _make_stack_op(op="swap"),
            ],
        ))
    emit(_make_stack_op(op="drop"))

    # Restore from altstack
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))

    # csum += steps_copy
    emit(_make_stack_op(op="opcode", code="OP_ROT"))
    emit(_make_stack_op(op="opcode", code="OP_ADD"))

    # Concat endpoint to endpt_acc
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="push", value=_big_int_push(3)))
    emit(_make_stack_op(op="opcode", code="OP_ROLL"))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))


# ---------------------------------------------------------------------------
# Full WOTS+ verifier
# ---------------------------------------------------------------------------

def emit_verify_wots(emit: Callable) -> None:
    """Emit the full WOTS+ signature verification script.

    Parameters: w=16, n=32 (SHA-256), len=67 chains.
    pubkey is 64 bytes: pubSeed(32) || pkRoot(32).

    Stack on entry: [..., msg, sig, pubkey] (pubkey on top).
    Stack on exit:  [..., bool] (1 = valid, 0 = invalid).
    """
    # Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
    emit(_make_stack_op(op="push", value=_big_int_push(32)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

    # Rearrange: put pubSeed at bottom, hash msg
    emit(_make_stack_op(op="opcode", code="OP_ROT"))
    emit(_make_stack_op(op="opcode", code="OP_ROT"))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_SHA256"))

    # Canonical layout
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="push", value=_big_int_push(0)))
    emit(_make_stack_op(op="opcode", code="OP_0"))
    emit(_make_stack_op(op="push", value=_big_int_push(3)))
    emit(_make_stack_op(op="opcode", code="OP_ROLL"))

    # Process 32 bytes -> 64 message chains
    for byte_idx in range(32):
        if byte_idx < 31:
            emit(_make_stack_op(op="push", value=_big_int_push(1)))
            emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
            emit(_make_stack_op(op="swap"))
        # Unsigned byte conversion
        emit(_make_stack_op(op="push", value=_big_int_push(0)))
        emit(_make_stack_op(op="push", value=_big_int_push(1)))
        emit(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        emit(_make_stack_op(op="opcode", code="OP_CAT"))
        emit(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
        # Extract nibbles
        emit(_make_stack_op(op="opcode", code="OP_DUP"))
        emit(_make_stack_op(op="push", value=_big_int_push(16)))
        emit(_make_stack_op(op="opcode", code="OP_DIV"))
        emit(_make_stack_op(op="swap"))
        emit(_make_stack_op(op="push", value=_big_int_push(16)))
        emit(_make_stack_op(op="opcode", code="OP_MOD"))

        if byte_idx < 31:
            emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
            emit(_make_stack_op(op="swap"))
            emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
        else:
            emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

        _emit_wots_one_chain(emit, byte_idx * 2)  # high nibble chain

        if byte_idx < 31:
            emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
            emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
            emit(_make_stack_op(op="swap"))
            emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
        else:
            emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))

        _emit_wots_one_chain(emit, byte_idx * 2 + 1)  # low nibble chain

        if byte_idx < 31:
            emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))

    # Checksum digits
    emit(_make_stack_op(op="swap"))
    # d66
    emit(_make_stack_op(op="opcode", code="OP_DUP"))
    emit(_make_stack_op(op="push", value=_big_int_push(16)))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
    # d65
    emit(_make_stack_op(op="opcode", code="OP_DUP"))
    emit(_make_stack_op(op="push", value=_big_int_push(16)))
    emit(_make_stack_op(op="opcode", code="OP_DIV"))
    emit(_make_stack_op(op="push", value=_big_int_push(16)))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
    # d64
    emit(_make_stack_op(op="push", value=_big_int_push(256)))
    emit(_make_stack_op(op="opcode", code="OP_DIV"))
    emit(_make_stack_op(op="push", value=_big_int_push(16)))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

    # 3 checksum chains (indices 64, 65, 66)
    for ci in range(3):
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
        emit(_make_stack_op(op="push", value=_big_int_push(0)))
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        _emit_wots_one_chain(emit, 64 + ci)
        emit(_make_stack_op(op="swap"))
        emit(_make_stack_op(op="drop"))

    # Final comparison
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="drop"))
    emit(_make_stack_op(op="opcode", code="OP_SHA256"))
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
    emit(_make_stack_op(op="opcode", code="OP_EQUAL"))
    # Clean up pubSeed
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="drop"))
