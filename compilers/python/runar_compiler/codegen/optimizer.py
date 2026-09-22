"""Peephole optimizer -- runs on Stack IR before emission.

Scans for short sequences of stack operations that can be replaced with
fewer or cheaper opcodes.  Applies rules iteratively until a fixed point
is reached (no more changes).  Mirrors the TypeScript / Go peephole optimizer.

Port of ``compilers/go/codegen/optimizer.go``.
"""

from __future__ import annotations

from typing import Optional

from runar_compiler.codegen.stack import StackOp, PushValue

MAX_OPTIMIZATION_ITERATIONS = 100


def optimize_stack_ops(ops: list[StackOp]) -> list[StackOp]:
    """Apply peephole optimization to a list of stack ops."""
    # First, recursively optimize nested if-blocks
    current = [_optimize_nested_if(op) for op in ops]

    for _ in range(MAX_OPTIMIZATION_ITERATIONS):
        result, changed = _apply_one_pass(current)
        if not changed:
            break
        current = result

    return current


def _optimize_nested_if(op: StackOp) -> StackOp:
    if op.op == "if":
        optimized_then = optimize_stack_ops(op.then)
        optimized_else = optimize_stack_ops(op.else_ops) if op.else_ops else []
        return StackOp(
            op="if",
            then=optimized_then,
            else_ops=optimized_else,
            source_loc=op.source_loc,
        )
    return op


def _propagate_source_loc(original: StackOp, replacements: list[StackOp]) -> None:
    """Copy source_loc from the first matched op to all replacement ops."""
    if original.source_loc is not None:
        for r in replacements:
            if r.source_loc is None:
                r.source_loc = original.source_loc


def _apply_one_pass(ops: list[StackOp]) -> tuple[list[StackOp], bool]:
    result: list[StackOp] = []
    changed = False
    i = 0

    while i < len(ops):
        # Try 4-op window
        if i + 3 < len(ops):
            replacement = _match_window4(ops[i], ops[i + 1], ops[i + 2], ops[i + 3])
            if replacement is not None:
                _propagate_source_loc(ops[i], replacement)
                result.extend(replacement)
                i += 4
                changed = True
                continue

        # Try 3-op window
        if i + 2 < len(ops):
            replacement = _match_window3(ops[i], ops[i + 1], ops[i + 2])
            if replacement is not None:
                _propagate_source_loc(ops[i], replacement)
                result.extend(replacement)
                i += 3
                changed = True
                continue

        # Try 2-op window
        if i + 1 < len(ops):
            replacement = _match_window2(ops[i], ops[i + 1])
            if replacement is not None:
                _propagate_source_loc(ops[i], replacement)
                result.extend(replacement)
                i += 2
                changed = True
                continue

        result.append(ops[i])
        i += 1

    return result, changed


def _is_raw_bytes(op: StackOp) -> bool:
    """Return True if *op* is an opaque raw_bytes span emitted by a raw_script
    ANF node. raw_bytes is a hard peephole barrier -- no optimization window
    may span or rewrite across it, because the bytes are opaque and not
    guaranteed to form a well-formed opcode stream.
    """
    return op.op == "raw_bytes"


def _match_window2(a: StackOp, b: StackOp) -> Optional[list[StackOp]]:
    """Try to match a window-2 peephole rule.  Returns replacement list or None."""
    if _is_raw_bytes(a) or _is_raw_bytes(b):
        return None

    # PUSH x, DROP -> remove both (dead value elimination)
    if a.op == "push" and b.op == "drop":
        return []

    # DUP, DROP -> remove both
    if a.op == "dup" and b.op == "drop":
        return []

    # SWAP, SWAP -> remove both (identity)
    if a.op == "swap" and b.op == "swap":
        return []

    # PUSH 1, OP_ADD -> OP_1ADD
    if _is_push_bigint(a, 1) and _is_opcode_op(b, "OP_ADD"):
        return [StackOp(op="opcode", code="OP_1ADD")]

    # PUSH 1, OP_SUB -> OP_1SUB
    if _is_push_bigint(a, 1) and _is_opcode_op(b, "OP_SUB"):
        return [StackOp(op="opcode", code="OP_1SUB")]

    # NOTE (F-001): no ``PUSH 0, OP_ADD``, ``PUSH 0, OP_SUB`` or
    # ``OP_NEGATE, OP_NEGATE`` elimination.  x+0, x-0 and -(-x) are identities
    # over integers, not over stack elements: the opcode decodes its operand as
    # a CScriptNum (rejecting a non-minimal encoding under strict rules) and
    # pushes back the minimal re-encoding.  Deleting it changes accept/reject
    # and the value for a witness-supplied operand.

    # NOTE: ``OP_NOT, OP_NOT`` is NOT eliminated here -- see the guarded 3-op
    # rule in ``_match_window3`` (C17).  The pair is boolean normalisation, not
    # numeric identity, so it may only be dropped when the producer of the
    # negated value provably leaves a canonical 0/1 behind.

    # OP_EQUAL, OP_VERIFY -> OP_EQUALVERIFY
    if _is_opcode_op(a, "OP_EQUAL") and _is_opcode_op(b, "OP_VERIFY"):
        return [StackOp(op="opcode", code="OP_EQUALVERIFY")]

    # OP_CHECKSIG, OP_VERIFY -> OP_CHECKSIGVERIFY
    if _is_opcode_op(a, "OP_CHECKSIG") and _is_opcode_op(b, "OP_VERIFY"):
        return [StackOp(op="opcode", code="OP_CHECKSIGVERIFY")]

    # OP_NUMEQUAL, OP_VERIFY -> OP_NUMEQUALVERIFY
    if _is_opcode_op(a, "OP_NUMEQUAL") and _is_opcode_op(b, "OP_VERIFY"):
        return [StackOp(op="opcode", code="OP_NUMEQUALVERIFY")]

    # OP_CHECKMULTISIG, OP_VERIFY -> OP_CHECKMULTISIGVERIFY
    if _is_opcode_op(a, "OP_CHECKMULTISIG") and _is_opcode_op(b, "OP_VERIFY"):
        return [StackOp(op="opcode", code="OP_CHECKMULTISIGVERIFY")]

    # OP_DUP, OP_DROP -> remove both
    if _is_opcode_op(a, "OP_DUP") and _is_opcode_op(b, "OP_DROP"):
        return []

    # OP_OVER, OP_OVER -> OP_2DUP
    if a.op == "over" and b.op == "over":
        return [StackOp(op="opcode", code="OP_2DUP")]

    # OP_DROP, OP_DROP -> OP_2DROP
    if a.op == "drop" and b.op == "drop":
        return [StackOp(op="opcode", code="OP_2DROP")]

    # PUSH(0) + Roll(0) → remove both (typed or string-form)
    if _is_push_bigint(a, 0) and (
        (b.op == "roll" and b.depth == 0) or _is_opcode_op(b, "OP_ROLL")
    ):
        return []

    # PUSH(1) + Roll(1) → Swap (typed or string-form)
    if _is_push_bigint(a, 1) and (
        (b.op == "roll" and b.depth == 1) or _is_opcode_op(b, "OP_ROLL")
    ):
        return [StackOp(op="swap")]

    # PUSH(2) + Roll(2) → Rot (typed or string-form)
    if _is_push_bigint(a, 2) and (
        (b.op == "roll" and b.depth == 2) or _is_opcode_op(b, "OP_ROLL")
    ):
        return [StackOp(op="rot")]

    # PUSH(0) + Pick(0) → Dup (typed or string-form)
    if _is_push_bigint(a, 0) and (
        (b.op == "pick" and b.depth == 0) or _is_opcode_op(b, "OP_PICK")
    ):
        return [StackOp(op="dup")]

    # PUSH(1) + Pick(1) → Over (typed or string-form)
    if _is_push_bigint(a, 1) and (
        (b.op == "pick" and b.depth == 1) or _is_opcode_op(b, "OP_PICK")
    ):
        return [StackOp(op="over")]

    # SHA256 + SHA256 → HASH256
    if _is_opcode_op(a, "OP_SHA256") and _is_opcode_op(b, "OP_SHA256"):
        return [StackOp(op="opcode", code="OP_HASH256")]

    # PUSH 0 + NUMEQUAL → NOT
    if _is_push_bigint(a, 0) and _is_opcode_op(b, "OP_NUMEQUAL"):
        return [StackOp(op="opcode", code="OP_NOT")]

    return None


# Opcodes whose result is guaranteed to be a CANONICAL boolean -- the minimal
# script-number encoding of 0 (the empty element) or 1 (``{0x01}``), and nothing
# else.  Every entry pushes ``CScriptNum(0|1).getvch()`` (or
# ``vchFalse``/``vchTrue``) in the reference interpreter.
#
# Stack-shuffling ops (``OP_DUP`` / ``OP_PICK`` / ``OP_ROLL`` / ``OP_SWAP`` / ...)
# are deliberately absent: they forward a value whose provenance this local
# window cannot see.
CANONICAL_BOOL_OPCODES = frozenset(
    {
        "OP_EQUAL",
        "OP_NUMEQUAL",
        "OP_NUMNOTEQUAL",
        "OP_LESSTHAN",
        "OP_GREATERTHAN",
        "OP_LESSTHANOREQUAL",
        "OP_GREATERTHANOREQUAL",
        "OP_BOOLAND",
        "OP_BOOLOR",
        "OP_WITHIN",
        "OP_NOT",
        "OP_0NOTEQUAL",
        "OP_CHECKSIG",
        "OP_CHECKMULTISIG",
    }
)


def _produces_canonical_bool(op: StackOp) -> bool:
    """Return True when *op* provably leaves a canonical boolean (0 or 1)."""
    if op.op == "opcode":
        return op.code in CANONICAL_BOOL_OPCODES
    if op.op == "push" and op.value is not None:
        if op.value.kind == "bool":
            return True
        if op.value.kind == "bigint":
            return op.value.big_int in (0, 1)
    return False


def _match_window3(a: StackOp, b: StackOp, c: StackOp) -> Optional[list[StackOp]]:
    """Try to match a window-3 peephole rule."""
    if _is_raw_bytes(a) or _is_raw_bytes(b) or _is_raw_bytes(c):
        return None

    # <canonical-bool producer>, OP_NOT, OP_NOT -> <canonical-bool producer>
    #
    # ``OP_NOT OP_NOT`` is boolean NORMALISATION, not numeric identity: for any
    # non-canonical operand (say 5) the pair yields 1, while deleting it leaves
    # 5.  Truthiness is preserved, the VALUE is not -- and a downstream
    # ``OP_EQUAL`` / ``OP_NUMEQUAL`` / state serialisation consumes the value,
    # so the two programs disagree on accept/reject.
    #
    # The window therefore includes the PRODUCER of the value being negated and
    # only fires when that producer provably yields a canonical 0/1 (C17).  This
    # matters because the ``PUSH 0; OP_NUMEQUAL -> OP_NOT`` rule in
    # ``_match_window2`` synthesises a fresh ``OP_NOT`` sitting on top of an
    # ARBITRARY script number: for ``x !== 0n`` the lowerer emits
    # ``<x>; PUSH 0; OP_NUMEQUAL; OP_NOT``, which an unguarded 2-op rule
    # collapsed all the way down to ``<x>``.  With the guard the pair survives
    # as ``<x>; OP_NOT; OP_NOT`` -- still one byte shorter than the input, and
    # value-exact.
    if (
        _produces_canonical_bool(a)
        and _is_opcode_op(b, "OP_NOT")
        and _is_opcode_op(c, "OP_NOT")
    ):
        return [a]

    a_val = _push_bigint_value(a)
    b_val = _push_bigint_value(b)
    if a_val is not None and b_val is not None:
        if _is_opcode_op(c, "OP_ADD"):
            return [StackOp(op="push", value=PushValue(kind="bigint", big_int=a_val + b_val))]
        if _is_opcode_op(c, "OP_SUB"):
            return [StackOp(op="push", value=PushValue(kind="bigint", big_int=a_val - b_val))]
        if _is_opcode_op(c, "OP_MUL"):
            return [StackOp(op="push", value=PushValue(kind="bigint", big_int=a_val * b_val))]
    return None


def _match_window4(
    a: StackOp, b: StackOp, c: StackOp, d: StackOp
) -> Optional[list[StackOp]]:
    """Try to match a window-4 peephole rule."""
    if _is_raw_bytes(a) or _is_raw_bytes(b) or _is_raw_bytes(c) or _is_raw_bytes(d):
        return None
    a_val = _push_bigint_value(a)
    c_val = _push_bigint_value(c)
    if a_val is not None and c_val is not None:
        if _is_opcode_op(b, "OP_ADD") and _is_opcode_op(d, "OP_ADD"):
            return [
                StackOp(op="push", value=PushValue(kind="bigint", big_int=a_val + c_val)),
                StackOp(op="opcode", code="OP_ADD"),
            ]
        if _is_opcode_op(b, "OP_SUB") and _is_opcode_op(d, "OP_SUB"):
            return [
                StackOp(op="push", value=PushValue(kind="bigint", big_int=a_val + c_val)),
                StackOp(op="opcode", code="OP_SUB"),
            ]
    return None


def _push_bigint_value(op: StackOp) -> Optional[int]:
    if op.op != "push" or op.value is None:
        return None
    if op.value.kind != "bigint" or op.value.big_int is None:
        return None
    return op.value.big_int


def _is_push_bigint(op: StackOp, n: int) -> bool:
    if op.op != "push" or op.value is None:
        return False
    if op.value.kind != "bigint" or op.value.big_int is None:
        return False
    return op.value.big_int == n


def _is_opcode_op(op: StackOp, code: str) -> bool:
    return op.op == "opcode" and op.code == code
