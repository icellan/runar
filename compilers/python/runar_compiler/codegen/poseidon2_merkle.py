"""Poseidon2 Merkle proof codegen -- Merkle root computation for Bitcoin Script
using Poseidon2 KoalaBear compression.

Follows the merkle.py pattern: self-contained module imported by stack.py.

Unlike the SHA-256 Merkle variants (which use 32-byte hash digests),
Poseidon2 KoalaBear Merkle trees represent each node as 8 KoalaBear field
elements. Compression feeds two 8-element digests (16 elements total) into
the Poseidon2 permutation and takes the first 8 elements of the output.

The depth parameter must be a compile-time constant because the loop is
unrolled at compile time (Bitcoin Script has no loops).

Stack convention:

  Input:  [..., leaf_0..leaf_7, sib0_0..sib0_7, ..., sib(D-1)_0..sib(D-1)_7, index]
  Output: [..., root_0..root_7]

Where D = depth. The leaf is 8 field elements, each sibling is 8 field
elements, and index is a bigint whose bits determine left/right ordering at
each tree level.

Direct port of ``compilers/go/codegen/poseidon2_merkle.go``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

from runar_compiler.codegen.poseidon2_koalabear import emit_poseidon2_kb_compress

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp


def _make_stack_op(*, op: str, **kwargs) -> "StackOp":
    from runar_compiler.codegen.stack import StackOp, PushValue
    if "else_" in kwargs:
        kwargs["else_ops"] = kwargs.pop("else_")
    return StackOp(op=op, **kwargs)


def _big_int_push(n: int) -> "PushValue":
    from runar_compiler.codegen.stack import PushValue
    return PushValue(kind="bigint", big_int=n)


def _emit_roll(emit: Callable[["StackOp"], None], d: int) -> None:
    """Emit a ROLL operation for a given depth."""
    if d == 0:
        return
    if d == 1:
        emit(_make_stack_op(op="swap"))
        return
    if d == 2:
        emit(_make_stack_op(op="rot"))
        return
    emit(_make_stack_op(op="push", value=_big_int_push(d)))
    emit(_make_stack_op(op="roll", depth=d))


def emit_poseidon2_merkle_root(emit: Callable[["StackOp"], None], depth: int) -> None:
    """Emit Poseidon2 Merkle root computation.

    Stack in:  [..., leaf(8 elems), proof(depth*8 elems), index]
    Stack out: [..., root(8 elems)]

    depth is a compile-time constant (unrolled loop). Must be in [1, 32].
    Higher depths produce quadratically larger scripts due to roll operations.

    Strategy overview:

    At each level i, the stack is:
      [..., current(8), sib_i(8), future_sibs((depth-i-1)*8), index]

    1. Save index to alt-stack (it stays there for the whole level).
    2. Compute direction bit from index (DUP before saving).
    3. Roll current(8)+sib_i(8) above future_sibs so they become the top 16.
    4. Retrieve bit from alt, do conditional swap.
    5. Poseidon2 compress (top 16 -> top 8).
    6. Roll new_current(8) back below future_sibs.
    7. Restore index from alt.

    At the end, drop index and leave root(8) on the stack.
    """
    if depth < 1 or depth > 32:
        raise RuntimeError(
            f"emit_poseidon2_merkle_root: depth must be in [1, 32], got {depth}"
        )

    for i in range(depth):
        # Stack: [..., current(8), sib_i(8), future_sibs(F*8), index]
        # where F = depth - i - 1 (number of future sibling groups).
        future_elems = (depth - i - 1) * 8

        # ----- Compute direction bit and save index + bit to alt -----
        emit(_make_stack_op(op="opcode", code="OP_DUP"))  # dup index
        if i > 0:
            if i == 1:
                emit(_make_stack_op(op="opcode", code="OP_2DIV"))
            else:
                emit(_make_stack_op(op="push", value=_big_int_push(i)))
                emit(_make_stack_op(op="opcode", code="OP_RSHIFTNUM"))
        emit(_make_stack_op(op="push", value=_big_int_push(2)))
        emit(_make_stack_op(op="opcode", code="OP_MOD"))
        # Stack: [..., current(8), sib_i(8), future_sibs, index, bit]

        # Save bit then index to alt-stack. We need bit first (on top of alt)
        # when we retrieve it later.
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # save bit
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # save index
        # Stack: [..., current(8), sib_i(8), future_sibs]
        # Alt (top->bottom): [index, bit]

        # ----- Roll current+sib_i above future_sibs -----
        # current_0 is the deepest element of the working area.
        # Its depth from stack top = futureElems + 15.
        # After each roll from that depth, the next target element ends up
        # at the same depth (the removed element came from below).
        if future_elems > 0:
            roll_depth = future_elems + 15
            for _ in range(16):
                _emit_roll(emit, roll_depth)
        # Stack: [..., future_sibs, current(8), sib_i(8)]
        # Top 16 elements: current_0..7 then sib_i_0..7 (sib_i_7 on top)

        # ----- Retrieve bit and conditional swap -----
        # Pop index from alt (it's on top), save to main, get bit.
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # get index
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # get bit
        # Stack: [..., future_sibs, current(8), sib_i(8), index, bit]

        # Save index back to alt
        emit(_make_stack_op(op="swap"))
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # save index
        # Stack: [..., future_sibs, current(8), sib_i(8), bit]
        # Alt: [index]

        # OP_IF consumes bit. If bit==1, swap current and sibling groups.
        # 8x roll(15) moves each element of the bottom group (current) above
        # the top group (sibling), producing [sibling(8), current(8)].
        then_ops = []
        for _ in range(8):
            then_ops.append(_make_stack_op(op="push", value=_big_int_push(15)))
            then_ops.append(_make_stack_op(op="roll", depth=15))

        emit(_make_stack_op(
            op="if",
            then=then_ops,
            else_ops=[],  # bit==0: already in correct order [current(8), sibling(8)]
        ))
        # Stack: [..., future_sibs, left(8), right(8)]

        # ----- Poseidon2 compress -----
        emit_poseidon2_kb_compress(emit)
        # Stack: [..., future_sibs, new_current(8)]

        # ----- Roll new_current back below future_sibs -----
        # Roll each future_sib element to the top. After that, future_sibs are
        # above new_current.
        # NOTE: This is O(futureElems) rolls per level, making total script size
        # quadratic in tree depth -- a known limitation of Bitcoin Script's stack model.
        if future_elems > 0:
            # The bottom future_sib element is at depth 7 + futureElems.
            roll_depth = 7 + future_elems
            for _ in range(future_elems):
                _emit_roll(emit, roll_depth)
        # Stack: [..., new_current(8), future_sibs]

        # ----- Restore index from alt -----
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        # Stack: [..., new_current(8), future_sibs, index]

    # After all levels: [..., root(8), index]
    emit(_make_stack_op(op="drop"))
    # Stack: [..., root_0..root_7]
