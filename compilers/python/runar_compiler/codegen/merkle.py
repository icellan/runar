"""Merkle proof codegen -- Merkle root computation for Bitcoin Script.

Follows the ec.py / babybear.py pattern: self-contained module imported by
stack.py.

Provides two variants:
- merkle_root_sha256: uses OP_SHA256 (single SHA-256, used by FRI/STARK)
- merkle_root_hash256: uses OP_HASH256 (double SHA-256, standard Bitcoin Merkle)

The depth parameter must be a compile-time constant because the loop is
unrolled at compile time (Bitcoin Script has no loops).

Stack convention:
  Input:  [..., leaf(32B), proof(depth*32 bytes), index(bigint)]
  Output: [..., root(32B)]

Direct port of ``packages/runar-compiler/src/passes/merkle-codegen.ts``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp


# ---------------------------------------------------------------------------
# Lazy imports to avoid circular dependency with stack.py
# ---------------------------------------------------------------------------

def _make_stack_op(*, op: str, **kwargs) -> "StackOp":
    from runar_compiler.codegen.stack import StackOp
    if "else_" in kwargs:
        kwargs["else_ops"] = kwargs.pop("else_")
    return StackOp(op=op, **kwargs)


def _big_int_push(n: int) -> "StackOp":
    from runar_compiler.codegen.stack import big_int_push
    return big_int_push(n)


# ===========================================================================
# Public emit functions
# ===========================================================================

def emit_merkle_root_sha256(emit: Callable[["StackOp"], None], depth: int) -> None:
    """Compute Merkle root using SHA-256.

    Stack in:  [..., leaf(32B), proof(depth*32B), index(bigint)]
    Stack out: [..., root(32B)]

    *depth* must be a compile-time constant: number of levels in the Merkle tree.
    """
    _emit_merkle_root(emit, depth, "OP_SHA256")


def emit_merkle_root_hash256(emit: Callable[["StackOp"], None], depth: int) -> None:
    """Compute Merkle root using Hash256 (double SHA-256).

    Stack in:  [..., leaf(32B), proof(depth*32B), index(bigint)]
    Stack out: [..., root(32B)]

    *depth* must be a compile-time constant: number of levels in the Merkle tree.
    """
    _emit_merkle_root(emit, depth, "OP_HASH256")


# ===========================================================================
# Core Merkle root computation
# ===========================================================================

def _emit_merkle_root(
    emit: Callable[["StackOp"], None],
    depth: int,
    hash_op: str,
) -> None:
    """Core Merkle root computation.

    Stack layout at entry: [leaf, proof, index]

    For each level i from 0 to depth-1:
      Stack before iteration: [current, remaining_proof, index]

      1. Get sibling: split remaining_proof at offset 32
      2. Get direction bit: (index >> i) & 1
      3. OP_IF (direction=1): swap current and sibling before concatenating
      4. OP_CAT + hash -> new current

    After all levels: [root, empty_proof, index]
    Clean up: drop empty proof and index, leave root.
    """
    # Stack: [leaf, proof, index]

    # R-120: bound the index BEFORE walking the tree.
    #
    # The loop below reads bit i of the index at level i and never looks above bit
    # depth-1, then drops the index unexamined. So index, index + 2^depth,
    # index + 2^40 and any NEGATIVE index walk the same path and produce the same
    # root: measured at depth 2, indices 1, 5, 9, 1025 and -1 all returned
    # 5306f72f...6ee0f336. ABORT rather than clamp -- these are VALUE builtins, and
    # CL-BUG-095 set the policy that predicates clamp and flag while value producers
    # OP_VERIFY. OP_WITHIN is half-open: exactly 0 <= index < 2^depth, and the lower
    # bound is what rejects a negative index.
    emit(_make_stack_op(op="opcode", code="OP_DUP"))
    emit(_make_stack_op(op="push", value=_big_int_push(0)))
    emit(_make_stack_op(op="push", value=_big_int_push(1 << depth)))
    emit(_make_stack_op(op="opcode", code="OP_WITHIN"))
    emit(_make_stack_op(op="opcode", code="OP_VERIFY"))

    for i in range(depth):
        # Stack: [current, proof, index]

        # --- Step 1: Extract sibling from proof ---
        # Roll proof to top: swap index and proof
        # Stack: [current, proof, index]
        # After roll(1): [current, index, proof]
        emit(_make_stack_op(op="swap"))

        # Split proof at 32 to get sibling
        # Stack: [current, index, proof]
        emit(_make_stack_op(op="push", value=_big_int_push(32)))
        emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
        # Stack: [current, index, sibling(32B), rest_proof]

        # Move rest_proof out of the way (to alt stack)
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
        # Stack: [current, index, sibling]  Alt: [rest_proof]

        # --- Step 2: Get direction bit ---
        # Bring index to top (it's at depth 1)
        emit(_make_stack_op(op="swap"))
        # Stack: [current, sibling, index]

        # Compute direction bit: (index >> i) & 1
        emit(_make_stack_op(op="opcode", code="OP_DUP"))
        # Stack: [current, sibling, index, index]
        # Extract bit i: Chronicle opcodes: OP_2DIV (i=1), OP_RSHIFTNUM (i>1)
        if i == 1:
            emit(_make_stack_op(op="opcode", code="OP_2DIV"))
        elif i > 1:
            emit(_make_stack_op(op="push", value=_big_int_push(i)))
            emit(_make_stack_op(op="opcode", code="OP_RSHIFTNUM"))
        emit(_make_stack_op(op="push", value=_big_int_push(2)))
        emit(_make_stack_op(op="opcode", code="OP_MOD"))
        # Stack: [current, sibling, index, direction_bit]

        # Move index below for safekeeping
        # Current stack: [current, sibling, index, direction_bit]
        emit(_make_stack_op(op="swap"))
        # Stack: [current, sibling, direction_bit, index]
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
        # Stack: [current, sibling, direction_bit]  Alt: [rest_proof, index]

        # --- Step 3: Conditional swap + concatenate + hash ---
        # Roll current to top:
        emit(_make_stack_op(op="rot"))
        # Stack: [sibling, direction_bit, current]
        emit(_make_stack_op(op="rot"))
        # Stack: [direction_bit, current, sibling]

        # Now: if direction_bit=1, swap current and sibling before CAT
        emit(_make_stack_op(op="rot"))
        # Stack: [current, sibling, direction_bit]

        emit(_make_stack_op(
            op="if",
            then=[
                # direction = 1: want hash(sibling || current), so swap
                _make_stack_op(op="swap"),
            ],
            # direction = 0: want hash(current || sibling), already in order
        ))
        # Stack: [a, b] where a||b is the correct concatenation order

        emit(_make_stack_op(op="opcode", code="OP_CAT"))
        emit(_make_stack_op(op="opcode", code=hash_op))
        # Stack: [new_current]

        # Restore index and rest_proof from alt stack
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        # Stack: [new_current, index]
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        # Stack: [new_current, index, rest_proof]

        # Reorder to [new_current, rest_proof, index]
        emit(_make_stack_op(op="swap"))
        # Stack: [new_current, rest_proof, index]

    # Final stack: [root, empty_proof, index]
    emit(_make_stack_op(op="drop"))   # drop index
    # Stack: [root, rest_proof]

    # R-120: the proof remainder must be EMPTY.
    #
    # Each level OP_SPLITs 32 bytes off the front of the blob; what was left after
    # the last level used to be dropped without ever being looked at, so a proof of
    # 32*depth + k bytes verified for every k >= 0 and produced the same root as the
    # correctly-sized one (measured at depth 2: 64, 65, 96 and 128 bytes all returned
    # 5306f72f...6ee0f336). The SHORT direction was already closed -- OP_SPLIT aborts
    # when the blob runs out.
    emit(_make_stack_op(op="opcode", code="OP_SIZE"))
    emit(_make_stack_op(op="push", value=_big_int_push(0)))
    emit(_make_stack_op(op="opcode", code="OP_NUMEQUALVERIFY"))
    emit(_make_stack_op(op="drop"))   # drop the (now proved empty) proof
    # Stack: [root]
