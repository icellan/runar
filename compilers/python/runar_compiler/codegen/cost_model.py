"""Script-byte cost model for Stack IR.

Port of ``packages/runar-compiler/src/metrics/cost-model.ts``. Optimizer passes
need to compare two candidate lowerings by the metric that actually matters --
serialized locking-script bytes -- before either one is emitted. ``OP_DUP`` and
a 33-byte constant push are one instruction each and 1 vs 34 bytes; an
instruction count cannot tell them apart.

This is deliberately NOT an approximation: every push routes through the same
encoders ``emit.py`` uses, so::

    estimate_script_bytes(ops) == len(emit_method(...).script_hex) // 2

holds exactly. ``test_cost_model.py`` asserts that over every crypto emitter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import PushValue, StackOp


def size_of_push_value(value: "PushValue") -> int:
    """Serialized byte cost of a single push value.

    Mirrors ``encode_push_value`` in ``emit.py``: booleans are the 1-byte
    OP_TRUE / OP_FALSE, integers go through the small-int opcodes where
    possible, and byte strings are MINIMALDATA-aware before falling back to a
    length-prefixed push.
    """
    from runar_compiler.codegen.emit import encode_push_value

    hex_str, _ = encode_push_value(value)
    return len(hex_str) // 2


def size_of_push_int(n: int) -> int:
    """``size_of_push_value`` for a bare integer.

    This is what the constant pool and the comb width search compare against.
    """
    from runar_compiler.codegen.stack import big_int_push

    return size_of_push_value(big_int_push(n))


def size_of_stack_op(op: "StackOp") -> int:
    """Serialized byte cost of one Stack IR operation, including nested arms.

    Note on ``pick`` / ``roll``: they cost ONE byte here. The depth operand is a
    separate ``push`` op that the tracker emits immediately before, so charging
    the depth here would double-count it.

    Raises on an unknown opcode mnemonic rather than costing it zero -- a typo
    in a codegen module should surface loudly, not as a cost model that quietly
    under-reports.
    """
    from runar_compiler.codegen.emit import OPCODES

    kind = op.op
    if kind == "push":
        return size_of_push_value(op.value)

    if kind in ("dup", "swap", "roll", "pick", "drop", "nip", "over", "rot", "tuck"):
        return 1

    if kind == "opcode":
        if OPCODES.get(op.code) is None:
            raise RuntimeError(f"cost-model: unknown opcode '{op.code}'")
        return 1

    if kind == "if":
        # OP_IF + then + [OP_ELSE + else] + OP_ENDIF. The emitter writes
        # OP_ELSE only for a NON-EMPTY else arm.
        total = 2
        total += estimate_script_bytes(op.then or [])
        if op.else_ops:
            total += 1 + estimate_script_bytes(op.else_ops)
        return total

    if kind in ("placeholder", "push_codesep_index"):
        # Both emit a single 0x00 byte that the SDK rewrites later.
        return 1

    if kind == "raw_bytes":
        return len(op.raw_bytes or b"")

    raise RuntimeError(f"cost-model: unknown stack op kind '{kind}'")


def estimate_script_bytes(ops: list["StackOp"]) -> int:
    """Serialized byte cost of a Stack IR sequence."""
    return sum(size_of_stack_op(op) for op in ops)
