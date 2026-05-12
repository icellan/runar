"""Op-shape parity tests for the Python ``add_output`` lowering.

``add_output`` is the multi-output stateful continuation intrinsic; it builds
a full BIP-143 output serialization::

    amount(8LE) + varint(scriptLen) + codePart + OP_RETURN(0x6a) + stateBytes

This test pins the *load-bearing tail* of the lowered Stack-IR (OP_RETURN
byte push, OP_NUM2BIN width, OP_CAT cadence) so a wrong-opcode regression in
``stack.py:_lower_add_output`` fails locally instead of surfacing only as a
hex divergence in the conformance suite.

The probe compiles the in-tree ``stateful-counter`` example (a 1-state-property
stateful contract whose `increment` method exercises a single `add_output`
continuation) and asserts on the resulting Stack-IR shape for the increment
method.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.codegen.stack import StackMethod, StackOp, lower_to_stack
from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check
from runar_compiler.frontend.validator import validate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[4]
COUNTER_SRC = REPO_ROOT / "examples" / "python" / "stateful-counter" / "Counter.runar.py"


def _lower_counter() -> list[StackMethod]:
    """Parse + validate + typecheck + lower the stateful-counter example.

    The compiler's standard ``lower_to_stack`` injects ``_codePart`` and
    ``_opPushTxSig`` implicit params at the base of the stack for stateful
    methods, so ``add_output`` finds ``_codePart`` already present.
    """
    source = COUNTER_SRC.read_text(encoding="utf-8")
    pr = parse_source(source, COUNTER_SRC.name)
    assert not pr.errors, f"parse errors: {pr.errors}"
    vr = validate(pr.contract)
    assert not vr.errors, f"validation errors: {vr.errors}"
    tr = type_check(pr.contract)
    assert not tr.errors, f"typecheck errors: {tr.errors}"
    program = lower_to_anf(pr.contract)
    return lower_to_stack(program)


def _is_opcode(op: StackOp, code: str) -> bool:
    return op.op == "opcode" and op.code == code


def _is_push_int(op: StackOp, n: int) -> bool:
    return (
        op.op == "push"
        and op.value is not None
        and op.value.kind == "bigint"
        and op.value.big_int == n
    )


def _is_push_bytes(op: StackOp, b: bytes) -> bool:
    return (
        op.op == "push"
        and op.value is not None
        and op.value.kind == "bytes"
        and op.value.bytes_val == b
    )


def _flatten_ops(ops: list[StackOp]) -> list[StackOp]:
    """Recursively flatten if-then-else branches into a single op stream."""
    out: list[StackOp] = []
    for op in ops:
        out.append(op)
        if op.op == "if":
            out.extend(_flatten_ops(op.then))
            out.extend(_flatten_ops(op.else_ops))
    return out


def _increment_ops() -> list[StackOp]:
    methods = _lower_counter()
    inc = next(m for m in methods if m.name == "increment")
    return inc.ops


# ---------------------------------------------------------------------------
# Op-count + characteristic-opcode count goldens
# ---------------------------------------------------------------------------

def test_increment_emits_op_return_byte_push():
    """add_output appends 0x6a (OP_RETURN-as-data) once into the script body
    via a literal byte push, NOT via OP_RETURN opcode emission.
    """
    flat = _flatten_ops(_increment_ops())
    return_byte_pushes = [op for op in flat if _is_push_bytes(op, bytes([0x6A]))]
    assert len(return_byte_pushes) == 1, (
        f"expected exactly one push of bytes(0x6a), got {len(return_byte_pushes)}"
    )


def test_increment_does_not_emit_op_return_opcode():
    """OP_RETURN must NEVER appear as an opcode (would terminate the script).
    The 0x6a byte must always be pushed as data.
    """
    flat = _flatten_ops(_increment_ops())
    op_returns = [op for op in flat if _is_opcode(op, "OP_RETURN")]
    assert len(op_returns) == 0, (
        f"add_output must not emit OP_RETURN as an opcode; got {len(op_returns)}"
    )


def test_increment_emits_op_size_for_varint_length():
    """The output script length is computed via OP_SIZE before the varint
    encoding routine wraps it.
    """
    flat = _flatten_ops(_increment_ops())
    sizes = [op for op in flat if _is_opcode(op, "OP_SIZE")]
    assert len(sizes) >= 1, f"expected >=1 OP_SIZE, got {len(sizes)}"


def test_increment_emits_num2bin_for_satoshis_and_state():
    """add_output emits NUM2BIN for both:
       - 8-byte LE state value (1x for the bigint count field)
       - 8-byte LE satoshi amount
    Plus the deserialize_state path emits one for state extraction.
    """
    flat = _flatten_ops(_increment_ops())
    num2bins = [op for op in flat if _is_opcode(op, "OP_NUM2BIN")]
    assert len(num2bins) >= 2, (
        f"expected >=2 OP_NUM2BIN, got {len(num2bins)}"
    )


def test_increment_emits_op_cat_for_concatenation():
    """add_output stitches the output via repeated OP_CAT calls."""
    flat = _flatten_ops(_increment_ops())
    cats = [op for op in flat if _is_opcode(op, "OP_CAT")]
    assert len(cats) >= 4, f"expected >=4 OP_CATs, got {len(cats)}"


def test_increment_emits_op_codeseparator():
    """Stateful methods inject OP_CODESEPARATOR at the start of the
    checkPreimage flow so scriptCode in the BIP-143 preimage is reduced.
    add_output runs after that.
    """
    flat = _flatten_ops(_increment_ops())
    cs = [op for op in flat if _is_opcode(op, "OP_CODESEPARATOR")]
    assert len(cs) == 1, f"expected exactly 1 OP_CODESEPARATOR, got {len(cs)}"


def test_increment_pushes_8_for_satoshis_and_state_widths():
    """Both the bigint state value and the satoshi amount are NUM2BIN'd at
    width 8. Verify the literal 8 push appears at least twice.
    """
    flat = _flatten_ops(_increment_ops())
    eights = [op for op in flat if _is_push_int(op, 8)]
    assert len(eights) >= 2, f"expected >=2 push(8), got {len(eights)}"


# ---------------------------------------------------------------------------
# Op-count golden -- pinned baseline captured from this Python implementation
# ---------------------------------------------------------------------------

# These counts pin the precise shape of the lowering. Update only if the
# stateful-counter contract or add_output codegen changes intentionally.
EXPECTED_INCREMENT_TOTAL_OPS = 134  # captured from current emission

def test_increment_total_op_count_pinned():
    flat = _flatten_ops(_increment_ops())
    assert len(flat) == EXPECTED_INCREMENT_TOTAL_OPS, (
        f"increment total flattened op count drift: "
        f"got {len(flat)} want {EXPECTED_INCREMENT_TOTAL_OPS}"
    )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_add_output_lowering_is_deterministic():
    a = _flatten_ops(_increment_ops())
    b = _flatten_ops(_increment_ops())
    assert len(a) == len(b)
    for i, (x, y) in enumerate(zip(a, b)):
        assert x.op == y.op, f"op[{i}] kind drifts"
        assert x.code == y.code, f"op[{i}] code drifts"
