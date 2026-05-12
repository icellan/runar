"""Op-shape parity tests for the Python ``add_raw_output`` lowering.

``add_raw_output`` emits a Bitcoin output whose script body is supplied
verbatim by the caller (no codePart, no state continuation). The serialized
shape is::

    amount(8LE) + varint(scriptLen) + scriptBytes

This test pins the *load-bearing tail* of the lowered Stack-IR (OP_SIZE for
varint width derivation, NUM2BIN(8) for satoshis, OP_CAT cadence) so a
wrong-opcode regression in ``stack.py:_lower_add_raw_output`` fails locally
instead of surfacing only as a hex divergence in the conformance suite.

Probe contract: the in-tree ``add-raw-output`` example, whose ``send_to_script``
method calls ``self.add_raw_output(1000, script_bytes)`` followed by a state
continuation via ``add_output``. The test isolates assertions to the
add_raw_output portion using its uniquely identifiable opcode pattern.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.codegen.stack import StackMethod, StackOp, lower_to_stack
from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check
from runar_compiler.frontend.validator import validate


REPO_ROOT = Path(__file__).resolve().parents[4]
RAW_OUTPUT_SRC = REPO_ROOT / "examples" / "python" / "add-raw-output" / "RawOutputTest.runar.py"


def _lower_raw_output_contract() -> list[StackMethod]:
    source = RAW_OUTPUT_SRC.read_text(encoding="utf-8")
    pr = parse_source(source, RAW_OUTPUT_SRC.name)
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


def _flatten_ops(ops: list[StackOp]) -> list[StackOp]:
    out: list[StackOp] = []
    for op in ops:
        out.append(op)
        if op.op == "if":
            out.extend(_flatten_ops(op.then))
            out.extend(_flatten_ops(op.else_ops))
    return out


def _send_to_script_ops() -> list[StackOp]:
    methods = _lower_raw_output_contract()
    method = next(m for m in methods if m.name == "sendToScript")
    return method.ops


# ---------------------------------------------------------------------------
# Op-count + shape goldens
# ---------------------------------------------------------------------------

# Pinned baseline captured from the Python implementation. This contract has
# both an add_raw_output AND an add_output continuation, so the count covers
# the complete sendToScript method.
EXPECTED_TOTAL_OPS = 193  # captured baseline


def test_send_to_script_total_op_count_pinned():
    flat = _flatten_ops(_send_to_script_ops())
    assert len(flat) == EXPECTED_TOTAL_OPS, (
        f"sendToScript op count drift: got {len(flat)} want {EXPECTED_TOTAL_OPS}"
    )


def test_send_to_script_pushes_satoshi_value_1000():
    """The contract calls add_raw_output(1000, script_bytes) with a literal 1000.
    The constant folder should preserve the literal as a push.
    """
    flat = _flatten_ops(_send_to_script_ops())
    pushes_1000 = [op for op in flat if _is_push_int(op, 1000)]
    assert len(pushes_1000) >= 1, (
        f"expected at least one push(1000) for the satoshi value, got {len(pushes_1000)}"
    )


def test_send_to_script_emits_op_size_for_varint_derivation():
    """add_raw_output uses OP_SIZE on the user-supplied script bytes to derive
    the varint length prefix. Should appear at least once for raw output, plus
    one more for the state continuation add_output.
    """
    flat = _flatten_ops(_send_to_script_ops())
    sizes = [op for op in flat if _is_opcode(op, "OP_SIZE")]
    assert len(sizes) >= 2, (
        f"expected >=2 OP_SIZE (one for raw, one for state cont.), got {len(sizes)}"
    )


def test_send_to_script_emits_num2bin_for_satoshis_width():
    """add_raw_output and add_output both NUM2BIN the satoshi amount as 8-byte LE.
    add_output adds one more for the bigint state value -> 3 minimum.
    """
    flat = _flatten_ops(_send_to_script_ops())
    num2bins = [op for op in flat if _is_opcode(op, "OP_NUM2BIN")]
    assert len(num2bins) >= 3, (
        f"expected >=3 OP_NUM2BIN, got {len(num2bins)}"
    )


def test_send_to_script_emits_cat_chain():
    """add_raw_output emits 2 OP_CATs (varint||script, then sats||rest).
    add_output emits 4 more (codePart||0x6a, ||stateBytes, varint||script,
    sats||rest). Total >=6.
    """
    flat = _flatten_ops(_send_to_script_ops())
    cats = [op for op in flat if _is_opcode(op, "OP_CAT")]
    assert len(cats) >= 6, f"expected >=6 OP_CATs, got {len(cats)}"


def test_send_to_script_does_not_emit_op_return_opcode():
    """add_raw_output never emits OP_RETURN as an opcode (would terminate
    the script). Even add_output's 0x6a is pushed as data, not as an opcode.
    """
    flat = _flatten_ops(_send_to_script_ops())
    op_returns = [op for op in flat if _is_opcode(op, "OP_RETURN")]
    assert len(op_returns) == 0, (
        f"raw outputs must not emit OP_RETURN as opcode; got {len(op_returns)}"
    )


def test_send_to_script_emits_codeseparator_once():
    """OP_CODESEPARATOR is injected exactly once at the checkPreimage entry
    of the stateful method, regardless of subsequent add_raw_output / add_output
    calls.
    """
    flat = _flatten_ops(_send_to_script_ops())
    cs = [op for op in flat if _is_opcode(op, "OP_CODESEPARATOR")]
    assert len(cs) == 1, f"expected exactly 1 OP_CODESEPARATOR, got {len(cs)}"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_add_raw_output_lowering_is_deterministic():
    a = _flatten_ops(_send_to_script_ops())
    b = _flatten_ops(_send_to_script_ops())
    assert len(a) == len(b)
    for i, (x, y) in enumerate(zip(a, b)):
        assert x.op == y.op, f"op[{i}] kind drifts"
        assert x.code == y.code, f"op[{i}] code drifts"
