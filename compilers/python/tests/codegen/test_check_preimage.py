"""Op-shape parity tests for the Python ``check_preimage`` lowering.

``check_preimage`` is the OP_PUSH_TX trick — it verifies that the spending
transaction matches a developer-supplied BIP-143 preimage by:

  1. OP_CODESEPARATOR (so the scriptCode in the preimage is short)
  2. push compressed secp256k1 generator G (33 bytes, prefix 0x02)
  3. OP_CHECKSIGVERIFY against an implicit ``_opPushTxSig``

For ``StatefulSmartContract`` subclasses the ANF lower auto-injects a
checkPreimage call at every public method entry. This test verifies both:

  * Auto-injection: a stateful contract's increment method emits the
    OP_CODESEPARATOR + G push + OP_CHECKSIGVERIFY signature.
  * No injection: a stateless contract's method does NOT carry the same
    pattern (no OP_CODESEPARATOR, no compressed-G push).

The probes drive the lowering through real Python source so the auto-
injection flow is exercised end-to-end.
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
COUNTER_SRC = REPO_ROOT / "examples" / "python" / "stateful-counter" / "Counter.runar.py"
P2PKH_SRC = REPO_ROOT / "examples" / "python" / "p2pkh" / "P2PKH.runar.py"


# Compressed secp256k1 generator G (33 bytes) -- pushed verbatim by
# _lower_check_preimage in stack.py.
_COMPRESSED_G = bytes([
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
    0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
    0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
])


def _lower_source(path: Path) -> list[StackMethod]:
    source = path.read_text(encoding="utf-8")
    pr = parse_source(source, path.name)
    assert not pr.errors, f"parse errors: {pr.errors}"
    vr = validate(pr.contract)
    assert not vr.errors, f"validation errors: {vr.errors}"
    tr = type_check(pr.contract)
    assert not tr.errors, f"typecheck errors: {tr.errors}"
    program = lower_to_anf(pr.contract)
    return lower_to_stack(program)


def _is_opcode(op: StackOp, code: str) -> bool:
    return op.op == "opcode" and op.code == code


def _flatten_ops(ops: list[StackOp]) -> list[StackOp]:
    out: list[StackOp] = []
    for op in ops:
        out.append(op)
        if op.op == "if":
            out.extend(_flatten_ops(op.then))
            out.extend(_flatten_ops(op.else_ops))
    return out


def _is_push_compressed_g(op: StackOp) -> bool:
    return (
        op.op == "push"
        and op.value is not None
        and op.value.kind == "bytes"
        and op.value.bytes_val == _COMPRESSED_G
    )


# ---------------------------------------------------------------------------
# Auto-injection: stateful contract MUST emit the checkPreimage triple
# ---------------------------------------------------------------------------

def test_stateful_increment_emits_op_codeseparator():
    """Stateful contracts auto-inject OP_CODESEPARATOR at the start of the
    OP_PUSH_TX flow. This is the load-bearing first opcode.
    """
    methods = _lower_source(COUNTER_SRC)
    inc = next(m for m in methods if m.name == "increment")
    flat = _flatten_ops(inc.ops)
    code_seps = [op for op in flat if _is_opcode(op, "OP_CODESEPARATOR")]
    assert len(code_seps) == 1, (
        f"stateful increment must auto-inject exactly 1 OP_CODESEPARATOR; "
        f"got {len(code_seps)}"
    )


def test_stateful_increment_pushes_compressed_secp256k1_generator():
    """The OP_PUSH_TX trick pushes the 33-byte compressed secp256k1 generator
    point G as the public key for OP_CHECKSIGVERIFY.
    """
    methods = _lower_source(COUNTER_SRC)
    inc = next(m for m in methods if m.name == "increment")
    flat = _flatten_ops(inc.ops)
    g_pushes = [op for op in flat if _is_push_compressed_g(op)]
    assert len(g_pushes) == 1, (
        f"stateful increment must push compressed-G exactly once; "
        f"got {len(g_pushes)}"
    )


def test_stateful_increment_emits_op_checksigverify():
    """checkPreimage emits OP_CHECKSIGVERIFY (not plain CHECKSIG) so a failure
    aborts the script.
    """
    methods = _lower_source(COUNTER_SRC)
    inc = next(m for m in methods if m.name == "increment")
    flat = _flatten_ops(inc.ops)
    csv = [op for op in flat if _is_opcode(op, "OP_CHECKSIGVERIFY")]
    assert len(csv) == 1, (
        f"stateful increment must emit exactly 1 OP_CHECKSIGVERIFY; got {len(csv)}"
    )


def test_stateful_decrement_also_auto_injects():
    """Auto-injection happens at EVERY public method entry, not just the first."""
    methods = _lower_source(COUNTER_SRC)
    dec = next(m for m in methods if m.name == "decrement")
    flat = _flatten_ops(dec.ops)
    assert any(_is_opcode(op, "OP_CODESEPARATOR") for op in flat)
    assert any(_is_push_compressed_g(op) for op in flat)
    assert any(_is_opcode(op, "OP_CHECKSIGVERIFY") for op in flat)


def test_stateful_increment_check_preimage_triple_in_order():
    """Verify the canonical ordering: OP_CODESEPARATOR ... compressed-G push
    ... OP_CHECKSIGVERIFY. Indices must be monotonic.
    """
    methods = _lower_source(COUNTER_SRC)
    inc = next(m for m in methods if m.name == "increment")
    flat = _flatten_ops(inc.ops)

    cs_idx = next(i for i, op in enumerate(flat) if _is_opcode(op, "OP_CODESEPARATOR"))
    g_idx = next(i for i, op in enumerate(flat) if _is_push_compressed_g(op))
    csv_idx = next(i for i, op in enumerate(flat) if _is_opcode(op, "OP_CHECKSIGVERIFY"))

    assert cs_idx < g_idx < csv_idx, (
        f"checkPreimage triple out of order: "
        f"OP_CODESEPARATOR={cs_idx}, G_push={g_idx}, OP_CHECKSIGVERIFY={csv_idx}"
    )


# ---------------------------------------------------------------------------
# Negative: stateless contract must NOT emit the checkPreimage triple
# ---------------------------------------------------------------------------

def test_stateless_p2pkh_does_not_auto_inject_check_preimage():
    """SmartContract subclasses (no state) do not auto-inject checkPreimage.
    The classical P2PKH unlock must therefore not contain the OP_PUSH_TX
    pattern (no OP_CODESEPARATOR + compressed-G push + OP_CHECKSIGVERIFY).
    """
    methods = _lower_source(P2PKH_SRC)
    unlock = next(m for m in methods if m.name == "unlock")
    flat = _flatten_ops(unlock.ops)
    code_seps = [op for op in flat if _is_opcode(op, "OP_CODESEPARATOR")]
    g_pushes = [op for op in flat if _is_push_compressed_g(op)]
    assert len(code_seps) == 0, (
        f"stateless contract must NOT auto-inject OP_CODESEPARATOR; got {len(code_seps)}"
    )
    assert len(g_pushes) == 0, (
        f"stateless contract must NOT push compressed-G; got {len(g_pushes)}"
    )
