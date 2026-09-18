"""Op-shape parity tests for the Python ``check_preimage`` lowering.

``check_preimage`` is the OP_PUSH_TX trick — it verifies that the spending
transaction matches a developer-supplied BIP-143 preimage.

BUG-100 fix: the ECDSA signature is now DERIVED FROM THE PREIMAGE ON CHAIN
(Optimal OP_PUSH_TX) rather than supplied as a witness item and checked against
G. The derivation compiles to a FIXED opcode blob (identical across all seven
tiers) emitted as a single opaque ``raw_bytes`` op. So the lowering is:

  1. bring the preimage to the top (kept for field extractors)
  2. one ``raw_bytes`` op carrying the canonical binding construction — this
     internally re-derives the signature from hash256(preimage) and runs
     OP_CHECKSIGVERIFY against G. There is NO discrete compressed-G push and NO
     discrete OP_CHECKSIGVERIFY opcode any more; both live inside the blob.
  3. the R-010 ``_codePart`` authentication (only when the method carries the
     ``_codePart`` witness), which rebuilds the code part from the now-authentic
     ``scriptCode`` and OP_EQUALVERIFYs it against the spender's copy.

R-010 removed the OP_CODESEPARATOR that used to head this sequence: a
per-method separator hid the dispatch preamble and every preceding method body
from ``scriptCode``, and those are exactly the bytes ``_codePart`` claims to
reproduce. The emitter now places one separator at offset 1 of the whole
locking script instead.

For ``StatefulSmartContract`` subclasses the ANF lower auto-injects a
checkPreimage call at every public method entry. This test verifies both:

  * Auto-injection: a stateful contract's increment method emits the canonical
    binding ``raw_bytes`` blob.
  * No injection: a stateless contract's method does NOT carry the same
    pattern (no binding blob).

The probes drive the lowering through real Python source so the auto-
injection flow is exercised end-to-end.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.codegen.stack import (
    StackMethod,
    StackOp,
    lower_to_stack,
    _CHECK_PREIMAGE_BINDING_HEX,
)
from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check
from runar_compiler.frontend.validator import validate


REPO_ROOT = Path(__file__).resolve().parents[4]
COUNTER_SRC = REPO_ROOT / "examples" / "python" / "stateful-counter" / "Counter.runar.py"
P2PKH_SRC = REPO_ROOT / "examples" / "python" / "p2pkh" / "P2PKH.runar.py"


# The canonical on-chain preimage-binding construction (BUG-100 fix). Emitted as
# a single opaque raw_bytes op by _lower_check_preimage in stack.py.
_BINDING_BYTES = bytes.fromhex(_CHECK_PREIMAGE_BINDING_HEX)


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


def _is_binding_blob(op: StackOp) -> bool:
    return op.op == "raw_bytes" and op.raw_bytes == _BINDING_BYTES


# ---------------------------------------------------------------------------
# Auto-injection: stateful contract MUST emit the checkPreimage sequence
# ---------------------------------------------------------------------------

def test_stateful_increment_emits_no_per_method_codeseparator():
    """R-010: no OP_CODESEPARATOR inside a method's ops.

    The separator is emitted once by the emitter, at offset 1 of the whole
    locking script, so that ``scriptCode`` covers the dispatch preamble and
    every method body — which is what makes the spender-supplied ``_codePart``
    authenticatable at all. ``lower_to_stack`` sets ``needs_code_separator`` to
    tell the emitter a separator is needed.
    """
    methods = _lower_source(COUNTER_SRC)
    inc = next(m for m in methods if m.name == "increment")
    flat = _flatten_ops(inc.ops)
    code_seps = [op for op in flat if _is_opcode(op, "OP_CODESEPARATOR")]
    assert len(code_seps) == 0, (
        f"stateful increment must not carry a per-method OP_CODESEPARATOR; "
        f"got {len(code_seps)}"
    )
    assert inc.needs_code_separator, (
        "stateful increment must flag needs_code_separator so the emitter "
        "places the script-level separator"
    )


def test_stateful_increment_emits_binding_blob():
    """The OP_PUSH_TX trick derives the signature from the preimage on-chain via
    a single opaque raw_bytes op carrying the canonical binding construction
    (BUG-100 fix). It replaces the old discrete compressed-G push +
    OP_CHECKSIGVERIFY sequence.
    """
    methods = _lower_source(COUNTER_SRC)
    inc = next(m for m in methods if m.name == "increment")
    flat = _flatten_ops(inc.ops)
    blobs = [op for op in flat if _is_binding_blob(op)]
    assert len(blobs) == 1, (
        f"stateful increment must emit the binding blob exactly once; "
        f"got {len(blobs)}"
    )
    # The blob declares net-zero stack effect (preimage in -> preimage out).
    assert blobs[0].in_arity == 1 and blobs[0].out_arity == 1


def test_stateful_increment_has_no_discrete_checksig_or_g_push():
    """After the fix the signature check lives INSIDE the opaque binding blob;
    there must be no discrete OP_CHECKSIGVERIFY opcode and no discrete
    compressed-G push in the checkPreimage flow.
    """
    methods = _lower_source(COUNTER_SRC)
    inc = next(m for m in methods if m.name == "increment")
    flat = _flatten_ops(inc.ops)
    assert not any(_is_opcode(op, "OP_CHECKSIGVERIFY") for op in flat), (
        "checkPreimage must not emit a discrete OP_CHECKSIGVERIFY opcode"
    )
    assert not any(_is_opcode(op, "OP_CHECKSIG") for op in flat), (
        "checkPreimage must not emit a discrete OP_CHECKSIG opcode"
    )


def test_stateful_decrement_also_auto_injects():
    """Auto-injection happens at EVERY public method entry, not just the first."""
    methods = _lower_source(COUNTER_SRC)
    dec = next(m for m in methods if m.name == "decrement")
    flat = _flatten_ops(dec.ops)
    assert not any(_is_opcode(op, "OP_CODESEPARATOR") for op in flat)
    assert dec.needs_code_separator
    assert any(_is_binding_blob(op) for op in flat)


def test_stateful_increment_authenticates_code_part_after_binding():
    """R-010 ordering: the ``_codePart`` authentication must come AFTER the
    binding blob.

    The authentication reads ``scriptCode`` out of the preimage, so it is only
    sound once the blob has proven that preimage belongs to this transaction.
    The authentication's tail is ``push <61ab>``, the prologue-byte pin.
    """
    methods = _lower_source(COUNTER_SRC)
    inc = next(m for m in methods if m.name == "increment")
    flat = _flatten_ops(inc.ops)

    blob_idx = next(i for i, op in enumerate(flat) if _is_binding_blob(op))
    pin_idx = next(
        i for i, op in enumerate(flat)
        if op.op == "push" and getattr(op.value, "bytes_val", None) == bytes([0x61, 0xAB])
    )

    assert blob_idx < pin_idx, (
        f"_codePart authentication must follow the binding blob: "
        f"binding_blob={blob_idx}, prologue_pin={pin_idx}"
    )


# ---------------------------------------------------------------------------
# Negative: stateless contract must NOT emit the checkPreimage sequence
# ---------------------------------------------------------------------------

def test_stateless_p2pkh_does_not_auto_inject_check_preimage():
    """SmartContract subclasses (no state) do not auto-inject checkPreimage.
    The classical P2PKH unlock must therefore not contain the OP_PUSH_TX
    pattern (no binding blob).
    """
    methods = _lower_source(P2PKH_SRC)
    unlock = next(m for m in methods if m.name == "unlock")
    flat = _flatten_ops(unlock.ops)
    code_seps = [op for op in flat if _is_opcode(op, "OP_CODESEPARATOR")]
    blobs = [op for op in flat if _is_binding_blob(op)]
    assert len(code_seps) == 0, (
        f"stateless contract must NOT auto-inject OP_CODESEPARATOR; got {len(code_seps)}"
    )
    assert len(blobs) == 0, (
        f"stateless contract must NOT emit the checkPreimage binding blob; "
        f"got {len(blobs)}"
    )
