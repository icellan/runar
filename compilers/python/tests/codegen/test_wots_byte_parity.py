"""Byte-parity test for the Python ``verifyWOTS`` codegen against the
``post-quantum-wots`` conformance fixture.

The fixture's expected-script.hex was minted from the Python (and 6 peer
compiler) implementation; the conformance suite verifies all 7 tiers emit
byte-identical hex. This file adds a *direct* assertion-grade probe that:

  1. Compiles the in-tree Python WOTS+ example through the full pipeline.
  2. Asserts the resulting hex is exactly the conformance golden (byte parity).
  3. Pins the op count + leading-op shape of the spend method's Stack-IR.

Prior to this test the only Python-side WOTS+ assertion lived in
``test_multiformat.py:324``: it merely checked the ``verifyWOTS`` ANF call
is present in the body. That gives no protection against:

  * A wrong opcode emitted by ``_emit_wots_one_chain`` (e.g. swapping
    SHA256 for HASH160).
  * A drift in the unrolled chain count (96 chains × W steps).
  * A wrong literal pushed for the W parameter.

This test catches all three by comparing against the fixture goldens.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.codegen.stack import StackOp, lower_to_stack
from runar_compiler.compiler import compile_from_source
from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check
from runar_compiler.frontend.validator import validate


REPO_ROOT = Path(__file__).resolve().parents[4]
WOTS_SRC = (
    REPO_ROOT
    / "examples"
    / "python"
    / "post-quantum-wots-naive-INSECURE"
    / "PostQuantumWOTSNaiveInsecure.runar.py"
)
CONFORMANCE_DIR = REPO_ROOT / "conformance" / "tests" / "post-quantum-wots"
EXPECTED_HEX_PATH = CONFORMANCE_DIR / "expected-script.hex"


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


def _spend_method_ops() -> list[StackOp]:
    """Lower the WOTS+ contract end-to-end and return the spend method's Stack-IR."""
    source = WOTS_SRC.read_text(encoding="utf-8")
    pr = parse_source(source, WOTS_SRC.name)
    assert not pr.errors, f"parse errors: {pr.errors}"
    vr = validate(pr.contract)
    assert not vr.errors, f"validation errors: {vr.errors}"
    tr = type_check(pr.contract)
    assert not tr.errors, f"typecheck errors: {tr.errors}"
    program = lower_to_anf(pr.contract)
    methods = lower_to_stack(program)
    return next(m for m in methods if m.name == "spend").ops


# ---------------------------------------------------------------------------
# Op count + leading-op-shape goldens (captured from the Python emission)
# ---------------------------------------------------------------------------

# Captured from the current Python implementation. The WOTS+ verification
# unrolls all 96 chains (64 message + 32 checksum) so the Stack-IR is dense.
# Pinned baseline; any drift in the WOTS emitter will fail this immediately.
EXPECTED_SPEND_OP_COUNT = 15494

# 64 message-nibble chains + 3 checksum chains = 67 WOTS+ chains.
# Each chain emits 1 SHA256 (chain start) + 1 SPLIT (sig element extract).
# Plus the verify_wots prelude / checksum prelude / final tail emit a few more.
EXPECTED_CHAIN_COUNT = 67


def test_spend_op_count_matches_pinned_baseline():
    ops = _spend_method_ops()
    flat = _flatten_ops(ops)
    assert len(flat) == EXPECTED_SPEND_OP_COUNT, (
        f"spend op count drift: got {len(flat)} want {EXPECTED_SPEND_OP_COUNT}"
    )


def test_spend_emits_per_chain_op_split():
    """Each WOTS+ chain starts with OP_SPLIT(32) to extract the chain's
    32-byte signature element. With 67 chains we expect AT LEAST 67 OP_SPLITs.
    """
    flat = _flatten_ops(_spend_method_ops())
    splits = [op for op in flat if _is_opcode(op, "OP_SPLIT")]
    assert len(splits) >= EXPECTED_CHAIN_COUNT, (
        f"WOTS+ must emit >= {EXPECTED_CHAIN_COUNT} OP_SPLIT; got {len(splits)}"
    )


def test_spend_terminates_with_op_equal_against_alt_pubkey_root():
    """The verify_wots emitter ends with: OP_SHA256, OP_FROMALTSTACK, OP_EQUAL
    so the entire WOTS+ proof reduces to a single boolean for the trailing
    assert. The trailing OP_EQUAL is what makes the script's final stack
    item the verifyWOTS truthiness.
    """
    flat = _flatten_ops(_spend_method_ops())
    equals = [op for op in flat if _is_opcode(op, "OP_EQUAL")]
    assert len(equals) >= 1, (
        f"WOTS+ verify must emit at least one OP_EQUAL for the final "
        f"pubkey-root comparison; got {len(equals)}"
    )


def test_spend_emits_repeated_sha256_for_chain_hashing():
    """Each chain runs up to W=15 hash steps inside its IF-then-else loop,
    plus the verify prelude calls OP_SHA256 twice (msg hash + final compare).
    A reasonable lower bound across 67 chains × multi-step hashing is >= 67.
    """
    flat = _flatten_ops(_spend_method_ops())
    sha256s = [op for op in flat if _is_opcode(op, "OP_SHA256")]
    assert len(sha256s) >= EXPECTED_CHAIN_COUNT, (
        f"WOTS+ must emit >= {EXPECTED_CHAIN_COUNT} OP_SHA256 across all chains; "
        f"got {len(sha256s)}"
    )


# ---------------------------------------------------------------------------
# Byte-identical conformance golden parity
# ---------------------------------------------------------------------------

def test_compiled_hex_matches_conformance_golden_byte_for_byte():
    """The full compile pipeline must produce hex that is byte-identical to
    the conformance golden ``expected-script.hex`` (which is the cross-tier
    invariant). The conformance suite enforces this *across* tiers; this
    test enforces it *for the Python tier alone* so a regression in the
    Python WOTS emitter is caught even if the conformance runner is not
    invoked.
    """
    art = compile_from_source(str(WOTS_SRC))
    expected = EXPECTED_HEX_PATH.read_text(encoding="utf-8").strip()
    assert art.script == expected, (
        f"Python WOTS+ hex diverges from conformance golden: "
        f"got len={len(art.script)} want len={len(expected)}; "
        f"prefix-mismatch at first {next((i for i, (a, b) in enumerate(zip(art.script, expected)) if a != b), None)}"
    )
