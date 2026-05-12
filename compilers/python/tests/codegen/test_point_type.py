"""Verifies the Python compiler's stack-layout treatment of the ``Point``
and ``RabinSig`` (& ``RabinPubKey``) types.

These three types are special among the 14 supported state-field types:

  * ``Point``       -- 64-byte fixed-width ByteString (x[32] || y[32]),
                       classified as a fixed-length state type (uses plain
                       OP_SPLIT(64) at deserialize, no OP_BIN2NUM tail).
  * ``RabinSig``    -- bigint alias (8-byte script-number layout, NUMERIC).
  * ``RabinPubKey`` -- bigint alias (same as RabinSig).

This test pins both:

  1. Their classification via ``is_numeric_state_type`` /
     ``is_variable_length_state_type`` -- the helpers in stack.py:62 and 67
     that drive deserialize-state codegen.
  2. End-to-end -- compiling the in-tree ``ec-primitives`` example exercises
     ``Point`` as a readonly constructor parameter and the lowering must
     succeed without crashing on the type.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.codegen.stack import (
    StackOp,
    is_numeric_state_type,
    is_variable_length_state_type,
    lower_to_stack,
)
from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check
from runar_compiler.frontend.validator import validate


REPO_ROOT = Path(__file__).resolve().parents[4]
EC_SRC = REPO_ROOT / "examples" / "python" / "ec-primitives" / "ECPrimitives.runar.py"


# ---------------------------------------------------------------------------
# Type classification (the helpers that drive deserialize-state codegen)
# ---------------------------------------------------------------------------

def test_point_is_not_numeric_state_type():
    """Point is a 64-byte fixed-width byte string, NOT a script number.
    Classifying it as numeric would emit a spurious OP_BIN2NUM at deserialize.
    """
    assert is_numeric_state_type("Point") is False


def test_point_is_not_variable_length_state_type():
    """Point has a fixed 64-byte width, so deserialize must use OP_SPLIT(64),
    not the variable-length push-data decode path.
    """
    assert is_variable_length_state_type("Point") is False


def test_rabin_sig_is_numeric_state_type():
    """RabinSig is a bigint alias -- 8-byte script-number layout in state.
    Classifying it as a byte string would skip the OP_BIN2NUM at deserialize
    and the state value would round-trip wrong.
    """
    assert is_numeric_state_type("RabinSig") is True


def test_rabin_sig_is_not_variable_length():
    assert is_variable_length_state_type("RabinSig") is False


def test_rabin_pub_key_is_numeric_state_type():
    """RabinPubKey is also a bigint alias (same 8-byte layout as RabinSig)."""
    assert is_numeric_state_type("RabinPubKey") is True


def test_rabin_pub_key_is_not_variable_length():
    assert is_variable_length_state_type("RabinPubKey") is False


def test_unrelated_types_classification_for_contrast():
    """Sanity-check the negation: a few well-known types from the same enum
    must classify correctly, so the test is asserting the actual table not
    the tautology ``True is True``.
    """
    # bigint is numeric, not variable.
    assert is_numeric_state_type("bigint") is True
    assert is_variable_length_state_type("bigint") is False
    # ByteString is variable-length, not numeric.
    assert is_numeric_state_type("ByteString") is False
    assert is_variable_length_state_type("ByteString") is True


# ---------------------------------------------------------------------------
# End-to-end: a contract whose property is `pt: Point` lowers cleanly.
# ---------------------------------------------------------------------------

def _lower_ec_primitives() -> object:
    """Run the full frontend on the ec-primitives example which has a
    ``pt: Point`` readonly constructor parameter.
    """
    source = EC_SRC.read_text(encoding="utf-8")
    pr = parse_source(source, EC_SRC.name)
    assert not pr.errors, f"parse errors: {pr.errors}"
    vr = validate(pr.contract)
    assert not vr.errors, f"validation errors: {vr.errors}"
    tr = type_check(pr.contract)
    assert not tr.errors, f"typecheck errors: {tr.errors}"
    program = lower_to_anf(pr.contract)
    return program, lower_to_stack(program)


def test_point_property_lowers_without_error():
    program, methods = _lower_ec_primitives()
    # Confirm the Point property is preserved through the frontend.
    assert any(p.type == "Point" for p in program.properties), (
        "ECPrimitives must declare a Point-typed property"
    )
    # All 14 public methods must produce non-empty StackMethods.
    public_names = [m.name for m in program.methods if m.is_public]
    assert len(public_names) >= 5, f"expected several public methods; got {public_names}"
    for sm in methods:
        assert sm.ops, f"method {sm.name} produced empty Stack-IR"


def test_point_method_emits_ec_primitive_opcodes():
    """The `check_x` method calls ec_point_x(self.pt). The ec_point_x emitter
    drops a known opcode count (233 ops, see test_ec.py:41). Verify the
    lowering goes through that path by checking opcode totals are within an
    expected band.
    """
    _, methods = _lower_ec_primitives()
    check_x = next(m for m in methods if m.name == "checkX")
    # ec_point_x alone is 233 ops; the rest of the method (load_param /
    # equality / assert / param-shuffling) adds <100 more.
    assert 233 <= len(check_x.ops) <= 400, (
        f"check_x op count out of band: {len(check_x.ops)}"
    )
