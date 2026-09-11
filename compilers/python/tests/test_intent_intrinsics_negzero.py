"""N-060 — a ``-0`` index evades the literal gate and silently DELETES the
covenant.

The typecheck index gate in ``frontend/typecheck.py`` accepts
``UnaryExpr('-', BigIntLiteral)`` only so that a negative index reports
"must be >= 0" instead of the misleading "must be an integer literal".
``-0`` negates to ``0``, so it passes that bound check — but ANF lowering
matches on a BARE ``BigIntLiteral`` and, finding a ``UnaryExpr``, falls
through to ``load_const ""``: no witness param, no hash assertion, NO
COVENANT, and no diagnostic. A contract whose whole purpose is the covenant
compiles to a script that does not carry it.

Mirrors ``compilers/rust/tests/intent_intrinsics_bounds.rs`` (R-068).
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check


EPS_NEG_ZERO_SRC = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    H     runar.ByteString
    Count runar.Bigint
}

func (c *Cov) Bind() {
    s := runar.ExtractPrevOutputScript(-0, c.H)
    runar.Assert(runar.Len(s) > 0)
    c.Count = c.Count + 1
}
"""

ROP_NEG_ZERO_SRC = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    PKH   runar.ByteString
    Amt   runar.Bigint
    Count runar.Bigint
}

func (c *Cov) Pay() {
    runar.RequireOutputP2PKH(-0, c.PKH, c.Amt)
    c.Count = c.Count + 1
}
"""


def _typecheck_errors(source: str) -> list[str]:
    result = parse_source(source, "Test.runar.go")
    assert result.errors == [], result.error_strings()
    assert result.contract is not None
    return [d.format_message() for d in type_check(result.contract).errors]


def _expect_error(source: str, substr: str) -> None:
    msgs = _typecheck_errors(source)
    assert any(substr in m for m in msgs), (
        f"expected typecheck error containing {substr!r}, got: {msgs}"
    )


def _anf_str(source: str) -> str | None:
    """Lower to ANF and stringify. Returns None when typecheck rejected it."""
    result = parse_source(source, "Test.runar.go")
    assert result.errors == [], result.error_strings()
    if type_check(result.contract).errors:
        return None
    return str(lower_to_anf(result.contract))


def test_extract_prev_output_script_negative_zero_index_rejects():
    _expect_error(EPS_NEG_ZERO_SRC, "must be an integer literal")


def test_require_output_p2pkh_negative_zero_index_rejects():
    _expect_error(ROP_NEG_ZERO_SRC, "must be an integer literal")


@pytest.mark.parametrize(
    "label,src",
    [
        ("extractPrevOutputScript", EPS_NEG_ZERO_SRC),
        ("requireOutputP2PKH", ROP_NEG_ZERO_SRC),
    ],
)
def test_negative_zero_index_never_silently_drops_the_covenant(label, src):
    """The funds-safety half of the pair: a ``-0`` index must never reach
    codegen, because when it does the intrinsic lowers to a bare empty-string
    constant and the covenant it was supposed to install is simply absent."""
    text = _anf_str(src)
    if text is None:
        return
    pytest.fail(
        f"{label}(-0, ...) compiled with NO diagnostic; covenant markers present: "
        f"_prevOutScript_={'_prevOutScript_' in text} "
        f"_serialisedOutputs={'_serialisedOutputs' in text}"
    )


# Controls — the valid forms must keep lowering exactly as before.


def test_control_literal_zero_index_still_installs_the_covenant():
    eps = EPS_NEG_ZERO_SRC.replace(
        "ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(0,"
    )
    text = _anf_str(eps)
    assert text is not None, "valid eps contract must lower"
    assert "_prevOutScript_0" in text, (
        "extractPrevOutputScript(0, ...) must still auto-inject its witness param"
    )

    rop = ROP_NEG_ZERO_SRC.replace(
        "RequireOutputP2PKH(-0,", "RequireOutputP2PKH(1,"
    )
    text = _anf_str(rop)
    assert text is not None, "valid rop contract must lower"
    assert "_serialisedOutputs" in text, (
        "requireOutputP2PKH(1, ...) must still auto-inject _serialisedOutputs"
    )


def test_control_plain_negative_index_still_reports_the_bound_message():
    src = EPS_NEG_ZERO_SRC.replace(
        "ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(-3,"
    )
    _expect_error(src, "must be >= 0")
