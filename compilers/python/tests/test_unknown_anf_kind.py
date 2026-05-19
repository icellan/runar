"""Regression test for F-003: every ANF-kind dispatch in the Python
compiler must raise ``UnknownANFKindError`` when it encounters a kind it
doesn't recognize, instead of silently returning a no-op result.

Each test drives one dispatch site with a synthetic ANFValue whose
``kind`` does not appear in the ANFValue union, then asserts the
resulting error is the typed error and carries the synthetic kind name.

If a new ANFValue variant is added in the future, the dispatch sites
below must be updated; this test guards against silently shipping an
unhandled variant.

Direct port of
``packages/runar-compiler/src/__tests__/unknown-anf-kind.test.ts``.
"""

from __future__ import annotations

import pytest

from runar_compiler.codegen.stack import collect_refs, lower_to_stack
from runar_compiler.frontend.anf_optimize import (
    _collect_refs,
    _eliminate_dead_bindings,
    _has_side_effect,
)
from runar_compiler.frontend.constant_fold import _fold_value, fold_constants
from runar_compiler.ir.types import ANFBinding, ANFMethod, ANFProgram, ANFValue
from runar_compiler.ir.unknown_anf_kind_error import UnknownANFKindError


SYNTHETIC_KIND = "synthetic_test_kind_for_regression_only"


def _synthetic_value() -> ANFValue:
    """Build an ANFValue whose runtime ``kind`` discriminator is not in the
    schema. The whole point is to simulate a developer adding a new ANF
    variant without wiring it through every dispatch site.
    """
    return ANFValue(kind=SYNTHETIC_KIND)


def _make_program(body: list[ANFBinding]) -> ANFProgram:
    method = ANFMethod(name="m", params=[], body=body, is_public=True)
    return ANFProgram(contract_name="Test", properties=[], methods=[method])


# ---------------------------------------------------------------------------
# constant-fold dispatch sites
# ---------------------------------------------------------------------------

def test_fold_value_raises_on_unknown_kind() -> None:
    program = _make_program([ANFBinding(name="t0", value=_synthetic_value())])

    with pytest.raises(UnknownANFKindError) as exc_info:
        fold_constants(program)

    assert exc_info.value.kind == SYNTHETIC_KIND
    assert exc_info.value.location == "constant-fold.foldValue"


def test_fold_value_direct_call_raises_on_unknown_kind() -> None:
    """Drive ``_fold_value`` directly so the error site is unambiguous."""
    with pytest.raises(UnknownANFKindError) as exc_info:
        _fold_value(_synthetic_value(), {})

    assert exc_info.value.kind == SYNTHETIC_KIND
    assert exc_info.value.location == "constant-fold.foldValue"


def test_collect_refs_from_value_raises_on_unknown_kind() -> None:
    """``_collect_refs`` is the DCE ref-walker (TS collectRefsFromValue)."""
    used: set[str] = set()
    with pytest.raises(UnknownANFKindError) as exc_info:
        _collect_refs(_synthetic_value(), used)

    assert exc_info.value.kind == SYNTHETIC_KIND
    assert exc_info.value.location == "constant-fold.collectRefsFromValue"


def test_has_side_effect_raises_on_unknown_kind() -> None:
    with pytest.raises(UnknownANFKindError) as exc_info:
        _has_side_effect(_synthetic_value())

    assert exc_info.value.kind == SYNTHETIC_KIND
    assert exc_info.value.location == "constant-fold.hasSideEffect"


def test_dce_raises_on_unknown_kind() -> None:
    """DCE drives both ``_collect_refs`` and ``_has_side_effect``; either
    dispatch site is acceptable -- both must reject the kind.
    """
    program = _make_program([ANFBinding(name="t0", value=_synthetic_value())])
    method = program.methods[0]

    with pytest.raises(UnknownANFKindError) as exc_info:
        _eliminate_dead_bindings(method)

    assert exc_info.value.kind == SYNTHETIC_KIND
    assert exc_info.value.location in (
        "constant-fold.collectRefsFromValue",
        "constant-fold.hasSideEffect",
    )


# ---------------------------------------------------------------------------
# stack-lower dispatch sites
# ---------------------------------------------------------------------------

def test_collect_refs_raises_on_unknown_kind() -> None:
    """``collect_refs`` runs first (computeLastUses) -- that's where we
    expect the throw. ``_lower_binding`` is the fallback.
    """
    with pytest.raises(UnknownANFKindError) as exc_info:
        collect_refs(_synthetic_value())

    assert exc_info.value.kind == SYNTHETIC_KIND
    assert exc_info.value.location == "stack.collect_refs"


def test_lower_to_stack_raises_on_unknown_kind() -> None:
    """End-to-end stack lowering must reject the synthetic kind. Either
    dispatch site is acceptable -- both must reject the kind.
    """
    program = _make_program([ANFBinding(name="t0", value=_synthetic_value())])

    with pytest.raises(UnknownANFKindError) as exc_info:
        lower_to_stack(program)

    assert exc_info.value.kind == SYNTHETIC_KIND
    assert exc_info.value.location in (
        "stack.collect_refs",
        "stack.lower_binding",
    )


# ---------------------------------------------------------------------------
# Error shape
# ---------------------------------------------------------------------------

def test_error_message_references_developer_recipe() -> None:
    err = UnknownANFKindError(SYNTHETIC_KIND, "unit-test.location")
    msg = str(err)
    assert SYNTHETIC_KIND in msg
    assert "unit-test.location" in msg
    assert "Adding a New ANF Value Kind" in msg
    assert err.kind == SYNTHETIC_KIND
    assert err.location == "unit-test.location"
