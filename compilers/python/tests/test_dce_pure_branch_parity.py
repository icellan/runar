"""R-140 / CL-BUG-027 — `if` and `loop` were unconditionally side-effecting here.

`has_side_effect` listed ``if`` and ``loop`` among the side-effecting kinds, so
an unreferenced branch or loop whose bodies are all pure was kept. The Go, Java,
Rust and TypeScript tiers recurse into the nested bindings and return False when
none of them is effectful. Measured on the predicate itself, which is the only
place the disagreement is visible today::

    go   HasSideEffect(pure if)   = false      zig  hasSideEffect(pure if)   = true
    go   HasSideEffect(pure loop) = false      zig  hasSideEffect(pure loop) = true

The reference tier (`packages/runar-compiler/src/optimizer/dce.ts`) recurses,
and says why in a comment this file now mirrors: retention is all-or-nothing,
because nested bindings live inside the parent node rather than flattened into
the method body, so dropping an effectful `if` would take every nested
``assert`` / ``check_preimage`` / ``add_output`` with it. Recursing is what makes
that safe AND precise.

Byte-neutral at HEAD: no shipped path reaches DCE with an unreferenced pure
branch, which is why the conformance suite never saw it. It is a divergence
waiting for the first caller that does — three tiers keeping a binding four
tiers delete is a hex divergence by construction.
"""

from runar_compiler.frontend.dce import has_side_effect
from runar_compiler.ir.types import ANFBinding, ANFValue


def binding(name: str, value: ANFValue) -> ANFBinding:
    return ANFBinding(name=name, value=value)


def pure(kind: str = "load_const") -> ANFValue:
    return ANFValue(kind=kind)


def test_if_with_pure_branches_is_not_side_effecting():
    v = ANFValue(kind="if", then=[binding("t1", pure())], else_=[binding("t2", pure())])
    assert has_side_effect(v) is False


def test_loop_with_a_pure_body_is_not_side_effecting():
    v = ANFValue(kind="loop", body=[binding("t1", pure("bin_op"))])
    assert has_side_effect(v) is False


def test_if_keeps_an_effectful_then_branch():
    v = ANFValue(
        kind="if",
        then=[binding("t1", ANFValue(kind="assert", value_ref="c"))],
        else_=[binding("t2", pure())],
    )
    assert has_side_effect(v) is True


def test_if_keeps_an_effectful_else_branch():
    v = ANFValue(
        kind="if",
        then=[binding("t1", pure())],
        else_=[binding("t2", ANFValue(kind="add_output"))],
    )
    assert has_side_effect(v) is True


def test_loop_keeps_an_effectful_body():
    v = ANFValue(kind="loop", body=[binding("t1", ANFValue(kind="update_prop", name="x", value_ref="t0"))])
    assert has_side_effect(v) is True


def test_recursion_reaches_a_NESTED_branch():
    """An effect two levels down must still keep the outer node — this is the
    case an `any(...)` over the top level alone would miss."""
    inner = ANFValue(kind="if", then=[binding("t2", ANFValue(kind="assert", value_ref="c"))], else_=[])
    outer = ANFValue(kind="if", then=[binding("t1", inner)], else_=[binding("t3", pure())])
    assert has_side_effect(outer) is True


def test_an_empty_if_is_pure():
    assert has_side_effect(ANFValue(kind="if", then=[], else_=[])) is False
