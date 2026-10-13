"""N-218: port of F-343 to this tier.

The TS reference's optimizeBodyOnce
(packages/runar-compiler/src/optimizer/anf-ec.ts) keeps the rewritten
binding's source location on every helper binding a rule mints -- the N-104
operand gate, the N-251 neg-cancel gate, and the fused-scalar helper --
because stack lowering maps opcodes through binding.source_loc. Before this
fix, ``_optimize_method`` appended every helper binding with
``source_loc=None`` regardless of the rewritten binding's own location, so
none of a rewritten EC call's gate opcodes reached the source map.

Proves: a located ecMul(p, 0) rewrite's mul gate (5 bindings), a located
ecAdd(p, ecNegate(p)) rewrite's neg-cancel gate (7 bindings), and a located
nested-ecMul fusion's ``_k`` helper all carry the rewritten binding's
source_loc; an unlocated rewrite mints unlocated helpers (no source_loc
invented from nothing).

Does not prove: exact file/line/column assignment upstream in the ANF
lowerer, or end-to-end script-map behavior -- that is covered by the TS test
f343-ec-optimizer-source-loc.test.ts and by conformance, which strips
sourceLoc as debug-only and so cannot regress from this change.
"""

from __future__ import annotations

from runar_compiler.frontend.anf_optimize import optimize_ec
from runar_compiler.ir.types import ANFBinding, ANFMethod, ANFProgram, ANFValue, SourceLocation

LOC = SourceLocation(file="T.runar.ts", line=7, column=4)


def _find(body, name: str) -> ANFBinding:
    for b in body:
        if b.name == name:
            return b
    raise AssertionError(f"missing binding {name!r} in {[b.name for b in body]}")


def _program(body: list[ANFBinding]) -> ANFProgram:
    return ANFProgram(contract_name="Test", properties=[],
                      methods=[ANFMethod(name="test", params=[], body=body, is_public=True)])


def test_rule4_mul_gate_carries_source_loc():
    body = [
        ANFBinding(name="p", value=ANFValue(kind="load_param", name="pt")),
        ANFBinding(name="zero", value=ANFValue(kind="load_const", const_big_int=0, const_int=0, raw_value=0)),
        ANFBinding(name="t", value=ANFValue(kind="call", func="ecMul", args=["p", "zero"]), source_loc=LOC),
        ANFBinding(name="a", value=ANFValue(kind="assert", raw_value="t", value_ref="t")),
    ]
    out = optimize_ec(_program(body)).methods[0].body
    for name in ("t_inf", "t_isinf", "t_oncurve", "t_ok", "t_gate"):
        b = _find(out, name)
        assert b.source_loc == LOC, f"{name}: source_loc = {b.source_loc!r}, want {LOC!r}"
    t = _find(out, "t")
    assert t.source_loc == LOC, f"t: source_loc = {t.source_loc!r}, want {LOC!r}"


def test_rule8_neg_cancel_gate_carries_source_loc():
    body = [
        ANFBinding(name="p", value=ANFValue(kind="load_param", name="pt")),
        ANFBinding(name="n", value=ANFValue(kind="call", func="ecNegate", args=["p"])),
        ANFBinding(name="t", value=ANFValue(kind="call", func="ecAdd", args=["p", "n"]), source_loc=LOC),
        ANFBinding(name="a", value=ANFValue(kind="assert", raw_value="t", value_ref="t")),
    ]
    out = optimize_ec(_program(body)).methods[0].body
    for name in ("t_px", "t_py", "t_zero", "t_pxz", "t_pynz", "t_ok", "t_gate"):
        b = _find(out, name)
        assert b.source_loc == LOC, f"{name}: source_loc = {b.source_loc!r}, want {LOC!r}"


def test_rule9_fused_scalar_helper_carries_source_loc():
    body = [
        ANFBinding(name="p", value=ANFValue(kind="load_param", name="pt")),
        ANFBinding(name="k1", value=ANFValue(kind="load_const", const_big_int=3, const_int=3, raw_value=3)),
        ANFBinding(name="k2", value=ANFValue(kind="load_const", const_big_int=5, const_int=5, raw_value=5)),
        ANFBinding(name="inner", value=ANFValue(kind="call", func="ecMul", args=["p", "k1"])),
        ANFBinding(name="outer", value=ANFValue(kind="call", func="ecMul", args=["inner", "k2"]), source_loc=LOC),
        ANFBinding(name="a", value=ANFValue(kind="assert", raw_value="outer", value_ref="outer")),
    ]
    out = optimize_ec(_program(body)).methods[0].body
    helper = _find(out, "outer_k")
    assert helper.source_loc == LOC, f"outer_k: source_loc = {helper.source_loc!r}, want {LOC!r}"
    outer = _find(out, "outer")
    assert outer.source_loc == LOC, f"outer: source_loc = {outer.source_loc!r}, want {LOC!r}"


def test_unlocated_rewrite_mints_unlocated_helpers():
    body = [
        ANFBinding(name="p", value=ANFValue(kind="load_param", name="pt")),
        ANFBinding(name="zero", value=ANFValue(kind="load_const", const_big_int=0, const_int=0, raw_value=0)),
        ANFBinding(name="t", value=ANFValue(kind="call", func="ecMul", args=["p", "zero"])),
        ANFBinding(name="a", value=ANFValue(kind="assert", raw_value="t", value_ref="t")),
    ]
    out = optimize_ec(_program(body)).methods[0].body
    for b in out:
        assert b.source_loc is None, f"{b.name}: expected no source_loc, got {b.source_loc!r}"
