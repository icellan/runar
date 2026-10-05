"""N-104: the EC identity rewrites R1-R4 must keep the replaced builtin's
operand validation in place of the call.

ecAdd(q, O) -> q, ecAdd(O, q) -> q, ecMul(q, 1) -> q and ecMul(q, 0) -> O used
to drop the validation ecAdd (64-byte width + coordinate canonicity) and ecMul
(on-curve-or-O) perform first, so a malformed or off-curve q was accepted by the
optimized script and aborted by the unoptimized one.

Pins the exact gate bindings -- names, kinds, operands, order -- every tier
emits (the "gate" entries in optimizer/ec-rules.json), so the seven tiers stay
ANF- and hex-identical. Proves this tier emits the gate; the gate's script
semantics are executed on the real Spend engine by
packages/runar-testing/src/__tests__/n104-ec-optimizer-operand-gate.test.ts.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.anf_optimize import optimize_ec, INFINITY_HEX
from runar_compiler.ir.types import ANFBinding, ANFMethod, ANFProgram, ANFValue

FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def _describe(b: ANFBinding) -> str:
    v = b.value
    if v.kind == "load_param":
        d = f"load_param {v.name}"
    elif v.kind == "load_const":
        if v.const_string is not None:
            s = v.const_string
            if s == INFINITY_HEX:
                d = "const INFINITY"
            elif s.startswith("@ref:"):
                d = f"ref {s[5:]}"
            else:
                d = f"const {s}"
        else:
            d = f"const {v.const_big_int}"
    elif v.kind == "call":
        d = f"call {v.func} {' '.join(v.args)}"
    elif v.kind == "bin_op":
        d = f"bin_op {v.op} {v.left} {v.right}" + (f" {v.result_type}" if v.result_type else "")
    elif v.kind == "assert":
        d = f"assert {v.value_ref}"
    else:
        d = v.kind
    return f"{b.name} = {d}"


ADD_GATE = [
    "t_px = call ecPointX p",
    "t_py = call ecPointY p",
    f"t_fp = const {FIELD_P}",
    "t_pxok = bin_op < t_px t_fp",
    "t_pyok = bin_op < t_py t_fp",
    "t_ok = bin_op && t_pxok t_pyok",
    "t_gate = assert t_ok",
]
MUL_GATE = [
    "t_inf = const INFINITY",
    "t_isinf = bin_op === p t_inf bytes",
    "t_oncurve = call ecOnCurve p",
    "t_ok = bin_op || t_isinf t_oncurve",
    "t_gate = assert t_ok",
]


def _program(second: ANFBinding, func: str, args: list[str]) -> ANFProgram:
    body = [
        ANFBinding(name="p", value=ANFValue(kind="load_param", name="pt")),
        second,
        ANFBinding(name="t", value=ANFValue(kind="call", func=func, args=args)),
        ANFBinding(name="a", value=ANFValue(kind="assert", raw_value="t", value_ref="t")),
    ]
    return ANFProgram(contract_name="Test", properties=[],
                      methods=[ANFMethod(name="test", params=[], body=body, is_public=True)])


def _inf() -> ANFBinding:
    return ANFBinding(name="inf", value=ANFValue(kind="load_const", const_string=INFINITY_HEX, raw_value=INFINITY_HEX))


def _int(name: str, n: int) -> ANFBinding:
    return ANFBinding(name=name, value=ANFValue(kind="load_const", const_big_int=n, const_int=n, raw_value=n))


@pytest.mark.parametrize("rule,program,gate,result", [
    ("ec-add-identity-right", lambda: _program(_inf(), "ecAdd", ["p", "inf"]), ADD_GATE, "ref p"),
    ("ec-add-identity-left", lambda: _program(_inf(), "ecAdd", ["inf", "p"]), ADD_GATE, "ref p"),
    ("ec-mul-one", lambda: _program(_int("one", 1), "ecMul", ["p", "one"]), MUL_GATE, "ref p"),
    ("ec-mul-zero", lambda: _program(_int("zero", 0), "ecMul", ["p", "zero"]), MUL_GATE, "const INFINITY"),
])
def test_n104_rewrite_keeps_operand_gate(rule, program, gate, result):
    got = [_describe(b) for b in optimize_ec(program()).methods[0].body]
    assert got == ["p = load_param pt", *gate, f"t = {result}", "a = assert t"], rule
