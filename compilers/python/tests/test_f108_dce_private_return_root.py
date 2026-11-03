"""F-108 — DCE must treat a PRIVATE method's last binding as a liveness root.

Stack lowering inlines a private helper at each ``method_call`` and takes the
helper's LAST binding as the call's result. Nothing inside the helper
references that binding, so a pure return expression (``return n + 1n``) was
deleted whenever DCE ran — which in this tier happens to every method once any
EC rewrite fires anywhere in the program. The helper was emptied and the
contract failed to compile ("value 't2' not found on stack").

What this proves: ``eliminate_dead_bindings`` keeps a private method's final
binding and its inputs, still drops a genuinely dead binding ahead of it, and
still drops an unreferenced pure final binding of a PUBLIC method.
What it does not prove: spendability — ``conformance/dce/private-return.test.ts``
executes the compiled script on all seven tiers.
"""

from runar_compiler.frontend.dce import eliminate_dead_bindings
from runar_compiler.ir.types import ANFBinding, ANFMethod, ANFParam, ANFValue


def _add1(is_public: bool) -> ANFMethod:
    return ANFMethod(
        name="pub_m" if is_public else "add1",
        params=[ANFParam(name="n", type="bigint")],
        body=[
            ANFBinding(name="dead", value=ANFValue(kind="load_const", raw_value=7, const_big_int=7)),
            ANFBinding(name="t0", value=ANFValue(kind="load_param", name="n")),
            ANFBinding(name="t1", value=ANFValue(kind="load_const", raw_value=1, const_big_int=1)),
            ANFBinding(name="t2", value=ANFValue(kind="bin_op", op="+", left="t0", right="t1")),
        ],
        is_public=is_public,
    )


def test_dce_keeps_private_method_return_value():
    m = _add1(is_public=False)
    eliminate_dead_bindings(m)
    assert [b.name for b in m.body] == ["t0", "t1", "t2"], (
        "DCE emptied a private helper's return value"
    )


def test_dce_still_drops_public_method_pure_last_binding():
    m = _add1(is_public=True)
    eliminate_dead_bindings(m)
    assert [b.name for b in m.body] == []
