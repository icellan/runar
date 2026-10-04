"""N-087 -- load_ir enforces the source validator's parentClass rules and the
readonly/undeclared-property write rule on IR, with the diagnostics shared by
all seven tiers (conformance/negatives/ir-parent-class-cases.json).

Before: a SmartContract declaring ``owner`` with readonly:false (F-107's
v2-mut-stateless) compiled to 76767b8777, which an attacker's key spends under
strict @bsv/sdk Spend; stateful-only nodes in a non-stateful contract and
raw_script outside UnsafeSmartContract compiled too.

Proves: every corpus case is refused with its exact diagnostic and the accepted
programs (incl. parentClass-less IR) load. Does not prove that a declared
StatefulSmartContract body enforces its state continuation.
"""

import json
from pathlib import Path

import pytest

from runar_compiler.ir.loader import load_ir

_CORPUS = json.loads(
    (Path(__file__).resolve().parents[3] / "conformance" / "negatives"
     / "ir-parent-class-cases.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", _CORPUS["accept"], ids=lambda c: c["name"])
def test_accepts(case):
    load_ir(json.dumps(case["ir"]))


@pytest.mark.parametrize("case", _CORPUS["cases"], ids=lambda c: c["name"])
def test_refuses_with_shared_diagnostic(case):
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(case["ir"]))
    if case.get("match") == "prefix":
        assert str(exc.value).startswith(case["error"]), str(exc.value)
    else:
        assert str(exc.value) == case["error"]
