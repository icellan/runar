"""N-101 -- load_ir refuses a StatefulSmartContract program (declared, or
inferred per N-087) any of whose public methods lacks, reorders or alters the
scaffolding ANF lowering injects (auto-injected parameters, the checkPreimage /
sighash / deserialize_state prologue, the state continuation), with the
diagnostics shared by all seven tiers
(conformance/negatives/ir-stateful-scaffold-cases.json).

Before: F-107's attack body relabelled StatefulSmartContract compiled to
76767b8777, which an attacker's key spends under strict @bsv/sdk Spend, and so
did the parentClass-less variant carrying a dead add_data_output.

Proves: every corpus case is refused with its exact diagnostic and the accepted
programs (incl. unmodified stateful goldens) load and compile. Does not prove
cross-tier agreement (conformance/negatives/ir-stateful-scaffold.test.ts does)
or anything about the free user code between prologue and continuation.
"""

import json
from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_ir_bytes
from runar_compiler.ir.loader import load_ir

_CORPUS = json.loads(
    (Path(__file__).resolve().parents[3] / "conformance" / "negatives"
     / "ir-stateful-scaffold-cases.json").read_text(encoding="utf-8")
)


def test_corpus_is_non_empty():
    assert len(_CORPUS["cases"]) >= 10
    assert len(_CORPUS["accept"]) >= 3


@pytest.mark.parametrize("case", _CORPUS["accept"], ids=lambda c: c["name"])
def test_accepts(case):
    load_ir(json.dumps(case["ir"]))
    compile_from_ir_bytes(json.dumps(case["ir"]).encode())


@pytest.mark.parametrize("case", _CORPUS["cases"], ids=lambda c: c["name"])
def test_refuses_with_shared_diagnostic(case):
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(case["ir"]))
    assert str(exc.value) == case["error"]
