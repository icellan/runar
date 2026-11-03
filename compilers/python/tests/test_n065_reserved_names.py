"""N-065 / N-060: a user identifier spelled like a name the compiler mints is
refused, with the diagnostic shared verbatim by all seven tiers.

Before: ``let t2: bigint = p; assert(p > 0n); if (c) { t2 = p; }
assert(t2 + 1n === 1n);`` compiled, and its final guard read the ANF temp
``t2`` (the ``0n``) instead of the local, so the script accepted p = 1,
c = false, which the source rejects. Every other minted family (stack-lowering
slots, FixedArray slots, auto-injected parameters) was accepted the same way,
and ``--ir`` accepted parameters, properties, bindings and references named
after stack lowering's own slots (N-060).

Proves: every source case in the shared corpus
(conformance/negatives/reserved-names-cases.json) is refused by this tier's
frontend with the exact shared sentence while its renamed twin compiles; a
stateless contract's own ``txPreimage`` parameter still compiles; every
``--ir`` case is refused by ``load_ir`` and the accepted IR (ANF temps and
``__merge$`` as binding names, ``txPreimage`` as a parameter) still compiles.
Does not prove: the on-chain effect (the TS conformance test runs the Spend
oracle) or agreement with the other tiers (conformance/negatives does).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_program, compile_from_source_str_with_result
from runar_compiler.ir.loader import load_ir

_CORPUS = json.loads(
    (Path(__file__).resolve().parents[3] / "conformance" / "negatives"
     / "reserved-names-cases.json").read_text(encoding="utf-8")
)


def _compile(src: str, file_name: str):
    return compile_from_source_str_with_result(src, file_name, disable_constant_folding=True)


@pytest.mark.parametrize("case", _CORPUS["source"]["cases"], ids=lambda c: c["name"])
def test_source_case_refused(case):
    r = _compile(case["src"], case["file"])
    assert not r.success
    assert case["error"] in [d.message for d in r.diagnostics]


@pytest.mark.parametrize("case", _CORPUS["source"]["cases"], ids=lambda c: c["name"])
def test_source_twin_compiles(case):
    r = _compile(case["twin"], case["file"])
    assert r.success, [d.message for d in r.diagnostics]


@pytest.mark.parametrize("case", _CORPUS["source"]["accept"], ids=lambda c: c["name"])
def test_source_accept(case):
    r = compile_from_source_str_with_result(case["src"], case["file"])
    assert r.success, [d.message for d in r.diagnostics]


@pytest.mark.parametrize("case", _CORPUS["ir"]["cases"], ids=lambda c: c["name"])
def test_ir_case_refused(case):
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(case["ir"]))
    assert case["error"] in str(exc.value)


@pytest.mark.parametrize("case", _CORPUS["ir"]["accept"], ids=lambda c: c["name"])
def test_ir_accept(case):
    art = compile_from_program(load_ir(json.dumps(case["ir"])), disable_constant_folding=True)
    assert art.script == "00ac"
