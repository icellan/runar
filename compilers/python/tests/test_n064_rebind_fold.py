"""N-064 — constant folding must not fold with a constant a name no longer
holds. Port of the reference tier's case in
packages/runar-compiler/src/__tests__/optimizer.test.ts.

The folder recorded a name's constant when a binding produced one and never
dropped it. A name can be bound more than once, and the probes that showed it
bound a user local to the name of an earlier compiler temp, so with folding
ON (the default) later uses folded with a stale value: Rebind's guard became
OP_TRUE (7600a0695151515177777777, spendable with any p > 0), RebindEq's
became OP_FALSE, and a rebinding inside an if arm or a loop body leaked the
same way past the if / into later iterations.

N-065 made that naming collision a refusal, so the probe SOURCES no longer
compile (asserted below). The fold must still be right for the ANF shape, so
each probe's exact ANF (conformance/negatives/n064-collision-anf.json,
generated from the source with parse -> lowerToANF and no validator) is
loaded with ``load_ir`` and compiled with folding ON and OFF. The TS reference
checked that the pre-N-064 folder turns this same ANF into ``staleFoldOn``
byte for byte, so the replay keeps the regression value of the old
source-level probes.

Proves: this tier's folder compiles each probe's ANF to the fold-OFF bytes
every tier emits (not the stale ones), and refuses the probe sources with the
N-065 diagnostic. Does NOT prove on-chain behaviour — the Spend-engine proof is
packages/runar-testing/src/__tests__/n064-rebind-fold-spend.test.ts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_program, compile_from_source_str_with_result
from runar_compiler.ir.loader import load_ir

PROBES = json.loads(
    (Path(__file__).resolve().parents[3] / "conformance" / "negatives"
     / "n064-collision-anf.json").read_text(encoding="utf-8")
)["probes"]

# The local each probe spells like an ANF temp — the name N-065 refuses.
COLLIDING_LOCAL = {"Rebind": "t1", "RebindEq": "t1", "IfStale": "t2", "LoopStale": "t2"}


@pytest.mark.parametrize("disable", [True, False])
@pytest.mark.parametrize("probe", PROBES, ids=[p["name"] for p in PROBES])
def test_fold_on_does_not_use_a_stale_constant(probe, disable: bool) -> None:
    program = load_ir(json.dumps(probe["ir"]))
    script = compile_from_program(program, disable_constant_folding=disable).script
    assert script != probe["staleFoldOn"]
    assert script == probe["foldOff"]


@pytest.mark.parametrize("probe", PROBES, ids=[p["name"] for p in PROBES])
def test_probe_source_is_refused_by_n065(probe) -> None:
    result = compile_from_source_str_with_result(probe["source"], f"{probe['name']}.runar.ts")
    assert not result.success
    name = COLLIDING_LOCAL[probe["name"]]
    want = f"'{name}' is reserved for compiler-generated names and cannot be used as an identifier"
    assert want in [d.message for d in result.diagnostics]
