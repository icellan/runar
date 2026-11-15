"""GK-GAP-013 -- ANF lowering refuses malformed intent-intrinsic calls.

``extractPrevOutputScript`` with the wrong arity or a non-literal index /
prefix length, and ``requireOutputP2PKH`` with the wrong arity or a
non-literal index, used to lower to ``load_const ""`` -- the hash assertion
(or the output pin) silently vanished. Typecheck refuses every shape first, so
the normal pipeline never got there, but ``lower_to_anf`` is a public entry
point and R-012 is the standing lesson about a security check that lives in
one pass. Corpus: conformance/negatives/intent-shape-cases.json.

Proves: lower_to_anf on each parsed (un-typechecked) shape raises the case's
message and returns no program; the full compile still refuses each shape.
Does not prove: the other six tiers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.compiler import CompilationError, compile_from_source
from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source

_REPO = Path(__file__).resolve().parents[3]
_CASES = json.loads(
    (_REPO / "conformance/negatives/intent-shape-cases.json").read_text()
)["cases"]


@pytest.mark.parametrize("case", _CASES, ids=[c["name"] for c in _CASES])
def test_lowerer_refuses_instead_of_emitting_empty_const(case):
    parsed = parse_source(case["src"], "Bad.runar.ts")
    assert parsed.contract is not None and not parsed.errors, parsed.errors
    with pytest.raises(ValueError) as exc:
        lower_to_anf(parsed.contract)
    assert case["lowerError"] in str(exc.value)


@pytest.mark.parametrize("case", _CASES, ids=[c["name"] for c in _CASES])
def test_full_compile_still_refuses(case, tmp_path):
    path = tmp_path / "Bad.runar.ts"
    path.write_text(case["src"])
    with pytest.raises(CompilationError, match="type check errors"):
        compile_from_source(str(path))
