"""GK-GAP-010 -- a public method's SigHashPreimage parameter must reach
checkPreimage() on every path.

spec/type-system.md 4.2 says a SigHashPreimage is checked exactly once; the
affine checker only refused a SECOND use. A stateless method that read fields
out of an unchecked preimage typechecked, and every field it read was chosen by
the spender. Corpus: conformance/negatives/preimage-checked-cases.json.

Proves: each refused shape (extract-only, one if-arm, right operand of ||/&&,
a helper that checks on one arm, a loop body, a .runar.py extract-only) fails
the compile with the shared diagnostic; each accepted shape (direct, both arms,
local alias, helper, left operand of &&) compiles.
Does not prove: the other six tiers (conformance/negatives covers them).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.compiler import CompilationError, compile_from_source

_REPO = Path(__file__).resolve().parents[3]
_CORPUS = json.loads((_REPO / "conformance/negatives/preimage-checked-cases.json").read_text())


@pytest.mark.parametrize("case", _CORPUS["refuse"], ids=[c["name"] for c in _CORPUS["refuse"]])
def test_refuses_unchecked_preimage(case, tmp_path):
    path = tmp_path / case["file"]
    path.write_text(case["src"])
    with pytest.raises(CompilationError) as exc:
        compile_from_source(str(path))
    assert case["error"] in str(exc.value)


@pytest.mark.parametrize("case", _CORPUS["accept"], ids=[c["name"] for c in _CORPUS["accept"]])
def test_accepts_checked_preimage(case, tmp_path):
    path = tmp_path / case["file"]
    path.write_text(case["src"])
    assert compile_from_source(str(path)).script
