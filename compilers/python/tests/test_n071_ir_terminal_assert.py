"""N-071: load_ir refuses a public method that does not END with an assert,
with the diagnostic shared by all seven tiers.

Before: F-014 already refused these shapes, but with a Python-only sentence
that also omitted the if/else form the rule accepts.

Proves: every case in the shared corpus
(conformance/negatives/ir-terminal-assert-cases.json) is refused with the exact
diagnostic every tier prints, and the accepted programs (a P2PK control and a
both-arm ``if``) load. Does not prove: that an accepted program is secure --
ending in an assert is necessary, not sufficient.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.ir.loader import load_ir

_CORPUS = json.loads(
    (Path(__file__).resolve().parents[3] / "conformance" / "negatives"
     / "ir-terminal-assert-cases.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", _CORPUS["accept"], ids=lambda c: c["name"])
def test_accepts(case):
    load_ir(json.dumps(case["ir"]))


@pytest.mark.parametrize("case", _CORPUS["cases"], ids=lambda c: c["name"])
def test_refuses_with_shared_diagnostic(case):
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(case["ir"]))
    assert str(exc.value) == case["error"]
