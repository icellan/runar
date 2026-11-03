"""N-069: load_ir checks every required ANF field for presence and JSON type.

Before: ``params: {}`` iterated as an empty list and was accepted,
``body: "x"`` died as ``'str' object has no attribute 'get'``, and an omitted
``body`` was refused only by the unrelated terminal-assert rule.

Proves: each single-field corruption in the shared corpus
(conformance/negatives/ir-required-fields-cases.json) is refused with the exact
diagnostic every tier prints, and the control loads. Does not prove: full
schema conformance (deliberately defaulted optional fields are not required).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.ir.loader import load_ir

_CORPUS = json.loads(
    (Path(__file__).resolve().parents[3] / "conformance" / "negatives"
     / "ir-required-fields-cases.json").read_text(encoding="utf-8")
)


def test_control_loads():
    load_ir(json.dumps(_CORPUS["control"]))


@pytest.mark.parametrize("case", _CORPUS["cases"], ids=lambda c: c["name"])
def test_refuses_with_shared_diagnostic(case):
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(case["ir"]))
    assert str(exc.value) == case["error"]
