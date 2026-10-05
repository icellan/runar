"""N-096 -- the IR loader refuses a ``syntheticArrayChain`` the
expand-fixed-arrays pass could not have written, with the diagnostic shared by
all 7 tiers (``conformance/negatives/ir-synthetic-array-chain.test.ts`` holds
the corpus).

Before the rule this tier published the F-105 probe's 1100-level property
``deep`` as a scalar constructor parameter.

Proves: the probe is refused at load time with the shared words, and the
FixedArray goldens still load. Does not prove the rest of the rule, which the
conformance corpus covers in every tier.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.ir.loader import load_ir

REPO_ROOT = Path(__file__).resolve().parents[3]


def _golden(fixture: str) -> dict:
    return json.loads((REPO_ROOT / "conformance" / "tests" / fixture / "expected-ir.json").read_text())


def test_f105_probe_is_refused_with_the_shared_diagnostic() -> None:
    ir = _golden("basic-p2pkh")
    ir["properties"].insert(1, {
        "name": "deep",
        "type": "bigint",
        "readonly": True,
        "syntheticArrayChain": [{"base": "deep", "index": 0, "length": 1}] * 1100,
    })
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(ir))
    assert str(exc.value) == (
        "IR validation: malformed syntheticArrayChain on property 'deep': "
        "1100 levels exceed the limit of 1023"
    )


@pytest.mark.parametrize("fixture", ["fixed-array-index", "fixed-array-write"])
def test_fixed_array_goldens_still_load(fixture: str) -> None:
    load_ir(json.dumps(_golden(fixture)))
