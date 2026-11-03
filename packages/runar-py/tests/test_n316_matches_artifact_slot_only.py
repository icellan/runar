"""N-316: ``matches_artifact`` must treat codeSepIndexSlots and
codePartLenSlots as variable script elements even when ``constructorSlots`` is
empty.

Replays the shared cross-tier fixture
``conformance/sdk-matches-artifact/fixtures.json`` (also replayed by the TS, Go,
Rust, Zig, Ruby and Java SDKs). Its first artifact is real compiler output for
a stateful contract with no constructor args.

Proves: an honest deployment of such an artifact matches it, and a script
differing in one code byte before/after the slot does not.
Does NOT prove: on-chain spendability, or slot layouts beyond the fixture.
"""

import json
import pathlib

import pytest

from runar.sdk.script_utils import matches_artifact
from runar.sdk.types import RunarArtifact

FIXTURE_PATH = (
    pathlib.Path(__file__).resolve().parents[3]
    / "conformance" / "sdk-matches-artifact" / "fixtures.json"
)
CASES = json.loads(FIXTURE_PATH.read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_matches_artifact_slot_only_artifacts(case):
    artifact = RunarArtifact.from_dict(case["artifact"])
    assert matches_artifact(artifact, case["script_hex"]) is case["expected"]
