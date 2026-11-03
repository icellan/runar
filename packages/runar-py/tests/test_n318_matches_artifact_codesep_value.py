"""N-318: ``matches_artifact`` must check the VALUE at every codeSepIndex slot.

Deploy bakes encode_script_number(code_sep_index + shift) there (shift = growth
of every constructor slot, and every earlier codeSep slot, before
code_sep_index); the matcher used to accept any element at the slot.

Replays the shared cross-tier vector
``conformance/sdk-matches-artifact/codesep.json`` (also replayed by the TS, Go,
Rust, Zig, Ruby and Java SDKs): honest TS-SDK deployments of a real compiled
artifact and of a synthetic artifact whose baked values depend on a
variable-length constructor arg, plus forgeries differing only in the number
pushed at a codeSep slot.

Proves: honest deployments match whatever the constructor-arg width, and a
forged separator index (OP_0, off by one, non-minimal, unshifted) does not.
Does NOT prove: on-chain spendability of the honest scripts.
"""

import json
import pathlib

import pytest

from runar.sdk.script_utils import matches_artifact
from runar.sdk.types import RunarArtifact

FIXTURE = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[3]
        / "conformance" / "sdk-matches-artifact" / "codesep.json"
    ).read_text()
)
CASES = FIXTURE["cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_matches_artifact_checks_codesep_value(case):
    artifact = RunarArtifact.from_dict(FIXTURE["artifacts"][case["artifact"]])
    assert matches_artifact(artifact, case["script_hex"]) is case["expected"]
