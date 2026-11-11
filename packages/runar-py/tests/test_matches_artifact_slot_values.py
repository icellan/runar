"""``matches_artifact`` must check what sits at each constructor slot, not only
the template bytes between slots: a push or small-integer opcode, the same
bytes at every reference of one param, and exactly ``fixedValueByteLength``
bytes where the slot declares it. A stateful artifact's script must carry an
OP_RETURN after its code part.

Replays the shared cross-tier vector
``conformance/sdk-matches-artifact/slot-values.json`` (also replayed by the TS,
Go, Rust, Zig, Ruby and Java SDKs), plus the TS unit cases for hex case,
``extract_constructor_args`` refusing a non-push opcode, and
``extract_constructor_args`` after a codeSepIndex slot wider than one byte.

Proves: honest deployments match; the forgeries in the vector do not;
``extract_constructor_args`` raises MalformedScriptError on a non-push opcode
at any reference of a param and reads an arg after a wide codeSep slot from
its deployed position.
Does NOT prove: that a slot push is minimally encoded, nor anything about the
length of the state after the OP_RETURN.
"""

import json
import pathlib

import pytest

from runar.sdk.errors import MalformedScriptError
from runar.sdk.script_utils import extract_constructor_args, matches_artifact
from runar.sdk.types import RunarArtifact

FIXTURE = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[3]
        / "conformance" / "sdk-matches-artifact" / "slot-values.json"
    ).read_text()
)
CASES = FIXTURE["cases"]
G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def _artifact(key: str) -> RunarArtifact:
    return RunarArtifact.from_dict(FIXTURE["artifacts"][key])


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_matches_artifact_checks_slot_values(case):
    assert matches_artifact(_artifact(case["artifact"]), case["script_hex"]) is case["expected"]


def test_slot_values_compare_without_regard_to_hex_case():
    assert matches_artifact(_artifact("owner2"), f"21{G}ad21{G.upper()}ac") is True


@pytest.mark.parametrize(
    "key,script",
    [
        ("owner2", f"acad21{G}ac"),
        ("owner2", f"21{G}adacac"),
        ("slotMatrix", "ac7b880111" + "7c9dac" + f"21{G}879169" + f"21{G}ac"),
    ],
    ids=["first-reference", "later-reference", "slotMatrix"],
)
def test_extract_constructor_args_refuses_non_push(key, script):
    with pytest.raises(MalformedScriptError):
        extract_constructor_args(_artifact(key), script)


def test_extract_constructor_args_honest_deployments():
    for c in CASES:
        if c["expected"] and c["artifact"] == "slotMatrix":
            args = extract_constructor_args(_artifact("slotMatrix"), c["script_hex"])
            assert args["count"] == 17 and args["owner"] == G, c["name"]
    honest = next(c for c in CASES if c["name"] == "owner2-honest")
    assert extract_constructor_args(_artifact("owner2"), honest["script_hex"]) == {"owner": G}


def test_extract_constructor_args_after_wide_codesep_slot():
    # Hand-built: a codeSepIndex slot at byte 1 with codeSepIndex 140, baked as
    # 143 (`02 8f00`), then a constructor slot at byte 3. Script pinned by the
    # TS SDK's RunarContract.getLockingScript().
    art = RunarArtifact.from_dict({
        "version": "runar-v1.0.0-rc.1",
        "compilerVersion": "1.0.0-rc.1",
        "contractName": "CodeSepBeforeSlot",
        "abi": {"constructor": {"params": [{"name": "x", "type": "ByteString"}]}, "methods": []},
        "script": "5100520053",
        "constructorSlots": [{"paramIndex": 0, "byteOffset": 3}],
        "codeSepIndexSlots": [{"byteOffset": 1, "codeSepIndex": 140}],
    })
    script = "51028f005203aabbcc53"
    assert matches_artifact(art, script) is True
    assert extract_constructor_args(art, script) == {"x": "aabbcc"}
