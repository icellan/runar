"""N-051 (TaffyTail) — the ``SIZE(_codePart)`` pin is always an equality.

A stateful contract with a variable-length state section pins the length of the
spender-supplied ``_codePart`` with the nine-byte run::

    76 | 04 LL LL LL LL | 81 | 9c | 69
    OP_DUP  <len LE32>    OP_BIN2NUM  OP_NUMEQUAL  OP_VERIFY

When a readonly constructor arg of variable width (here ``tag: ByteString``) is
baked into the code, the compiler cannot know the deployed length. It used to
fall back to OP_GREATERTHANOREQUAL — a lower bound that let a stranger claim a
TRUNCATED ``_codePart`` ending at a 0x6a byte inside the baked value. Now the
compiler records the length field as an artifact ``codePartLenSlots`` entry and
the SDK writes the real deployed code-part length into it at deploy time.

The artifact and expected hex are the TypeScript reference (fold OFF), checked
in under ``tests/testdata/taffytail-vault-*.json``; the Python SDK must
reproduce them byte for byte.
"""

from __future__ import annotations

import copy
import json
import pathlib

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.ordinals import Inscription
from runar.sdk.script_utils import matches_artifact
from runar.sdk.types import RunarArtifact

TESTDATA = pathlib.Path(__file__).resolve().parent / 'testdata'
ARTIFACT_JSON = json.loads((TESTDATA / 'taffytail-vault-artifact.json').read_text())
EXPECTED = json.loads((TESTDATA / 'taffytail-vault-expected.json').read_text())


def _contract(artifact_dict: dict | None = None) -> RunarContract:
    artifact = RunarArtifact.from_dict(artifact_dict or ARTIFACT_JSON)
    return RunarContract(artifact, list(EXPECTED['constructorArgs']))


def _inscription() -> Inscription:
    ins = EXPECTED['inscription']
    return Inscription(content_type=ins['contentType'], data=ins['data'])


def test_artifact_parses_code_part_len_slots():
    artifact = RunarArtifact.from_dict(ARTIFACT_JSON)
    assert [s.byte_offset for s in artifact.code_part_len_slots] == [959]
    # The template carries the equality pin, never the lower bound.
    assert artifact.script[958 * 2:959 * 2] == '04'
    assert artifact.script[963 * 2:966 * 2] == '819c69'


def test_built_code_part_and_locking_script_match_ts_reference():
    contract = _contract()
    code_part = contract._get_code_part_hex()
    assert len(code_part) // 2 == EXPECTED['codePartLen'] == 1608
    assert code_part == EXPECTED['codePartHex']
    assert contract.get_locking_script() == EXPECTED['lockingScriptHex']


def test_inscribed_code_part_matches_ts_reference():
    contract = _contract()
    # Deploy-time slot: patched to the inscribed length, so it is honoured.
    result = contract.with_inscription(_inscription())
    assert result is contract
    code_part = contract._get_code_part_hex()
    assert len(code_part) // 2 == EXPECTED['inscribedCodePartLen'] == 1631
    assert code_part == EXPECTED['inscribedCodePartHex']


def test_exact_compile_time_pin_still_refuses_inscription():
    """Control: the guard must still decode exact pins from the built code.

    Dropping the slot turns the field back into a compile-time value (1350 in
    the template, which is wrong for this deployment either way): the guard
    must refuse an inscription rather than silently patch.
    """
    d = copy.deepcopy(ARTIFACT_JSON)
    del d['codePartLenSlots']
    contract = _contract(d)
    with pytest.raises(ValueError) as excinfo:
        contract.with_inscription(_inscription())
    assert 'pins SIZE(_codePart) == ' in str(excinfo.value)
    assert contract.inscription is None


def test_corrupted_slot_offset_is_refused():
    d = copy.deepcopy(ARTIFACT_JSON)
    d['codePartLenSlots'] = [{'byteOffset': 958}]
    contract = _contract(d)
    with pytest.raises(ValueError) as excinfo:
        contract.get_locking_script()
    assert 'does not point at a verify_code_part_len length field' in str(excinfo.value)


def test_matches_artifact_checks_deployed_length_field():
    artifact = RunarArtifact.from_dict(ARTIFACT_JSON)
    locking = EXPECTED['lockingScriptHex']
    assert matches_artifact(artifact, locking)

    # The pin's field sits at template offset 959; in the deployed code it is
    # shifted by the 33-byte growth of the PubKey slot at template offset 465
    # (the ByteString slot at 1113 lies after it).
    at = (959 + 33) * 2
    assert locking[at:at + 8] == (1608).to_bytes(4, 'little').hex()
    altered = locking[:at] + (1607).to_bytes(4, 'little').hex() + locking[at + 8:]
    assert not matches_artifact(artifact, altered)
    # The unpatched template value is not accepted either.
    altered = locking[:at] + ARTIFACT_JSON['script'][959 * 2:963 * 2] + locking[at + 8:]
    assert not matches_artifact(artifact, altered)


def test_matches_artifact_rejects_trailing_bytes():
    artifact = RunarArtifact.from_dict(ARTIFACT_JSON)
    code = EXPECTED['codePartHex']
    state = EXPECTED['lockingScriptHex'][len(code):]
    # An extra code byte after the template's tail must not match.
    assert not matches_artifact(artifact, code + '51' + state)
