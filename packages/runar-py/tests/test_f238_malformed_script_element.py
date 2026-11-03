"""F-238 — ``_read_script_element`` must refuse malformed provider-supplied
scripts instead of raising a bare ``ValueError`` or silently truncating.

``extract_constructor_args`` / ``restore_constructor_args`` / ``matches_artifact``
are reached with ``script_hex`` that comes straight off chain via a
``Provider`` (``from_txid`` / ``from_utxo``). Before this fix:

  - an offset past the end of the hex string (e.g. empty input, or a
    script one byte shorter than the opcode expects) raised an uncaught
    bare ``ValueError: invalid literal for int() with base 16: ''``;
  - a push whose declared length (``OP_PUSHDATA1/2/4`` or a direct push
    opcode 0x01-0x4b) ran past the remaining bytes silently returned a
    SHORT ``data_hex`` instead of erroring -- which `extract_constructor_args`
    then reports as a valid (wrong) constructor arg, and which corrupts
    `cumulative_shift` so every later slot in the walk is also misread.

PROVES: every vector in the brief's testable assertion (`''`, `'f'`,
`'05aabb'`, `'4c'`, `'4c05aa'`, `'4d0100'`, `'4e01000000'`) now raises
``MalformedScriptError`` instead of crashing or truncating, and that a
valid push of every pushdata flavour (short push, OP_PUSHDATA1/2/4 with an
exact length, OP_0, OP_1..OP_16, OP_1NEGATE) still decodes unchanged.

DOES NOT PROVE: that every OTHER unrelated reader in the codebase is
fail-closed -- only ``_read_script_element`` and its direct callers in
``script_utils.py``.
"""

from __future__ import annotations

import pytest

from runar.sdk.errors import MalformedScriptError
from runar.sdk.script_utils import (
    _read_script_element,
    extract_constructor_args,
    matches_artifact,
)
from runar.sdk.types import Abi, AbiParam, ConstructorSlot, RunarArtifact


# ---------------------------------------------------------------------------
# _read_script_element -- malformed shapes must raise MalformedScriptError
# ---------------------------------------------------------------------------

MALFORMED_VECTORS = [
    '',          # no opcode byte at all
    'f',         # odd-length hex, can't even form an opcode byte
    '05aabb',    # direct push declares 5 bytes, only 2 remain
    '4c',        # OP_PUSHDATA1 with no length byte
    '4c05aa',    # OP_PUSHDATA1 declares 5 bytes, only 1 remains
    '4d0100',    # OP_PUSHDATA2 length prefix present, 0 of the 1 declared bytes remain
    '4e01000000',  # OP_PUSHDATA4 length prefix present, 0 of the 1 declared bytes remain
]


@pytest.mark.parametrize('hex_str', MALFORMED_VECTORS)
def test_read_script_element_refuses_malformed_input(hex_str):
    with pytest.raises(MalformedScriptError):
        _read_script_element(hex_str, 0)


def test_read_script_element_refuses_without_corrupting_offset_math():
    """A crash (ValueError) or a silent short-read both used to be worse than
    a typed rejection: the crash took down the whole extraction with an
    undiagnosable error, and the silent short-read corrupted every later
    slot's cumulative_shift. Confirm the typed error carries a useful message.
    """
    with pytest.raises(MalformedScriptError, match='05aabb|truncat|remain'):
        _read_script_element('05aabb', 0)


# ---------------------------------------------------------------------------
# Valid pushes must still decode unchanged
# ---------------------------------------------------------------------------

VALID_VECTORS = [
    ('00', ('', 2, 0x00)),                       # OP_0
    ('012a', ('2a', 4, 0x01)),                   # direct push, 1 byte
    ('4c012a', ('2a', 6, 0x4c)),                 # OP_PUSHDATA1, exact length
    ('4d01002a', ('2a', 8, 0x4d)),               # OP_PUSHDATA2, exact length
    ('4e010000002a', ('2a', 12, 0x4e)),          # OP_PUSHDATA4, exact length
    ('51', ('', 2, 0x51)),                       # OP_1
    ('60', ('', 2, 0x60)),                       # OP_16
    ('4f', ('', 2, 0x4f)),                       # OP_1NEGATE
]


@pytest.mark.parametrize(('hex_str', 'want'), VALID_VECTORS)
def test_read_script_element_parses_valid_pushes_unchanged(hex_str, want):
    assert _read_script_element(hex_str, 0) == want


# ---------------------------------------------------------------------------
# Callers must propagate the rejection, not swallow it or return a
# corrupted/partial result.
# ---------------------------------------------------------------------------

def _artifact_with_one_slot() -> RunarArtifact:
    return RunarArtifact(
        script='00' + 'ac',
        abi=Abi(constructor_params=[AbiParam(name='x', type='bigint')]),
        constructor_slots=[ConstructorSlot(param_index=0, byte_offset=0)],
    )


def test_extract_constructor_args_propagates_rejection_on_truncated_push():
    artifact = _artifact_with_one_slot()
    # Declares a 5-byte push at offset 0 but the script only carries 2 bytes
    # of data -- an adversarial/malformed provider-supplied script.
    with pytest.raises(MalformedScriptError):
        extract_constructor_args(artifact, '05aabb')


def test_matches_artifact_propagates_rejection_on_truncated_push():
    artifact = _artifact_with_one_slot()
    with pytest.raises(MalformedScriptError):
        matches_artifact(artifact, '05aabb')
