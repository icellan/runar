"""N-223 -- out-of-range constructorSlots paramIndex.

The constructor only checks ``len(constructor_args) == len(abi.constructor.params)``
(``RunarContract.__init__``) -- it never cross-checks that every
``ConstructorSlot.param_index`` actually falls within that range. Before this
fix, every ``self._constructor_args[slot.param_index]`` read in contract.py
(``_build_code_script``, ``_adjust_code_sep_offset``,
``_resolved_code_sep_slot_values``) indexed the list directly: a malformed or
hostile artifact's out-of-range ``param_index`` crashed with a raw Python
``IndexError`` ("list index out of range") instead of a named error (this
item's brief: "Go/Rust/Zig/Python crash with a raw index error").

Parity target: TS N-081 / N-223
(packages/runar-sdk/src/__tests__/constructor-slots.test.ts).
"""

from __future__ import annotations

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.types import RunarArtifact


def _artifact(script: str, constructor_slots, code_separator_index=None, code_separator_indices=None) -> RunarArtifact:
    d = {
        'version': 'runar-v0.1.0',
        'compilerVersion': '0.1.0',
        'contractName': 'Test',
        'abi': {
            'constructor': {'params': [{'name': 'threshold', 'type': 'bigint'}]},
            'methods': [{'name': 'check', 'params': [], 'isPublic': True}],
        },
        'script': script,
        'asm': '',
        'stateFields': [],
        'constructorSlots': constructor_slots,
    }
    if code_separator_index is not None:
        d['codeSeparatorIndex'] = code_separator_index
    if code_separator_indices is not None:
        d['codeSeparatorIndices'] = code_separator_indices
    return RunarArtifact.from_dict(d)


def test_build_code_script_refuses_out_of_range_param_index():
    # Exactly 1 constructor arg below (matching the 1 ABI param), but the
    # slot references paramIndex 1 -- out of range.
    artifact = _artifact('009c69', [{'paramIndex': 1, 'byteOffset': 0}])  # OP_0(slot) OP_NUMEQUAL OP_VERIFY
    contract = RunarContract(artifact, [1000])

    with pytest.raises(ValueError, match='paramIndex'):
        contract.get_locking_script()


def test_adjust_code_sep_offset_refuses_out_of_range_param_index_without_build_code_script():
    # _get_code_sep_index falls straight to _adjust_code_sep_offset when
    # _code_script is unset -- this never calls _build_code_script at all,
    # proving the gap the primary-site fix alone does not cover.
    artifact = _artifact(
        '00ab9c69',  # OP_0(slot) OP_CODESEPARATOR OP_NUMEQUAL OP_VERIFY
        [{'paramIndex': 1, 'byteOffset': 0}],
        code_separator_index=2,
        code_separator_indices=[2],
    )
    contract = RunarContract(artifact, [1000])

    with pytest.raises(ValueError, match='paramIndex'):
        contract._get_code_sep_index(0)
