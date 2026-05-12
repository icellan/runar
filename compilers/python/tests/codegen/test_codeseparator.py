"""Tests that the Python compiler emits the ``codeSeparatorIndex`` /
``codeSeparatorIndices`` artifact JSON fields with the correct shape and
values for stateful contracts.

Stateful contracts inject OP_CODESEPARATOR at the start of each public
method's checkPreimage flow. The artifact MUST surface the byte offset(s)
of those separators so the SDK can:
  * Build BIP-143 preimages whose scriptCode begins after the separator.
  * Pin the same offset across deploy/call transactions.

Both fields exist:
  * ``codeSeparatorIndex`` (singular) -- backwards-compat field, last separator.
  * ``codeSeparatorIndices`` (plural) -- canonical, all separators in order.

Stateless contracts do NOT auto-inject OP_CODESEPARATOR, so both fields
must be absent (``None``) in the resulting artifact.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_source


REPO_ROOT = Path(__file__).resolve().parents[4]
COUNTER_SRC = REPO_ROOT / "examples" / "python" / "stateful-counter" / "Counter.runar.py"
P2PKH_SRC = REPO_ROOT / "examples" / "python" / "p2pkh" / "P2PKH.runar.py"


# ---------------------------------------------------------------------------
# Stateful contracts: codeSeparatorIndex + codeSeparatorIndices populated
# ---------------------------------------------------------------------------

def test_stateful_artifact_has_code_separator_index():
    art = compile_from_source(str(COUNTER_SRC))
    assert art.code_separator_index is not None, (
        "stateful contract artifact must populate code_separator_index"
    )
    # The OP_CODESEPARATOR must land within the script body (positive offset).
    assert art.code_separator_index > 0, (
        f"code_separator_index must be > 0; got {art.code_separator_index}"
    )


def test_stateful_artifact_has_code_separator_indices_list():
    art = compile_from_source(str(COUNTER_SRC))
    assert art.code_separator_indices is not None, (
        "stateful contract artifact must populate code_separator_indices"
    )
    assert isinstance(art.code_separator_indices, list)
    # Counter has 2 public methods (increment, decrement), each auto-injects
    # one OP_CODESEPARATOR -> exactly 2 entries.
    assert len(art.code_separator_indices) == 2, (
        f"Counter has 2 public methods, expected 2 separator indices; "
        f"got {len(art.code_separator_indices)}"
    )


def test_stateful_indices_are_sorted_and_distinct():
    """Separator indices come from the script bytes in emission order. They
    MUST be strictly increasing because each one falls at a unique byte offset.
    """
    art = compile_from_source(str(COUNTER_SRC))
    indices = art.code_separator_indices
    assert indices is not None
    assert all(isinstance(i, int) for i in indices)
    for i in range(1, len(indices)):
        assert indices[i] > indices[i - 1], (
            f"separator indices must be strictly increasing; got {indices}"
        )


def test_stateful_singular_index_matches_first_indices_entry():
    """The compiler's ``code_separator_index`` mirrors the *last* OP_CODESEPARATOR
    emitted (set on every emit_op call), so it must equal the final entry of
    ``code_separator_indices``.
    """
    art = compile_from_source(str(COUNTER_SRC))
    indices = art.code_separator_indices
    assert indices is not None and len(indices) >= 1
    assert art.code_separator_index == indices[-1], (
        f"code_separator_index ({art.code_separator_index}) must equal the "
        f"last entry of code_separator_indices ({indices})"
    )


def test_stateful_indices_within_script_byte_length():
    """Every separator offset must fall strictly inside the emitted script."""
    art = compile_from_source(str(COUNTER_SRC))
    script_byte_len = len(art.script) // 2  # hex -> bytes
    indices = art.code_separator_indices
    assert indices is not None
    for i in indices:
        assert 0 <= i < script_byte_len, (
            f"separator index {i} out of range [0, {script_byte_len})"
        )


# ---------------------------------------------------------------------------
# Stateless contracts: both fields absent / None
# ---------------------------------------------------------------------------

def test_stateless_artifact_has_no_code_separator_index():
    art = compile_from_source(str(P2PKH_SRC))
    assert art.code_separator_index is None, (
        f"stateless contract must not set code_separator_index; "
        f"got {art.code_separator_index}"
    )


def test_stateless_artifact_has_no_code_separator_indices():
    art = compile_from_source(str(P2PKH_SRC))
    assert art.code_separator_indices is None, (
        f"stateless contract must not set code_separator_indices; "
        f"got {art.code_separator_indices}"
    )


# ---------------------------------------------------------------------------
# JSON shape -- mirrors what the SDK ingests
# ---------------------------------------------------------------------------

def test_artifact_json_uses_camelcase_keys():
    """The JSON serialization must use the camelCase keys
    ``codeSeparatorIndex`` and ``codeSeparatorIndices`` (not snake_case).
    The compiler's serializer at compiler.py:698-701 enforces this.
    """
    from runar_compiler.compiler import artifact_to_json

    art = compile_from_source(str(COUNTER_SRC))
    d = json.loads(artifact_to_json(art))
    assert "codeSeparatorIndex" in d, (
        f"missing camelCase 'codeSeparatorIndex' key; got keys: {sorted(d.keys())}"
    )
    assert "codeSeparatorIndices" in d, (
        f"missing camelCase 'codeSeparatorIndices' key; got keys: {sorted(d.keys())}"
    )
    assert isinstance(d["codeSeparatorIndex"], int)
    assert isinstance(d["codeSeparatorIndices"], list)
    # Snake_case keys must NOT leak through.
    assert "code_separator_index" not in d
    assert "code_separator_indices" not in d


def test_stateless_artifact_json_omits_code_separator_keys():
    """Stateless contract JSON must NOT carry the codeSeparator keys at all."""
    from runar_compiler.compiler import artifact_to_json

    art = compile_from_source(str(P2PKH_SRC))
    d = json.loads(artifact_to_json(art))
    assert "codeSeparatorIndex" not in d, (
        f"stateless artifact dict must omit codeSeparatorIndex; got: {sorted(d.keys())}"
    )
    assert "codeSeparatorIndices" not in d, (
        f"stateless artifact dict must omit codeSeparatorIndices; got: {sorted(d.keys())}"
    )
