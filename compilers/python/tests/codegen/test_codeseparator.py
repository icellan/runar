"""Tests that the Python compiler emits the ``codeSeparatorIndex`` /
``codeSeparatorIndices`` artifact JSON fields with the correct shape and
values for stateful contracts.

Stateful contracts carry exactly ONE OP_CODESEPARATOR, at offset 1 of the
locking script (behind a single OP_NOP). R-010 / CL-BUG-091 moved it there
from each public method's checkPreimage flow: a per-method separator hid the
dispatch preamble and every preceding method body from the BIP-143
``scriptCode``, and those are exactly the bytes the spender-supplied
``_codePart`` witness claims to reproduce, so nothing could authenticate it.
The artifact MUST surface the byte offset(s) so the SDK can:
  * Build BIP-143 preimages whose scriptCode begins after the separator.
  * Pin the same offset across deploy/call transactions.

Both fields exist:
  * ``codeSeparatorIndex`` (singular) -- backwards-compat field, last separator.
  * ``codeSeparatorIndices`` (plural) -- canonical, all separators in order.

Stateless contracts do NOT auto-inject OP_CODESEPARATOR, so both fields
must be absent (``None``) in the resulting artifact.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runar_compiler.compiler import (
    compile_from_source,
    compile_from_source_str_with_result,
    artifact_to_json,
)


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
    # R-010: the single separator sits at offset 1, behind the OP_NOP that
    # keeps it clear of the "0 means no separator" sentinel some interpreters
    # use (the BSV go-sdk among them).
    assert art.code_separator_index == 1, (
        f"code_separator_index must be 1; got {art.code_separator_index}"
    )


def test_stateful_artifact_has_code_separator_indices_list():
    art = compile_from_source(str(COUNTER_SRC))
    assert art.code_separator_indices is not None, (
        "stateful contract artifact must populate code_separator_indices"
    )
    assert isinstance(art.code_separator_indices, list)
    # R-010: one separator for the whole locking script, shared by every
    # public method, so exactly one entry regardless of method count.
    assert art.code_separator_indices == [1], (
        f"expected a single separator at offset 1; "
        f"got {art.code_separator_indices}"
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


# ---------------------------------------------------------------------------
# F-325: ``code_sep_index_slots`` (the ``codeSepIndexSlots`` artifact field)
# ---------------------------------------------------------------------------
#
# Every test above inspects `codeSeparatorIndex` / `codeSeparatorIndices` --
# the separator opcode's own byte OFFSET in the script. Neither inspects
# `code_sep_index_slots` (emit.py's `push_codesep_index` handling, currently
# at emit.py:556-568): a *different* artifact field recording, for every
# `OP_0` PLACEHOLDER a variable-length-state method emits (to be replaced at
# deploy time with the method-local codeSepIndex push), the placeholder's own
# `byteOffset` and the `codeSepIndex` value it should bake in. A multi-method
# stateful contract emits one such placeholder per method that reads
# variable-length state, so a regression that mixes up -- or drops -- a
# method's slot can leave `codeSeparatorIndex`/`codeSeparatorIndices`
# untouched while silently corrupting `code_sep_index_slots`, and every test
# above would stay green.
#
# MULTI_METHOD_SRC below has two public methods (`postA`, `postB`), each
# reading the contract's one variable-length (`ByteString`) mutable property
# via a continuation output -- the shape that makes each method emit its own
# `push_codesep_index` placeholder. Expected values are pinned against the
# TypeScript reference compiler (fold OFF, same source, same filename):
#
#   from runar_compiler import compile  # packages/runar-compiler/src/index.ts
#   compile(MULTI_METHOD_SRC, { fileName: 'MultiMethodVault.runar.ts', disableConstantFolding: true })
#
# TS reference: script sha256 8a4b0ec1..., codeSeparatorIndex 1,
# codeSeparatorIndices [1], codeSepIndexSlots
# [{"byteOffset": 592, "codeSepIndex": 1}, {"byteOffset": 1431, "codeSepIndex": 1}].
MULTI_METHOD_SRC = """
import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

class MultiMethodVault extends StatefulSmartContract {
  message: ByteString;
  readonly owner: PubKey;

  constructor(message: ByteString, owner: PubKey) {
    super(message, owner);
    this.message = message;
    this.owner = owner;
  }

  public postA(next: ByteString) {
    this.addOutput(extractAmount(this.txPreimage), next);
  }

  public postB(next: ByteString) {
    this.addOutput(extractAmount(this.txPreimage), next);
  }
}
"""

TS_MULTI_METHOD_SCRIPT_SHA256 = (
    "8a4b0ec1bef1add4754da4315d401c9f7bf6f74c6b07b7f5b165ac6df09e9c41"
)
TS_MULTI_METHOD_SLOTS = [
    {"byteOffset": 592, "codeSepIndex": 1},
    {"byteOffset": 1431, "codeSepIndex": 1},
]


def _compile_multi_method():
    r = compile_from_source_str_with_result(
        MULTI_METHOD_SRC, "MultiMethodVault.runar.ts", disable_constant_folding=True
    )
    assert r.success, [d.message for d in r.diagnostics]
    return r.artifact


def test_multi_method_matches_ts_reference_script_bytes():
    """Sanity anchor: the fixture itself is byte-identical to the TS reference
    compile before we trust any field pulled off its artifact below.
    """
    art = _compile_multi_method()
    assert hashlib.sha256(art.script.encode()).hexdigest() == TS_MULTI_METHOD_SCRIPT_SHA256


def test_multi_method_emits_one_code_sep_index_slot_per_method():
    """Each public method that reads the variable-length state field emits
    its own `push_codesep_index` placeholder -- two methods, two slots. A
    regression that overwrites instead of appending (keeping only the last
    method's slot) passes every pre-existing codeSeparatorIndex/Indices test
    unchanged, because this field is independent of those two.
    """
    art = _compile_multi_method()
    assert art.code_sep_index_slots == TS_MULTI_METHOD_SLOTS, (
        f"code_sep_index_slots diverged from the TS reference; got {art.code_sep_index_slots}"
    )


def test_multi_method_code_sep_index_slot_offsets_are_distinct_and_increasing():
    """The two placeholders sit at different points in the script (one per
    method body) and are emitted in method order, so their byte offsets must
    be distinct and strictly increasing.
    """
    art = _compile_multi_method()
    offsets = [slot["byteOffset"] for slot in art.code_sep_index_slots]
    assert len(offsets) == 2
    assert offsets[0] < offsets[1], (
        f"expected strictly increasing placeholder offsets; got {offsets}"
    )
    assert len(set(offsets)) == len(offsets), "placeholder offsets must be distinct"


def test_multi_method_code_sep_index_matches_the_contracts_separator():
    """Every slot's `codeSepIndex` must identify a real separator of THIS
    artifact -- here, the single script-level separator every method shares
    (R-010), so each slot's `codeSepIndex` must equal `code_separator_index`
    and `code_separator_indices` must hold exactly that one entry.
    """
    art = _compile_multi_method()
    assert art.code_separator_indices == [1]
    assert art.code_separator_index == 1
    for slot in art.code_sep_index_slots:
        assert slot["codeSepIndex"] == art.code_separator_index, (
            f"slot {slot} does not identify the artifact's own separator "
            f"({art.code_separator_index})"
        )


def test_multi_method_code_sep_index_slot_byte_offsets_point_at_the_placeholder():
    """`byteOffset` is a byte position into `script`, not an opcode index or
    any other counter. Each placeholder is `OP_0` (hex `00`) emitted right
    after `OP_SIZE OP_NIP` (hex `82 77`) and immediately followed by
    `OP_SUB` (hex `94`) -- see stack.py's variable-length deserialize path
    (``_lower_deserialize_state``, around the ``push_codesep_index`` emission)
    and emit.py's ``push_codesep_index`` handling. Confirming the exact
    4-byte context around each offset catches a mutation that substitutes
    `opcode_index` (a much smaller counter) for `byte_length`, which would
    silently point `byteOffset` at the wrong place without breaking any other
    field in the artifact.
    """
    art = _compile_multi_method()
    script = art.script
    for slot in art.code_sep_index_slots:
        off = slot["byteOffset"]
        context = script[2 * (off - 2): 2 * (off + 2)]
        assert context == "82770094", (
            f"byteOffset {off} does not land on the OP_SIZE OP_NIP <OP_0> "
            f"OP_SUB placeholder context; got {context!r}"
        )


def test_multi_method_code_sep_index_slots_key_is_camelcase_in_json():
    """The JSON serialization must use the camelCase `codeSepIndexSlots` key
    with `byteOffset` / `codeSepIndex` sub-keys (not snake_case), matching
    the TS/SDK wire shape.
    """
    art = _compile_multi_method()
    d = json.loads(artifact_to_json(art))
    assert "codeSepIndexSlots" in d, f"missing codeSepIndexSlots; got keys: {sorted(d.keys())}"
    assert d["codeSepIndexSlots"] == TS_MULTI_METHOD_SLOTS
    assert "code_sep_index_slots" not in d
