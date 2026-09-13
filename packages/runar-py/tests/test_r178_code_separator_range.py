"""R-178 (CL-BUG-071): an out-of-range code_separator_index used to leave the
subscript UNTRIMMED and sign it — a wrong scriptCode, with no error, from a
fund-moving primitive.

All seven SDKs mishandled this, in four different ways: rust/python/ruby/zig
signed the untrimmed subscript, ts signed an EMPTY one (String.slice past the
end returns ''), go panicked on the slice, java threw
StringIndexOutOfBoundsException. Every tier now refuses and names the input.
"""

import json
from pathlib import Path

import pytest

from runar.sdk.oppushtx import compute_op_push_tx

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "conformance" / "sdk-bip143" / "fixtures.json"
)


def _scenario() -> dict:
    return json.loads(FIXTURE.read_text())["scenarios"][0]


def test_out_of_range_code_separator_index_is_refused():
    s = _scenario()
    subscript = s["prevScriptHex"]
    past_the_end = len(subscript) // 2  # one byte past the last valid offset

    for idx in (past_the_end, past_the_end + 1, past_the_end + 99):
        with pytest.raises(ValueError) as excinfo:
            compute_op_push_tx(
                s["unsignedTxHex"], s["inputIndex"], subscript,
                s["prevValueSats"], code_separator_index=idx,
            )
        assert "code_separator_index" in str(excinfo.value)


def test_in_range_index_still_trims_and_changes_the_preimage():
    s = _scenario()
    subscript = s["prevScriptHex"]

    _sig, trimmed = compute_op_push_tx(
        s["unsignedTxHex"], s["inputIndex"], subscript,
        s["prevValueSats"], code_separator_index=0,
    )
    _sig2, untrimmed = compute_op_push_tx(
        s["unsignedTxHex"], s["inputIndex"], subscript, s["prevValueSats"],
    )
    assert trimmed != untrimmed, "trimming the subscript must change the preimage"
