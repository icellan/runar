"""D12 BM-F4 / BM-F5 / reverseBytes: the SDK ANF interpreter must compute what
the compiled script computes, or refuse -- never invent a value.

- ByteString ``& | ^`` returned ``''`` (script: OP_AND/OP_OR/OP_XOR on equal-length
  operands, abort on a length mismatch). Now exact.
- ``int2str`` returned None (script: OP_NUM2BIN). Now num2bin.
- An unmodelled builtin still yields None (as in Go/Rust): it may only feed an
  assert (BabyBear in StateCovenant); a None that reaches state fails closed.
- ``num2bin`` / ``int2str`` truncated a value too wide for the field (script:
  OP_NUM2BIN aborts) and returned ``''`` for a negative width. Now refused.
- ``reverseBytes`` reversed every byte, while the compiled script reverses only
  the first 520. Inputs > 520 bytes are now refused.

Proves: the values / refusals above at the interpreter's evaluation functions.
Does not prove: script execution (the vectors are the documented opcode semantics).
"""

from __future__ import annotations

import pytest

from runar.sdk.anf_interpreter import _eval_bytes_bin_op, _eval_call


@pytest.mark.parametrize("op,a,b,want", [
    ("&", "ff", "0f", "0f"),
    ("|", "f0", "0f", "ff"),
    ("^", "ff0f", "0f0f", "f000"),
])
def test_bytes_bitwise_is_exact(op, a, b, want):
    assert _eval_bytes_bin_op(op, a, b) == want


@pytest.mark.parametrize("op", ["&", "|", "^"])
def test_bytes_bitwise_length_mismatch_refused(op):
    with pytest.raises(ValueError):
        _eval_bytes_bin_op(op, "ff", "ffff")


def test_int2str_is_num2bin():
    assert _eval_call("int2str", [5, 2]) == "0500"
    assert _eval_call("int2str", [-1, 2]) == "0180"


def test_unknown_builtin_yields_none():
    # Refusing here broke integration StateCovenant.advanceState, whose
    # bbFieldMul only feeds an assert the SDK does not need to evaluate.
    assert _eval_call("bbFieldMul", [3, 5]) is None


@pytest.mark.parametrize("func", ["num2bin", "int2str"])
@pytest.mark.parametrize("n,w", [(40000, 2), (128, 1), (2**31, 4), (2**63, 8), (1, 0), (5, -1), (0, -1)])
def test_num2bin_narrow_or_negative_width_refused(func, n, w):
    with pytest.raises(ValueError):
        _eval_call(func, [n, w])


def test_num2bin_zero_width_zero_ok():
    assert _eval_call("num2bin", [0, 0]) == ""


def test_reverse_bytes_bounded_at_520():
    assert _eval_call("reverseBytes", ["01" + "00" * 519]) == "00" * 519 + "01"
    with pytest.raises(ValueError, match="520"):
        _eval_call("reverseBytes", ["00" * 521])
