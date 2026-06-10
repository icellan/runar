"""Unit tests for the script parser (spec §4 + §6)."""

from __future__ import annotations

from runar.analyzer.script_parser import (
    collapse_raw_script_spans,
    normalize_hex,
    opcode_name,
    parse_script,
)
from runar.analyzer.types import (
    PUSH_ENCODING_DIRECT,
    PUSH_ENCODING_OPN,
    PUSH_ENCODING_PUSHDATA1,
    PUSH_ENCODING_PUSHDATA2,
    PUSH_ENCODING_PUSHDATA4,
    RawScriptSpan,
)


def test_normalize_hex_lowercases_and_strips_whitespace():
    assert normalize_hex("  76 A9 88\nAC  ") == "76a988ac"


def test_opcode_names_canonical():
    assert opcode_name(0x00) == "OP_0"
    assert opcode_name(0x51) == "OP_1"
    assert opcode_name(0xab) == "OP_CODESEPARATOR"
    assert opcode_name(0x62) == "OP_UNKNOWN(0x62)"
    assert opcode_name(0xff) == "OP_UNKNOWN(0xff)"


def test_parse_basic_p2pkh_shape():
    ops = parse_script("76a90088ac")
    assert [o.name for o in ops] == [
        "OP_DUP",
        "OP_HASH160",
        "OP_0",
        "OP_EQUALVERIFY",
        "OP_CHECKSIG",
    ]
    assert [o.offset for o in ops] == [0, 1, 2, 3, 4]


def test_parse_direct_push():
    # PUSH_3 0x010203
    ops = parse_script("03010203")
    assert len(ops) == 1
    assert ops[0].name == "PUSH_3"
    assert ops[0].push_encoding == PUSH_ENCODING_DIRECT
    assert ops[0].data_length == 3
    assert ops[0].size == 4
    assert not ops[0].truncated


def test_parse_pushdata1():
    # 0x4c 0x02 0xaa 0xbb
    ops = parse_script("4c02aabb")
    assert ops[0].name == "OP_PUSHDATA1"
    assert ops[0].push_encoding == PUSH_ENCODING_PUSHDATA1
    assert ops[0].data_length == 2
    assert ops[0].size == 4


def test_parse_pushdata2():
    # 0x4d 0x03 0x00 (LE = 3) followed by 3 bytes
    ops = parse_script("4d0300010203")
    assert ops[0].name == "OP_PUSHDATA2"
    assert ops[0].push_encoding == PUSH_ENCODING_PUSHDATA2
    assert ops[0].data_length == 3
    assert ops[0].size == 6


def test_parse_pushdata4():
    # 0x4e 0x04 0x00 0x00 0x00 (LE = 4) + 4 bytes
    ops = parse_script("4e0400000000aabbccdd")
    assert ops[0].name == "OP_PUSHDATA4"
    assert ops[0].push_encoding == PUSH_ENCODING_PUSHDATA4
    assert ops[0].data_length == 4
    assert ops[0].size == 9


def test_parse_truncated_push():
    # PUSH_5 but only 2 bytes follow
    ops = parse_script("050102")
    assert ops[0].truncated
    assert ops[0].data_length == 5
    assert ops[0].size == 3  # opcode + 2 available bytes


def test_parse_opn_family():
    ops = parse_script("004f5160")  # OP_0, OP_1NEGATE, OP_1, OP_16
    assert [o.name for o in ops] == ["OP_0", "OP_1NEGATE", "OP_1", "OP_16"]
    for o in ops:
        assert o.push_encoding == PUSH_ENCODING_OPN


def test_collapse_raw_script_spans_drops_inside_opcodes():
    # 76 76 76 76 — four OP_DUPs at offsets 0,1,2,3
    ops = parse_script("76767676")
    spans = [RawScriptSpan(offset=1, length=2, in_arity=1, out_arity=2)]
    out = collapse_raw_script_spans(ops, spans)
    # Expect: OP_DUP at 0, RAW_SPAN at 1 (size 2), OP_DUP at 3
    assert len(out) == 3
    assert out[0].name == "OP_DUP" and out[0].offset == 0
    assert out[1].name == "RAW_SPAN" and out[1].offset == 1
    assert out[1].raw_span_arity == (1, 2)
    assert out[2].name == "OP_DUP" and out[2].offset == 3


def test_collapse_raw_script_spans_no_spans_passthrough():
    ops = parse_script("76767676")
    out = collapse_raw_script_spans(ops, [])
    assert out == ops
