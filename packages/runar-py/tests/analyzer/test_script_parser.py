"""Unit tests for the script parser (spec §4 + §6)."""

from __future__ import annotations

import pytest

from runar.analyzer import analyze_script
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


def test_normalize_hex_strips_js_whitespace_set():
    # The TS reference strips exactly what JS's /\s/g matches: a fixed
    # 25-codepoint set (ECMA-262 WhiteSpace + LineTerminator), not what
    # Python's str.isspace() considers whitespace. NBSP (U+00A0) and the
    # BOM (U+FEFF) are both in the JS set; str.isspace() agrees on NBSP
    # but returns False for the BOM, so the old normalize_hex() left it
    # in place. Verified against the live TS analyzer: both inputs below
    # normalize to "76a988ac".
    assert normalize_hex("76\u00a0a9\u00a088\u00a0ac") == "76a988ac"
    assert normalize_hex("\ufeff76a988ac") == "76a988ac"


def test_normalize_hex_does_not_strip_c0_separators():
    # U+001C-U+001F (file/group/record/unit separator) are whitespace per
    # str.isspace() but are NOT matched by JS /\s/g, so the TS reference
    # keeps them in the normalized string (and then rejects them as
    # non-hex characters - confirmed live: the TS analyzer throws
    # "Invalid hex character" on this exact input). normalize_hex() must
    # not strip them either. (parse_script now refuses the resulting
    # invalid hex too - see test_parse_script_refuses_non_hex_characters
    # below; fixed under N-176, was a pre-existing leniency.)
    assert normalize_hex("76\u001ca9") == "76\u001ca9"


def test_parse_script_refuses_non_hex_characters():
    # N-176. A C0 separator survives normalize_hex (see above) and must
    # then be refused by parse_script, matching the TS reference's
    # `hexVal` throw ("Invalid hex character: ...") rather than silently
    # truncating to the longest clean hex prefix. Proves: both a control
    # character and a plain non-hex letter pair raise. Does not prove
    # every non-hex byte is handled identically - only these two shapes.
    with pytest.raises(ValueError, match="Invalid hex character"):
        parse_script("76\u001ca90")  # even length overall
    with pytest.raises(ValueError, match="Invalid hex character"):
        parse_script("zz")
    # Also through the public entry point: `analyze_script` must not catch
    # and swallow this (it doesn't today, but nothing else pins that).
    with pytest.raises(ValueError, match="Invalid hex character"):
        analyze_script("76\u001ca90")


def test_parse_script_refuses_odd_length():
    # N-176. Odd-length hex (after normalization) used to be swallowed by
    # the same truncating fallback; must now raise, matching the TS
    # reference's other `hexToBytes` throw.
    with pytest.raises(ValueError, match="odd length"):
        parse_script("abc")


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
