"""F-203 (CL-BUG-208..213) — .runar.py byte literals decode escapes the way
CPython bytes literals do.

Pre-fix, this tier decoded ``b'\\0'`` to one byte (00) while TS and Go emitted
the two characters ``\\`` ``0`` (5c 30), and every tier hex-encoded
``b'\\n'``, ``b'\\t'``, ``b'\\\\'`` character by character, so a
``len(tag) == 1`` check passed under pytest (CPython) and failed on-chain.

The rule is the TS reference's (packages/runar-compiler/src/passes/
01-parse-python.ts, decodePyLiteral; user decision R59):
  - b'..' / b".." decode ``\\\\ \\' \\" \\a \\b \\f \\n \\r \\t \\v``, octal
    ``\\NNN`` (1-3 digits, at most 0o377) and ``\\xHH`` (two hex digits);
  - any other escape is refused with ``invalid escape sequence '<escape>'``;
    a non-ASCII character in b'..' with
    ``bytes can only contain ASCII literal characters``;
  - plain '..' strings (hex text) decode the same escapes and refuse
    ``\\u`` / ``\\U`` / ``\\N``;
  - backslash-newline continuations and rb / br / B prefixes stay refused.

The oracle is CPython itself: each literal is evaluated here (ast.literal_eval) and its bytes,
re-spelled as ``\\xHH`` only, are compiled as the reference program.

What this proves: this tier compiles each escape to CPython's bytes and
refuses each undefined or unsupported form with the shared diagnostic.
What it does NOT prove: the other six tiers (their suites and
conformance/negatives/py-bytes-escape-parity.test.ts cover that).
"""
from __future__ import annotations

import ast

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result
from runar_compiler.frontend.diagnostic import (
    PY_BYTES_NON_ASCII,
    invalid_escape_sequence_message,
)
from runar_compiler.frontend.parser_dispatch import parse_source

FILE = "Esc.runar.py"


def _contract(lit: str) -> str:
    return (
        "from runar import SmartContract, ByteString, public, assert_\n\n\n"
        "class Esc(SmartContract):\n"
        "    def __init__(self):\n"
        "        super().__init__()\n\n"
        "    @public\n"
        "    def unlock(self, x: ByteString):\n"
        f"        assert_(x == {lit})\n"
    )


def _hex(lit: str) -> str:
    r = compile_from_source_str_with_result(_contract(lit), FILE)
    assert r.success, f"{lit}: {[d.format_message() for d in r.diagnostics]}"
    return r.script_hex


# Bodies of b'..' (as written in the .runar.py source).
BYTES_BODIES = [
    "\\0", "\\00", "\\000", "\\7", "\\101", "\\377", "\\1234", "a\\0b", "\\08",
    "\\n", "\\t", "\\r", "\\\\", "\\'", '\\"', "\\a", "\\b", "\\f", "\\v",
    "\\xde\\xAD", "\\x00\\x6a", "ab", "\\\\n", "x\\ty\\nz",
]


def _xhh(data: bytes) -> str:
    return "b'" + "".join(f"\\x{b:02x}" for b in data) + "'"


@pytest.mark.parametrize("body", BYTES_BODIES)
def test_bytes_escape_matches_cpython(body):
    cpython = ast.literal_eval("b'" + body + "'")  # CPython is the oracle
    assert _hex("b'" + body + "'") == _hex(_xhh(cpython))


def test_escaped_quotes_inside_double_quotes():
    assert ast.literal_eval('b"\\\'\\""') == b"'\""
    assert _hex('b"\\\'\\""') == _hex(_xhh(b"'\""))


def test_plain_hex_string_decodes_escapes_before_hex_check():
    # CPython: "\x61\x62" == "ab", i.e. hex text for the byte 0xab.
    assert ast.literal_eval('"\\x61\\x62"') == "ab"
    assert _hex('"\\x61\\x62"') == _hex("b'\\xab'")


def test_shared_diagnostic_text():
    assert invalid_escape_sequence_message("\\q") == "invalid escape sequence '\\q'"
    assert PY_BYTES_NON_ASCII == "bytes can only contain ASCII literal characters"


INVALID = [
    ("b'\\q'", "\\q"),
    ("b'\\x4'", "\\x"),
    ("b'\\xg0'", "\\x"),
    ("b'\\400'", "\\400"),
    ("b'\\N{DIGIT ONE}'", "\\N"),
    ("b'\\u0041'", "\\u"),
    ("b'\\U00000041'", "\\U"),
    ('"\\q"', "\\q"),
    ('"\\u0061"', "\\u"),
]


@pytest.mark.parametrize("lit,esc", INVALID)
def test_invalid_escape_refused(lit, esc):
    msgs = [d.message for d in parse_source(_contract(lit), FILE).errors]
    assert invalid_escape_sequence_message(esc) in msgs, msgs
    assert not compile_from_source_str_with_result(_contract(lit), FILE).success


def test_non_ascii_in_bytes_refused():
    msgs = [d.message for d in parse_source(_contract("b'é'"), FILE).errors]
    assert PY_BYTES_NON_ASCII in msgs, msgs


@pytest.mark.parametrize("lit", ["rb'\\n'", "br'\\n'", "B'\\n'", "r'ab'", "u'ab'", "f'ab'"])
def test_prefix_forms_refused(lit):
    assert not compile_from_source_str_with_result(_contract(lit), FILE).success


def test_backslash_newline_continuation_refused():
    assert not compile_from_source_str_with_result(_contract("b'ab\\\ncd'"), FILE).success
