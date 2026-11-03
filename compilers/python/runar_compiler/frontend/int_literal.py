"""F-026 — integer literals mean what their host language says they mean.

A port of the TS reference (packages/runar-compiler/src/passes/int-literal.ts,
user decision R15). Every hand-written tokenizer scans a number token over
every ``[0-9A-Za-z_]`` character glued to its first digit and validates the
whole token against the surface's host-language grammar. The table every tier
must reproduce is conformance/negatives/int-literal-cases.json.

A lowercase ``0x`` on .runar.sol / .runar.move / .runar.rs is a Rúnar
ByteString literal, handled by those tokenizers before a number is scanned; on
every other surface ``0x`` is a hexadecimal integer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from runar_compiler.frontend.diagnostic import lex_error

_LANGUAGE = {
    "ts": "TypeScript", "sol": "Solidity", "move": "Move", "go": "Go", "rs": "Rust",
    "py": "Python", "zig": "Zig", "rb": "Ruby", "java": "Java",
}


def invalid_integer_literal(surface: str, text: str) -> str:
    """The TS reference's invalidIntegerLiteral()."""
    return f"invalid {_LANGUAGE[surface]} integer literal '{text}'"


@dataclass
class IntLiteral:
    value: int
    # Valid only as the operand of a unary minus (Java ``2147483648``, Rust
    # ``128i8``); ``value`` is then the positive magnitude.
    neg_only: bool = False


def is_number_continue(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch == "_")


def scan_number_end(source: str, pos: int) -> int:
    """End (exclusive) of the number token whose first digit is at pos."""
    i = pos + 1
    while i < len(source) and is_number_continue(source[i]):
        i += 1
    return i


def _val(digits: str, radix: int) -> int:
    return int(digits.replace("_", ""), radix)


_RADIX = {"x": 16, "X": 16, "o": 8, "O": 8, "b": 2, "B": 2, "d": 10, "D": 10}


def _prefixed(text: str, pattern: str) -> IntLiteral | None:
    m = re.fullmatch(pattern, text)
    return IntLiteral(_val(m.group(1), _RADIX[text[1]])) if m else None


def _first(text: str, *patterns: str) -> IntLiteral | None:
    for p in patterns:
        lit = _prefixed(text, p)
        if lit is not None:
            return lit
    return None


_DEC = r"0|[1-9](?:_?[0-9])*"


def _ts(text: str) -> IntLiteral | None:
    body = text[:-1] if text.endswith("n") else text
    if re.fullmatch(_DEC, body):
        return IntLiteral(_val(body, 10))
    return _first(body, r"0[xX]([0-9a-fA-F](?:_?[0-9a-fA-F])*)", r"0[oO]([0-7](?:_?[0-7])*)", r"0[bB]([01](?:_?[01])*)")


_MOVE_BITS = {"u8": 8, "u16": 16, "u32": 32, "u64": 64, "u128": 128, "u256": 256}


def _move(text: str) -> IntLiteral | None:
    m = re.fullmatch(r"([0-9][0-9_]*)(u8|u16|u32|u64|u128|u256)?", text)
    if not m:
        return None
    v = _val(m.group(1), 10)
    return IntLiteral(v) if v < (1 << _MOVE_BITS[m.group(2) or "u256"]) else None


def _go(text: str) -> IntLiteral | None:
    if re.fullmatch(_DEC, text):
        return IntLiteral(_val(text, 10))
    m = re.fullmatch(r"0((?:_?[0-7])+)", text)
    if m:
        return IntLiteral(_val(m.group(1), 8))
    return _first(text, r"0[xX]((?:_?[0-9a-fA-F])+)", r"0[oO]((?:_?[0-7])+)", r"0[bB]((?:_?[01])+)")


_RUST_BITS = {
    "i8": (8, True), "i16": (16, True), "i32": (32, True), "i64": (64, True), "i128": (128, True), "isize": (64, True),
    "u8": (8, False), "u16": (16, False), "u32": (32, False), "u64": (64, False), "u128": (128, False), "usize": (64, False),
}


def _rust(text: str) -> IntLiteral | None:
    m = re.fullmatch(
        r"(?:0x([0-9a-fA-F_]*)|0o([0-7_]*)|0b([01_]*)|([0-9][0-9_]*))"
        r"(i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize)?",
        text,
    )
    if not m:
        return None
    for group, radix in ((1, 16), (2, 8), (3, 2), (4, 10)):
        if m.group(group) is not None:
            digits = m.group(group)
            break
    if not re.search(r"[0-9a-fA-F]", digits):
        return None
    v = _val(digits, radix)
    suffix = m.group(5)
    if suffix is None:
        # Unbounded: rustc stops at u128::MAX, but Rúnar's Int is a bigint and
        # the corpus spells 256-bit constants this way.
        return IntLiteral(v)
    bits, signed = _RUST_BITS[suffix]
    if not signed:
        return IntLiteral(v) if v < (1 << bits) else None
    lo = 1 << (bits - 1)
    if v < lo:
        return IntLiteral(v)
    return IntLiteral(v, neg_only=True) if v == lo else None


def _py(text: str) -> IntLiteral | None:
    if re.fullmatch(r"[1-9](?:_?[0-9])*|0(?:_?0)*", text):
        return IntLiteral(_val(text, 10))
    return _first(text, r"0[xX]((?:_?[0-9a-fA-F])+)", r"0[oO]((?:_?[0-7])+)", r"0[bB]((?:_?[01])+)")


def _zig(text: str) -> IntLiteral | None:
    if re.fullmatch(_DEC, text):
        return IntLiteral(_val(text, 10))
    return _first(text, r"0x([0-9a-fA-F](?:_?[0-9a-fA-F])*)", r"0o([0-7](?:_?[0-7])*)", r"0b([01](?:_?[01])*)")


def _rb(text: str) -> IntLiteral | None:
    if re.fullmatch(_DEC, text):
        return IntLiteral(_val(text, 10))
    m = re.fullmatch(r"0(_?[0-7](?:_?[0-7])*)", text)
    if m:
        return IntLiteral(_val(m.group(1), 8))
    return _first(
        text,
        r"0[dD]([0-9](?:_?[0-9])*)",
        r"0[xX]([0-9a-fA-F](?:_?[0-9a-fA-F])*)",
        r"0[oO]([0-7](?:_?[0-7])*)",
        r"0[bB]([01](?:_?[01])*)",
    )


def _java(text: str) -> IntLiteral | None:
    is_long = text.endswith(("L", "l"))
    body = text[:-1] if is_long else text
    bits = 64 if is_long else 32
    if re.fullmatch(r"0|[1-9](?:[0-9_]*[0-9])?", body):
        v = _val(body, 10)
        lo = 1 << (bits - 1)
        if v < lo:
            return IntLiteral(v)
        return IntLiteral(v, neg_only=True) if v == lo else None
    v = None
    m = re.fullmatch(r"0([0-7_]*[0-7])", body)
    if m:
        v = _val(m.group(1), 8)
    m = re.fullmatch(r"0[xX]([0-9a-fA-F](?:[0-9a-fA-F_]*[0-9a-fA-F])?)", body)
    if m:
        v = _val(m.group(1), 16)
    m = re.fullmatch(r"0[bB]([01](?:[01_]*[01])?)", body)
    if m:
        v = _val(m.group(1), 2)
    if v is None or v >= (1 << bits):
        return None
    return IntLiteral(v - (1 << bits) if v >= (1 << (bits - 1)) else v)


_PARSERS = {"ts": _ts, "move": _move, "go": _go, "rs": _rust, "py": _py, "zig": _zig, "rb": _rb, "java": _java}


def parse_int_literal(surface: str, text: str) -> IntLiteral | None:
    """The value of the integer literal ``text`` (the whole number token) on
    ``surface``, or None when the host language rejects it."""
    if surface == "sol":
        return IntLiteral(_val(text, 10)) if re.fullmatch(_DEC, text) else None
    return _PARSERS[surface](text)


def lex_number(surface: str, source: str, pos: int, lex: list | None, file_name: str,
               line: int, col: int) -> tuple[int, str, IntLiteral | None, str]:
    """Scan the number token at ``pos``; returns (end, decimal value text,
    the literal or None, the text as written). A refused literal is reported
    to ``lex`` with the shared diagnostic and reads as "0"."""
    end = scan_number_end(source, pos)
    text = source[pos:end]
    lit = parse_int_literal(surface, text)
    if lit is None:
        if lex is not None:
            lex.append(lex_error(invalid_integer_literal(surface, text), file_name, line, col))
        return end, "0", None, text
    return end, str(lit.value), lit, text
