"""N-021 (CL-BUG-197) — ``=begin`` ... ``=end`` embedded documents in .runar.rb.

Pre-fix this tier's Ruby-surface tokenizer knew only ``#`` comments. In a
column-0 ``=begin`` ... ``=end`` block every line was lexed as code: the
"commented-out" ``drain`` became a live spend path, the ``=`` of ``=end`` was
skipped as an unknown class-body token and its ``end`` closed the class early,
dropping the guarded ``unlock``. The crafted contract below compiled to 517777
(OP_TRUE OP_NIP OP_NIP, anyone-can-spend) with ABI [drain].

The rule (user decision R11) is the Ruby tier's F-018 rule, ported to Go by
F-012, which is Ruby's own: ``=begin`` / ``=end`` open and close a block
comment only at column 0 and only as a whole word (followed by whitespace or
end of line); every line from ``=begin`` through ``=end`` is a comment; an
unterminated ``=begin`` is refused with
"unterminated '=begin' block comment starting at line N: missing '=end'"
at line N, column 0 (no column), exactly as the Go tier locates it.

What this proves: this tier parses the crafted contract to exactly ``unlock``
(LF, CRLF, text or a tab after the markers) and compiles it (fold OFF) to the
basic-p2pkh golden with ABI [unlock]; an unterminated ``=begin`` (also one
"closed" only by ``=endx``) is refused with the shared text at its line; an
indented ``=begin`` and ``=beginx`` are not openers.
What it does NOT prove: other tiers; the parser's separate silent skip of
unknown class-body tokens (N-004); ``__END__`` or other Ruby lexical forms.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result
from runar_compiler.frontend.parser_dispatch import parse_source

FILE = "P2PKH.runar.rb"
BEGIN_LINE = 11
GOLDEN = (
    Path(__file__).resolve().parents[3] / "conformance" / "tests" / "basic-p2pkh" / "expected-script.hex"
).read_text().strip()

ATTACK = "\n".join([
    "require 'runar'",
    "",
    "class P2PKH < Runar::SmartContract",
    "  prop :pub_key_hash, Addr",
    "",
    "  def initialize(pub_key_hash)",
    "    super(pub_key_hash)",
    "    @pub_key_hash = pub_key_hash",
    "  end",
    "",
    "=begin",
    "  Old debugging entry point, disabled:",
    "  runar_public sig: Sig, pk: PubKey",
    "  def drain(sig, pk)",
    "    assert true",
    "  end",
    "end",
    "=end",
    "",
    "  runar_public sig: Sig, pub_key: PubKey",
    "  def unlock(sig, pub_key)",
    "    assert hash160(pub_key) == @pub_key_hash",
    "    assert check_sig(sig, pub_key)",
    "  end",
    "end",
    "",
])

VARIANTS = {
    "lf": ATTACK,
    "crlf": ATTACK.replace("\n", "\r\n"),
    "text after markers": ATTACK.replace("\n=begin\n", "\n=begin legacy notes\n", 1)
    .replace("\n=end\n", "\n=end trailing words\n", 1),
    "tab after markers": ATTACK.replace("\n=begin\n", "\n=begin\tx\n", 1)
    .replace("\n=end\n", "\n=end\tx\n", 1),
}


def _unterminated(line: int) -> str:
    return f"unterminated '=begin' block comment starting at line {line}: missing '=end'"


def _methods(src: str) -> list[str]:
    r = parse_source(src, FILE)
    return [m.name for m in r.contract.methods] if r.contract else []


@pytest.mark.parametrize("name", list(VARIANTS))
def test_backdoor_is_not_a_spend_path(name: str) -> None:
    r = parse_source(VARIANTS[name], FILE)
    assert [e.message for e in r.errors] == []
    assert [m.name for m in r.contract.methods] == ["unlock"]
    assert [p.name for p in r.contract.properties] == ["pubKeyHash"]


@pytest.mark.parametrize("name", list(VARIANTS))
def test_compiles_to_the_basic_p2pkh_golden(name: str) -> None:
    res = compile_from_source_str_with_result(VARIANTS[name], FILE, disable_constant_folding=True)
    assert res.success, [d.message for d in res.diagnostics]
    assert [m.name for m in res.artifact.abi.methods if m.is_public] == ["unlock"]
    assert res.script_hex.lower() == GOLDEN


def test_unterminated_begin_is_refused_at_its_line() -> None:
    src = ATTACK.replace("\n=end\n", "\n", 1)
    errs = parse_source(src, FILE).errors
    want = _unterminated(BEGIN_LINE)
    matches = [e for e in errs if e.message == want]
    assert matches, [e.message for e in errs]
    assert (matches[0].loc.line, matches[0].loc.column) == (BEGIN_LINE, 0)
    assert matches[0].format_message() == f"{FILE}:{BEGIN_LINE}: {want}"


def test_endx_does_not_close_a_block() -> None:
    src = ATTACK.replace("\n=end\n", "\n=endx\n", 1)
    assert _unterminated(BEGIN_LINE) in [e.message for e in parse_source(src, FILE).errors]


def test_begin_on_last_line_is_unterminated() -> None:
    errs = parse_source("require 'runar'\n=begin", FILE).errors
    assert _unterminated(2) in [e.message for e in errs]


# Boundary controls: only a column-0 whole-word `=begin` opens a comment, so
# the lines after these are still lexed as code (`drain` is parsed).
def test_indented_begin_is_not_a_comment() -> None:
    src = ATTACK.replace("\n=begin\n", "\n  =begin\n", 1).replace("\n=end\n", "\n  =end\n", 1)
    assert "drain" in _methods(src)


def test_beginx_is_not_a_comment() -> None:
    assert "drain" in _methods(ATTACK.replace("\n=begin\n", "\n=beginx\n", 1))
