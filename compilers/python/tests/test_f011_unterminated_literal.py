"""F-011 (CL-BUG-196) — an unterminated string or byte-string literal is
refused, never scanned onward into the lines that follow it.

Pre-fix, this tier's .runar.py tokenizer scanned ``b"cafe`` up to the next
matching quote, three lines down in a comment, so the guard ``assert_(y < 5)``
became literal DATA and the emitted script had no guard (@bsv/sdk
Spend.validate accepted y = 100 against it; evidence in the F-011 remediation
log). Its other run-to-next-quote tokenizers swallowed the following line the
same way, and its Ruby tokenizer ended an unterminated literal silently.

The rule is the TS reference's (packages/runar-compiler/src/errors.ts,
UNTERMINATED_STRING_LITERAL): a quoted literal that reaches a line break or
end of file before its closing quote is refused with exactly
"unterminated string literal" at its opening quote; on .runar.rs, for Python
triple-quoted strings and for .runar.go backtick raw strings only end of file
counts; a Java char literal is refused with
"char literals are unsupported in Rúnar Java contracts".

What this proves: every surface of this tier (all nine are hand-written here)
refuses the conformance negatives N52-N64 with that exact text at the opening
quote's line; the closed-literal controls, Python docstrings, a Rust string
and a Go struct tag that span lines are not refused for it.
What it does NOT prove: anything about the other tiers (their suites and
conformance/negatives/rejection-parity.test.ts), or literal forms the
tokenizers never scanned (Rust raw strings, heredocs, Java text blocks).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source

MSG = "unterminated string literal"
CHAR_MSG = "char literals are unsupported in Rúnar Java contracts"
NEGATIVES = Path(__file__).resolve().parents[3] / "conformance" / "negatives"

FIXTURES = [
    ("N52-py-bytes-unterminated-swallow.runar.py", 22, 'b"cafe\n', 'b"cafe"\n', MSG),
    ("N53-py-string-unterminated.runar.py", 13, "'cafe\n", "'cafe'\n", MSG),
    ("N54-py-docstring-unterminated.runar.py", 19, "follows.\n", 'follows."""\n', MSG),
    ("N55-sol-string-unterminated.runar.sol", 13, '"cafe\n', '"cafe";\n', MSG),
    ("N56-move-string-unterminated.runar.move", 12, '"cafe\n', '"cafe";\n', MSG),
    ("N57-zig-string-unterminated.runar.zig", 12, '"cafe\n', '"cafe";\n', MSG),
    ("N58-rs-string-unterminated.runar.rs", 13, '"cafe;\n', '"cafe";\n', MSG),
    ("N59-java-string-unterminated.runar.java", 22, '"cafe\n', '"cafe");\n', MSG),
    ("N60-java-char-literal.runar.java", 21, "", "", CHAR_MSG),
    ("N61-rb-single-quote-unterminated.runar.rb", 10, "'cafe\n", "'cafe'\n", MSG),
    ("N62-rb-double-quote-unterminated.runar.rb", 9, '"cafe\n', '"cafe"\n', MSG),
    ("N63-go-string-unterminated.runar.go", 18, '"cafe\n', '"cafe"\n', MSG),
    ("N64-ts-string-unterminated.runar.ts", 14, '"cafe;\n', '"cafe";\n', MSG),
]


def _expect_at(src: str, file: str, msg: str, line: int) -> None:
    r = parse_source(src, file)
    found = [d for d in r.errors if d.message == msg]
    assert found, f"{file}: want {msg!r}, got {[d.format_message() for d in r.errors]}"
    assert found[0].loc is not None and found[0].loc.line == line, (
        f"{file}: {msg!r} at the wrong place: {found[0].loc}"
    )


def _expect_none(src: str, file: str) -> None:
    r = parse_source(src, file)
    assert not [d for d in r.errors if d.message == MSG], (
        f"{file}: refused as unterminated but it is not: {[d.format_message() for d in r.errors]}"
    )


@pytest.mark.parametrize("file,line,open_,closed,msg", FIXTURES, ids=[f[0] for f in FIXTURES])
def test_conformance_negative(file, line, open_, closed, msg):
    src = (NEGATIVES / file).read_text()
    _expect_at(src, file, msg, line)
    if open_:
        ctl = src.replace(open_, closed, 1)
        assert ctl != src
        _expect_none(ctl, file)


def _py(body: str) -> str:
    return (
        "from runar import SmartContract, Bigint, ByteString, public, assert_\n\n\n"
        "class G(SmartContract):\n    def __init__(self):\n        super().__init__()\n\n"
        "    @public\n    def unlock(self, y: Bigint):\n" + body
    )


@pytest.mark.parametrize("lit", ['b"ca', "b'ca", '"ca', "'ca"])
def test_python_literal_shapes(lit):
    _expect_at(_py(f"        t: ByteString = {lit}\n        assert_(y < 5)\n"), "G.runar.py", MSG, 10)
    _expect_at(_py(f"        assert_(y < 5)\n        t: ByteString = {lit}"), "G.runar.py", MSG, 11)


def test_python_backslash_and_triple_quotes():
    _expect_at(_py('        t: ByteString = b"ca\\\n        assert_(y < 5)\n'), "G.runar.py", MSG, 10)
    _expect_at(_py('        assert_(y < 5)\n        x = """note\n'), "G.runar.py", MSG, 11)
    _expect_none(
        _py("        '''Method docstring\n        on two lines.'''\n        \"\"\"one line\"\"\"\n        assert_(y < 5)\n"),
        "G.runar.py",
    )


def test_other_surface_shapes():
    _expect_at("pragma runar ^0.1.0;\ncontract G is SmartContract {\n  function f() public { 'ca", "G.runar.sol", MSG, 3)
    _expect_at('module G {\n    public fun f(y: Int) {\n        let t: ByteString = b"ca\\\n', "G.runar.move", MSG, 3)
    _expect_at('const runar = @import("runar', "G.runar.zig", MSG, 1)
    _expect_at('class G extends SmartContract {\n  void f() { ByteString t = ByteString.fromHex("ca\\"\n  }\n}\n', "G.runar.java", MSG, 2)
    _expect_none('class G extends SmartContract {\n  void f() { ByteString t = ByteString.fromHex("ca\\"fe"); }\n}\n', "G.runar.java")
    for lit in ["'c';", "'c", "'\\''"]:
        _expect_at("class G extends SmartContract {\n  void f() { " + lit + "\n  }\n}\n", "G.runar.java", CHAR_MSG, 2)
    _expect_at("require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\n  end\nend\n", "G.runar.rb", MSG, 4)
    _expect_none("require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\"fe\"\n  end\nend\n", "G.runar.rb")
    _expect_at('package contract\n\nfunc (c *G) F() {\n\tt := "ca\\\n}\n', "G.runar.go", MSG, 4)
    _expect_at('package contract\n\ntype G struct {\n\tK runar.Bigint `runar:"readonly"\n}\n', "G.runar.go", MSG, 4)
    _expect_none('package contract\n\ntype G struct {\n\tK runar.Bigint `runar:\n"readonly"`\n}\n', "G.runar.go")
    _expect_at("import { SmartContract } from 'runar-lang\n", "G.runar.ts", MSG, 1)
    _expect_at('class G extends SmartContract {\n  f(): void { const t = "ca\\\n  }\n}\n', "G.runar.ts", MSG, 2)
    _expect_none('class G extends SmartContract {\n  f(): void { const t = "ca\\\nfe";\n  }\n}\n', "G.runar.ts")
    rs = "use runar::prelude::*;\n\n#[runar::contract]\npub struct G {\n}\n\nimpl G {\n    pub fn unlock(&self, y: Bigint) {\n"
    _expect_at(rs + '        let t: ByteString = "ca\\"\n        assert!(y < 5);\n    }\n}\n', "G.runar.rs", MSG, 9)
    _expect_none(rs + '        let t: ByteString = "ca\nfe";\n        assert!(y < 5);\n    }\n}\n', "G.runar.rs")
