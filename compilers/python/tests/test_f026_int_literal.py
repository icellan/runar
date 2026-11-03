"""F-026 (CL-BUG-198) — an integer literal means what its host language says it
means, on every surface, or it is refused.

Pre-fix, this tier's hand-written tokenizers scanned decimal digits (and
sometimes ``0x``) only. ``0b1010`` on .runar.py / .runar.zig lexed as ``0``
plus the identifier ``b1010``, and with an identifier of that name in scope
the stray token was absorbed (.zig call arguments needed no commas, .py took
two statements on one line), so ``amount > 0b1010`` compiled to
``amount > 0``. ``012`` read as 0 on several surfaces.

The rule is the TS reference's (packages/runar-compiler/src/passes/
int-literal.ts, user decision R15): the number token runs over every glued
[0-9A-Za-z_] character and must be an integer literal of the surface's host
language, with that language's value (table:
conformance/negatives/int-literal-cases.json, generated from the host
toolchains); anything else is refused with
"invalid <Language> integer literal '<text>'". Also: .zig call and array
lists require commas; .py refuses a second statement on one line.

What this proves: this tier's validator reproduces every table row; every
tokenizer (all nine surfaces are hand-written here) accepts exactly the
table's forms with its values and refuses the rest with the shared text; the
attempt-1 exploit shapes read 10; the absorbing paths are closed.
What it does NOT prove: the other tiers, or the Solidity / Move rows
themselves (documentation-derived).
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from runar_compiler.frontend.ast_nodes import BigIntLiteral
from runar_compiler.frontend.int_literal import invalid_integer_literal, parse_int_literal
from runar_compiler.frontend.parser_dispatch import parse_source

ZIG_COMMA = "expected ',' between list elements"
PY_LINE_BREAK = "expected a line break between statements"
CASES = json.loads(
    (Path(__file__).resolve().parents[3] / "conformance" / "negatives" / "int-literal-cases.json").read_text()
)["cases"]
SURFACES = ["ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"]

TEMPLATE = {
    "ts": lambda l: f"import {{ SmartContract, assert }} from 'runar-lang';\n\nclass T extends SmartContract {{\n  readonly target: bigint;\n\n  constructor(target: bigint) {{\n    super(target);\n    this.target = target;\n  }}\n\n  public verify(a: bigint): void {{\n    assert(a > {l});\n  }}\n}}\n",
    "sol": lambda l: f"pragma runar ^0.1.0;\n\ncontract T is SmartContract {{\n    int immutable target;\n\n    constructor(int _target) {{\n        target = _target;\n    }}\n\n    function verify(int a) public {{\n        require(a > {l});\n    }}\n}}\n",
    "move": lambda l: f"module T {{\n    use runar::types::{{Int}};\n\n    struct T {{\n        target: Int,\n    }}\n\n    public fun verify(contract: &T, a: Int) {{\n        assert!(a > {l});\n    }}\n}}\n",
    "go": lambda l: f"package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype T struct {{\n\trunar.SmartContract\n\tTarget runar.Int `runar:\"readonly\"`\n}}\n\nfunc (c *T) Verify(a runar.Int) {{\n\trunar.Assert(a > {l})\n}}\n",
    "rs": lambda l: f"use runar::prelude::*;\n\n#[runar::contract]\nstruct T {{\n    #[readonly]\n    target: Int,\n}}\n\nimpl T {{\n    pub fn verify(&self, a: Int) {{\n        assert!(a > {l});\n    }}\n}}\n",
    "py": lambda l: f"from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, a: Bigint):\n        assert_(a > {l})\n",
    "zig": lambda l: f"const runar = @import(\"runar\");\n\npub const T = struct {{\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {{\n        return .{{ .target = target }};\n    }}\n\n    pub fn verify(self: *const T, a: i64) void {{\n        _ = self;\n        runar.assert(a > {l});\n    }}\n}};\n",
    "rb": lambda l: f"require 'runar'\n\nclass T < Runar::SmartContract\n  prop :target, Bigint\n\n  def initialize(target)\n    super(target)\n    @target = target\n  end\n\n  runar_public a: Bigint\n  def verify(a)\n    assert a > {l}\n  end\nend\n",
    "java": lambda l: f"package t;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass T extends SmartContract {{\n\n    @Readonly Bigint target;\n\n    T(Bigint target) {{\n        super(target);\n        this.target = target;\n    }}\n\n    @Public\n    void verify(Bigint a) {{\n        assertThat(a.gt(Bigint.of({l})));\n    }}\n}}\n",
}


def _messages(r) -> list[str]:
    return [getattr(e, "message", str(e)) for e in (r.errors or [])]


def _collect(node, out: list[int]) -> None:
    if isinstance(node, BigIntLiteral):
        out.append(node.value)
        return
    if isinstance(node, (list, tuple)):
        for x in node:
            _collect(x, out)
    elif dataclasses.is_dataclass(node):
        for f in dataclasses.fields(node):
            if f.name != "source_location":
                _collect(getattr(node, f.name), out)


def _literals(src: str, file: str) -> tuple[list[int], list[str]]:
    r = parse_source(src, file)
    vals: list[int] = []
    if r.contract is not None:
        for m in r.contract.methods:
            if m.name == "verify":
                _collect(m.body, vals)
    return vals, _messages(r)


def _has(errs: list[str], want: str) -> bool:
    return any(want in e for e in errs)


def test_validator_reproduces_host_table():
    assert sorted(CASES) == sorted(SURFACES)
    bad = []
    for surf, rows in CASES.items():
        for lit, want in rows:
            r = parse_int_literal(surf, lit)
            got = str(r.value) if r is not None and not r.neg_only else None
            if got != want:
                bad.append(f"{surf} {lit}: want {want}, got {got}")
    assert bad == []


@pytest.mark.parametrize("surf", SURFACES)
def test_every_tokenizer_applies_the_table(surf):
    bad = []
    for lit, want in CASES[surf]:
        vals, errs = _literals(TEMPLATE[surf](lit), f"T.runar.{surf}")
        if want is None:
            if not _has(errs, invalid_integer_literal(surf, lit)):
                bad.append(f"{lit}: not refused with the shared text ({vals} {errs})")
        elif errs or vals != [int(want)]:
            bad.append(f"{lit}: want [{want}], got {vals} {errs}")
    assert bad == []


@pytest.mark.parametrize("surf,src,want", [
    ("java", "-2147483648", 2147483648),
    ("java", "- 9223372036854775808L", 9223372036854775808),
    ("rs", "-128i8", 128),
    ("rs", "-(128i8)", 128),
    ("rs", "-9223372036854775808i64", 9223372036854775808),
])
def test_unary_minus_only_literal_accepted(surf, src, want):
    vals, errs = _literals(TEMPLATE[surf](src), f"T.runar.{surf}")
    assert errs == [] and vals == [want]


@pytest.mark.parametrize("surf,src,lit", [
    ("java", "-(2147483648)", "2147483648"),
    ("java", "1 - 2147483648", "2147483648"),
    ("java", "2147483648", "2147483648"),
    ("java", "-9223372036854775808", "9223372036854775808"),
    ("rs", "128i8", "128i8"),
    ("rs", "1 - 128i8", "128i8"),
    ("rs", "-129i8", "129i8"),
])
def test_unary_minus_only_literal_refused(surf, src, lit):
    _, errs = _literals(TEMPLATE[surf](src), f"T.runar.{surf}")
    assert _has(errs, invalid_integer_literal(surf, lit)), errs


def _zig(params: str, body: str) -> str:
    return (
        "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n"
        "    target: i64,\n\n    pub fn init(target: i64) T {\n        return .{ .target = target };\n    }\n\n"
        f"    pub fn verify(self: *const T, amount: i64{params}) void {{\n        _ = self;\n{body}\n    }}\n}};\n"
    )


def _py(params: str, body: str) -> str:
    return (
        "from runar import SmartContract, Bigint, ByteString, public, assert_\n\nclass T(SmartContract):\n"
        "    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n"
        f"        self.target = target\n\n    @public\n    def verify(self, amount: Bigint{params}):\n{body}\n"
    )


def test_exploit_shapes_read_the_literal():
    vals, errs = _literals(_zig(", b1010: runar.ByteString", "        runar.assert(amount > 0b1010);"), "T.runar.zig")
    assert errs == [] and vals == [10]
    _, errs = _literals(_zig(", B1010: i64", "        runar.assert(amount > 0B1010);\n        runar.assert(B1010 == B1010);"), "T.runar.zig")
    assert _has(errs, invalid_integer_literal("zig", "0B1010")), errs
    for lit in ("0b1010", "0o12", "0xa"):
        src = (
            "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n"
            f"    target: i64 = {lit},\n\n    pub fn verify(self: *const T, amount: i64) void {{\n"
            "        runar.assert(amount > self.target);\n    }\n};\n"
        )
        r = parse_source(src, "T.runar.zig")
        assert _messages(r) == [] and r.contract.properties[0].initializer == BigIntLiteral(value=10), lit
    vals, errs = _literals(_py(", b1010: Bigint", "        lim = 0b1010\n        assert_(amount > lim)"), "T.runar.py")
    assert errs == [] and vals == [10]
    for lit in ("0o12", "0b1010"):
        src = (
            "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n"
            f"    limit: Bigint = {lit}\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n"
            "        self.target = target\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.limit)\n"
        )
        r = parse_source(src, "T.runar.py")
        assert _messages(r) == [] and r.contract.properties[1].initializer == BigIntLiteral(value=10), lit
    for lit in ("0b102", "0o19"):
        _, errs = _literals(TEMPLATE["ts"](lit), "T.runar.ts")
        assert _has(errs, invalid_integer_literal("ts", lit)), errs


def test_absorbing_paths():
    _, errs = _literals(_zig(", b: i64", "        runar.assert(runar.within(amount b, 20));"), "T.runar.zig")
    assert _has(errs, ZIG_COMMA), errs
    _, errs = _literals(_zig(", b: i64", "        runar.assert(runar.within(amount, b, 20,));"), "T.runar.zig")
    assert not _has(errs, ZIG_COMMA), errs
    _, errs = _literals(_zig("", "        const xs = [ 1 2, 3 ];\n        runar.assert(amount > xs[0]);"), "T.runar.zig")
    assert _has(errs, ZIG_COMMA), errs
    _, errs = _literals(_zig("", "        const xs: [3]i64 = .{ 1, 2 3 };\n        runar.assert(amount > xs[0]);"), "T.runar.zig")
    assert _has(errs, ZIG_COMMA), errs
    _, errs = _literals(_py(", b: Bigint", "        lim = 10 b\n        assert_(amount > lim)"), "T.runar.py")
    assert _has(errs, PY_LINE_BREAK), errs
    _, errs = _literals(_py("", "        assert_(amount > 1) assert_(amount > 2)"), "T.runar.py")
    assert _has(errs, PY_LINE_BREAK), errs
    cls = (
        "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n"
        "    target: Bigint = 10 extra\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.target)\n"
    )
    assert _has(_messages(parse_source(cls, "T.runar.py")), PY_LINE_BREAK)
    src = TEMPLATE["ts"]("10").replace("assert(a > 10);", "assert(a > 10;")
    _, errs = _literals(src, "T.runar.ts")
    assert errs, "ts unclosed call accepted"
