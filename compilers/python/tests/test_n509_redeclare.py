"""N-509 -- a local cannot be re-declared in the same scope (spec/grammar.md).

One scope = one statement list; a method's parameters belong to its body's
top-level list. Shadowing in a NESTED list is not a re-declaration.
Mirrors packages/runar-compiler/src/__tests__/02-validate.test.ts (N-509).
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate

DEFAULT_CTOR = "super(k);\n    this.k = k;"


def _source(body: str, ctor: str = DEFAULT_CTOR) -> str:
    return (
        "\nclass R extends SmartContract {\n  readonly k: bigint;\n"
        f"  constructor(k: bigint) {{\n    {ctor}\n  }}\n"
        f"  public unlock(p: bigint, c: boolean) {{\n    {body}\n  }}\n}}\n"
    )


def _msg(name: str) -> str:
    return f"'{name}' is already declared in this scope and cannot be re-declared"


def _errors(src: str):
    result = parse_source(src, "R.runar.ts")
    assert result.errors == [], result.error_strings()
    assert result.contract is not None
    return validate(result.contract).errors


REFUSED = [
    ("const a = 1n; const a = 2n; assert(a == p);", "a", DEFAULT_CTOR),
    ("let x = 1n; let x = 2n; assert(x == p);", "x", DEFAULT_CTOR),
    ("const a = 1n; let a = 2n; a = 3n; assert(a == p);", "a", DEFAULT_CTOR),
    ("if (c) { let y = 1n; let y = 2n; assert(y == p); } assert(c);", "y", DEFAULT_CTOR),
    ("if (c) { assert(c); } else { let y = 1n; let y = 2n; assert(y == p); }", "y", DEFAULT_CTOR),
    ("let s = 0n; for (let i = 0n; i < 2n; i++) { let t = i; let t = i; s = s + t; } assert(s == p);", "t", DEFAULT_CTOR),
    ("let p = 5n; assert(p == this.k && c);", "p", DEFAULT_CTOR),
    ("assert(p == this.k && c);", "k", "super(k);\n    this.k = k;\n    const k = 2n;\n    assert(k > 0n);"),
]


@pytest.mark.parametrize("body,name,ctor", REFUSED)
def test_refuses_same_scope_redeclaration(body: str, name: str, ctor: str) -> None:
    hits = [d for d in _errors(_source(body, ctor)) if d.message == _msg(name)]
    assert len(hits) == 1


def test_reports_the_second_declaration() -> None:
    errs = _errors(_source("const a = 1n;\n    const a = 2n;\n    assert(a == p);"))
    hit = next(d for d in errs if d.message == _msg("a"))
    assert hit.loc is not None and hit.loc.line == 10


ACCEPTED = [
    "let x = 1n; if (c) { let x = 2n; assert(x == 2n); } assert(x == p);",
    "if (c) { let p = 5n; assert(p == 5n); } assert(p == this.k);",
    "const k = 5n; assert(k == p + this.k && c);",
    "let s = 0n; for (let i = 0n; i < 2n; i++) { let i = 7n; s = s + i; } assert(s == p && c);",
    "if (c) { let y = 1n; assert(y == p); } else { let y = 2n; assert(y == p); }",
    "if (c) { let y = 1n; assert(y == p); } let y = 2n; assert(y == p);",
    "let s = 0n; for (let i = 0n; i < 2n; i++) { s = s + i; } for (let i = 0n; i < 3n; i++) { s = s + i; } assert(s == p && c);",
]


@pytest.mark.parametrize("body", ACCEPTED)
def test_accepts_shadowing_and_siblings(body: str) -> None:
    assert [d.message for d in _errors(_source(body)) if "already declared" in d.message] == []
