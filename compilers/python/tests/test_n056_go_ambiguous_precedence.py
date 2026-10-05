"""N-056 (CL-BUG-192) -- ``.runar.go`` operator precedence differed across tiers.

The Go tier parses ``.runar.go`` with go/parser (Go precedence); this tier, the
TS reference and the other four use the C ladder, so ``a & b + 1`` was
``(a & b) + 1`` in one tier and ``a & (b + 1)`` in the rest. R51: every tier
refuses an unparenthesised mix whose grouping differs between the two schemes,
with the shared diagnostic from 01-parse-go.ts.

The oracle recomputes the 72 ambiguous ordered operator pairs from the two
precedence tables rather than reusing the parser's constant.

What this proves: this tier refuses every ambiguous pair with the shared text,
accepts the 252 agreeing pairs and both parenthesisations, and treats ``&^``
as ``&`` and call results as operands.
What it does not prove: emitted bytes or the other tiers (conformance negatives
N175-N179 and the agreeing-pairs control cover cross-tier agreement).
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_go import parse_go

GO_PREC = {
    "*": 5, "/": 5, "%": 5, "<<": 5, ">>": 5, "&": 5,
    "+": 4, "-": 4, "|": 4, "^": 4,
    "==": 3, "!=": 3, "<": 3, "<=": 3, ">": 3, ">=": 3,
    "&&": 2, "||": 1,
}
C_PREC = {
    "*": 10, "/": 10, "%": 10, "+": 9, "-": 9, "<<": 8, ">>": 8,
    "<": 7, "<=": 7, ">": 7, ">=": 7, "==": 6, "!=": 6,
    "&": 5, "^": 4, "|": 3, "&&": 2, "||": 1,
}

PAIRS = [(x, y) for x in GO_PREC for y in GO_PREC]
CONFLICTING = [(x, y) for x, y in PAIRS if (GO_PREC[x] >= GO_PREC[y]) != (C_PREC[x] >= C_PREC[y])]
AGREEING = [(x, y) for x, y in PAIRS if (x, y) not in CONFLICTING]


def message(x: str, y: str) -> str:
    return (
        f"ambiguous operator precedence in .runar.go: `a {x} b {y} c` groups differently "
        f"under Go precedence than in Rúnar's other surfaces; add parentheses"
    )


def errors_of(expr: str) -> list[str]:
    src = f"""package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Probe struct {{
	runar.SmartContract
	T runar.Int `runar:"readonly"`
}}

func (c *Probe) Unlock(a runar.Int, b runar.Int, d runar.Int) {{
	x := {expr}
	runar.Assert(x == c.T)
}}
"""
    return [e.message for e in parse_go(src, "Probe.runar.go").errors]


def test_derived_set_size():
    assert (len(CONFLICTING), len(AGREEING)) == (72, 252)


@pytest.mark.parametrize("x,y", CONFLICTING)
def test_ambiguous_pair_refused(x, y):
    assert message(x, y) in errors_of(f"a {x} b {y} d")
    assert errors_of(f"(a {x} b) {y} d") == []
    assert errors_of(f"a {x} (b {y} d)") == []


@pytest.mark.parametrize("x,y", AGREEING)
def test_agreeing_pair_accepted(x, y):
    assert errors_of(f"a {x} b {y} d") == []


@pytest.mark.parametrize(
    "expr,pair",
    [
        ("a & b + 1", ("&", "+")),
        ("a + b << 2", ("+", "<<")),
        ("a | b + d", ("|", "+")),
        ("a & 255 == 15", ("&", "==")),
        ("a ^ b * d", None),
        ("(a & b + 1) * d", ("&", "+")),
        ("runar.Abs(a + b << 2)", ("+", "<<")),
        ("a * (d + (a | b + d))", ("|", "+")),
        ("a + b * d - a", None),
        ("a * b + d << 1", ("+", "<<")),
        ("a &^ b", None),
        ("a &^ b + d", ("&", "+")),
        ("(a &^ b) + d", None),
        ("runar.BigintBigAdd(a, b) << 2", None),
        ("runar.Abs(a + b) << 2", None),
        ("-a + b << 2", ("+", "<<")),
        ("-(a + b) << 2", None),
    ],
)
def test_probes(expr, pair):
    got = errors_of(expr)
    if pair is None:
        assert got == []
    else:
        assert message(*pair) in got
