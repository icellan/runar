"""N-153 — a .runar.go EMPTY statement ``;`` is refused, as in the TS reference.

Pre-fix this tier (with the Rust and Java tiers) skipped every ``;`` in a
block, so ``;`` on its own line, ``stmt; ;`` and ``if c { ; }`` compiled; the
TS reference and the Go tier (go/parser EmptyStmt) refuse them. TS says
"Unexpected token in expression: ';'".

A ``;`` that ends a statement on the same line still separates it from the
next one, as go/parser accepts; whether that separator should be accepted at
all (TS refuses it) is left open in the N-153 report.

What this proves: this tier's .runar.go parser refuses each empty-statement
shape with the TS diagnostic and still parses the same-line separator.
What it does NOT prove: other tiers (see
conformance/negatives/n153-statement-shape-parity.test.ts) or other surfaces.
"""
from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source

WANT = "Unexpected token in expression: ';'"


def go_src(stmt: str) -> str:
    return f"""package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Disc struct {{
\trunar.SmartContract
\tT runar.Bigint `runar:"readonly"`
}}

func (c *Disc) Unlock(x runar.Bigint) {{
\t{stmt}
\trunar.Assert(true)
}}

func (c *Disc) check(x runar.Bigint) runar.Bigint {{
\trunar.Assert(x == c.T)
\treturn x
}}
"""


@pytest.mark.parametrize(
    "stmt",
    [
        ";",
        "runar.Assert(x == c.T)\n\t;",
        "runar.Assert(x == c.T); ;",
        "runar.Assert(x == c.T);;",
        "if x == c.T { ; }",
    ],
)
def test_empty_statement_is_refused_with_the_ts_diagnostic(stmt: str) -> None:
    messages = [e.message for e in parse_source(go_src(stmt), "Disc.runar.go").errors]
    assert any(WANT in m for m in messages), f"go {stmt!r}: got {messages}"


@pytest.mark.parametrize(
    "stmt",
    [
        "runar.Assert(x == c.T);",
        "y := c.check(x); _ = y",
        "if x == c.T { runar.Assert(true) };",
    ],
)
def test_same_line_separator_is_unchanged(stmt: str) -> None:
    assert parse_source(go_src(stmt), "Disc.runar.go").errors == []


@pytest.mark.parametrize(
    "stmt",
    [
        "{ runar.Assert(x == c.T) }",
        "{ x, c.check(x) }",
        "{ }",
        "{\n\t\ty := x\n\t\trunar.Assert(y == c.T)\n\t}",
        "if x == c.T {\n\t\t{ runar.Assert(true) }\n\t}",
    ],
)
def test_statement_starting_with_a_brace_is_refused(stmt: str) -> None:
    """N-153 escalation decision: a `{` at statement start is refused (it used
    to parse as a brace composite literal, so `{ x, c.check(x) }` compiled)."""
    messages = [e.message for e in parse_source(go_src(stmt), "Disc.runar.go").errors]
    assert any("Unexpected token in expression: '{'" in m for m in messages), f"go {stmt!r}: got {messages}"


def test_expression_position_composite_literal_still_parses() -> None:
    assert parse_source(go_src("y := [2]runar.Bigint{x, c.T}\n\t_ = y"), "Disc.runar.go").errors == []
