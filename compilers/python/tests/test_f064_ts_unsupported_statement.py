"""F-064: the .runar.ts surface must refuse every statement kind outside
spec/grammar.md §9 with the TS reference's diagnostic,
"Unsupported statement kind: <ts.SyntaxKind name>" — never drop it.

Before the fix this parser silently ate empty statements (`;`, via
skip_semicolons) and fell through to the expression parser for every keyword
it did not dispatch on, so `throw x;` / `debugger;` / `break;` became an
identifier expression the typechecker happened to reject, and a nested `;`
compiled. Proves: the Python .runar.ts parser refuses each kind (top level,
nested in if, in a for body) with the shared diagnostic. Does not prove: the
other Python-tier surfaces (.runar.py/.sol/.move/...).
"""

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


def _wrap(stmt: str) -> str:
    return f"""import {{ SmartContract, assert }} from 'runar-lang';

class Probe extends SmartContract {{
  readonly a: bigint;

  constructor(a: bigint) {{
    super(a);
    this.a = a;
  }}

  public unlock(x: bigint) {{
    {stmt}
    assert(x > this.a);
  }}
}}
"""


CASES = [
    ("while (x > 0n) { assert(false); }", "WhileStatement"),
    ("do { assert(false); } while (x > 0n);", "DoStatement"),
    ("switch (x) { case 1n: assert(false); break; default: assert(false); }", "SwitchStatement"),
    ("outer: for (let i = 0n; i < 2n; i++) { assert(false); }", "LabeledStatement"),
    ("try { assert(false); } catch (e) { assert(false); }", "TryStatement"),
    ("throw x;", "ThrowStatement"),
    ("for (const k in this) { assert(false); }", "ForInStatement"),
    ("for (const k of [x]) { assert(false); }", "ForOfStatement"),
    ("{ assert(false); }", "Block"),
    (";", "EmptyStatement"),
    ("assert(x > 1n);;", "EmptyStatement"),
    ("const y = x;;", "EmptyStatement"),
    ("this.a;;", "EmptyStatement"),
    ("class Inner { }", "ClassDeclaration"),
    ("function inner(): void { assert(false); }", "FunctionDeclaration"),
    ("debugger;", "DebuggerStatement"),
    ("with (x) { assert(false); }", "WithStatement"),
    ("break;", "BreakStatement"),
    ("continue;", "ContinueStatement"),
]

CONTEXTS = [
    "{s}",
    "if (x > 0n) {{ {s} }}",
    "for (let j = 0n; j < 2n; j++) {{ {s} }}",
]


@pytest.mark.parametrize("stmt,kind", CASES)
@pytest.mark.parametrize("ctx", CONTEXTS)
def test_unsupported_statement_kind_is_refused(stmt: str, kind: str, ctx: str) -> None:
    body = ctx.format(s=stmt)
    result = parse_source(_wrap(body), "Probe.runar.ts")
    messages = [e.message for e in result.errors]
    assert f"Unsupported statement kind: {kind}" in messages, (body, messages)


def test_well_formed_body_still_parses_clean() -> None:
    result = parse_source(_wrap("const y = x + 1n;\n    assert(y > 0n);"), "Probe.runar.ts")
    assert result.errors == []
