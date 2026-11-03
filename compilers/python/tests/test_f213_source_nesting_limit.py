"""F-213: a deeply nested source is REFUSED with one shared diagnostic, never
crashes the compiler.

Before F-213 this tier bounded nothing: CPython's default recursion limit
(1000) and ~15-20 parser frames per nesting level meant 128 nested parens,
128 nested ifs or 64 unary minuses already died with ``maximum recursion
depth exceeded`` -- a refusal by accident, with the wrong message, and the
legitimately deep (at-limit) programs did not compile at all.

The limit, ``MAX_SOURCE_NESTING`` (mirrors ``InputLimits.MAX_SOURCE_NESTING``
in packages/runar-ir-schema/src/input-limits.ts), is enforced on two measures:
  (A) parse nesting -- statements + full-expression parse entries (paren
      groups, call args, ...) + prefix-unary operands, counted by each parser;
  (B) AST nesting -- statement level + expression-tree depth, checked on the
      finished AST at every parser entry point.
The canonical shapes below sit exactly on either side of the limit for one of
the two measures, on all nine surfaces.

Proves: on every surface this tier compiles each shape at the limit end to end
(so the recursion headroom covers validate / typecheck / ANF / stack / emit),
and refuses it one past the limit with the shared diagnostic -- through the
dispatcher-backed compile entry, the per-format ``parse_*`` exports, and the
CLI; a 20 000-deep shape (2 500 for Python-surface ifs, whose indentation
would otherwise pass MAX_SOURCE_BYTES) and a 500 000-term chain are refused by
the CLI with exit code 1 and no traceback.
Does NOT prove: that the at-limit hex equals the other six tiers' (the F-213
boundary harness / conformance parity test checks that), nor that the limit
is the right size (the corpus measurement in input-limits.ts does).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

PYTHON_COMPILER_DIR = Path(__file__).resolve().parent.parent

L = 128
DIAG = f"source nesting depth exceeds MAX_SOURCE_NESTING (limit={L})"

SURFACES = ["ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"]


def _brace_if(open_: str, close: str):
    return lambda n, inner: open_ * n + inner + "\n" + close * n


def _py_if(n: int, inner: str) -> str:
    lines = ["        " + " " * i + "if mode:" for i in range(n)]
    lines.append("        " + " " * n + inner.strip())
    return "\n".join(lines)


# (head with {BODY}, assign(expr) -> statement, if_wrap(n, inner) -> statements)
TPL = {
    "ts": (
        "import { SmartContract, assert } from 'runar-lang';\n\nclass P extends SmartContract {\n  readonly limit: bigint;\n  constructor(limit: bigint) { super(limit); this.limit = limit; }\n  public check(value: bigint, mode: boolean): void {\n    let result: bigint = 0n;\n{BODY}\n    assert(result > 0n);\n  }\n}\n",
        lambda e: f"    result = {e};",
        _brace_if("if (mode) {\n", "}\n"),
    ),
    "sol": (
        "pragma runar ^0.1.0;\n\ncontract P is SmartContract {\n    int immutable limit;\n    constructor(int _limit) { limit = _limit; }\n    function check(int value, bool mode) public {\n        int result = 0;\n{BODY}\n        require(result > 0);\n    }\n}\n",
        lambda e: f"        result = {e};",
        _brace_if("if (mode) {\n", "}\n"),
    ),
    "move": (
        "module P {\n    use runar::types::{Int};\n    struct P { limit: Int, }\n    public fun check(contract: &P, value: Int, mode: bool) {\n        let result: Int = 0;\n{BODY}\n        assert!(result > 0, 0);\n    }\n}\n",
        lambda e: f"        result = {e};",
        _brace_if("if (mode) {\n", "};\n"),
    ),
    "go": (
        'package contract\n\nimport runar "github.com/icellan/runar/packages/runar-go"\n\ntype P struct {\n\trunar.SmartContract\n\tLimit runar.Int `runar:"readonly"`\n}\n\nfunc (c *P) Check(value runar.Int, mode runar.Bool) {\n\tresult := runar.Int(0)\n{BODY}\n\trunar.Assert(result > 0)\n}\n',
        lambda e: f"\tresult = {e}",
        _brace_if("if mode {\n", "}\n"),
    ),
    "rs": (
        "use runar::prelude::*;\n\n#[runar::contract]\nstruct P {\n    #[readonly]\n    limit: Int,\n}\n\nimpl P {\n    pub fn check(&self, value: Int, mode: bool) {\n        let mut result: Int = 0;\n{BODY}\n        assert!(result > 0);\n    }\n}\n",
        lambda e: f"        result = {e};",
        _brace_if("if mode {\n", "}\n"),
    ),
    "py": (
        "from runar import SmartContract, Bigint, public, assert_\n\nclass P(SmartContract):\n    limit: Bigint\n\n    def __init__(self, limit: Bigint):\n        super().__init__(limit)\n        self.limit = limit\n\n    @public\n    def check(self, value: Bigint, mode: bool):\n        result: Bigint = 0\n{BODY}\n        assert_(result > 0)\n",
        lambda e: f"        result = {e}",
        _py_if,
    ),
    "zig": (
        'const runar = @import("runar");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    limit: i64,\n    pub fn init(limit: i64) P { return .{ .limit = limit }; }\n    pub fn check(self: *const P, value: i64, mode: bool) void {\n        var result: i64 = 0;\n{BODY}\n        runar.assert(result > 0);\n    }\n};\n',
        lambda e: f"        result = {e};",
        _brace_if("if (mode) {\n", "}\n"),
    ),
    "rb": (
        "require 'runar'\n\nclass P < Runar::SmartContract\n  prop :limit, Bigint\n\n  def initialize(limit)\n    super(limit)\n    @limit = limit\n  end\n\n  runar_public value: Bigint, mode: Boolean\n  def check(value, mode)\n    result = 0\n{BODY}\n    assert result > 0\n  end\nend\n",
        lambda e: f"    result = {e}",
        _brace_if("if mode\n", "end\n"),
    ),
    "java": (
        "package p;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass P extends SmartContract {\n    @Readonly Bigint limit;\n    P(Bigint limit) { super(limit); this.limit = limit; }\n    @Public\n    void check(Bigint value, boolean mode) {\n        Bigint result = Bigint.ZERO;\n{BODY}\n        assertThat(result.gt(Bigint.ZERO));\n    }\n}\n",
        lambda e: f"        result = {e};",
        _brace_if("if (mode) {\n", "}\n"),
    ),
}


def shape_source(surface: str, shape: str, n: int) -> str:
    """The canonical F-213 shape (see the spec) on one surface.

    parens: A = n + 2   nested-if: A = n + 2, B = n + 2
    unary:  A = 2n + 2  chain: A = 2, B = n + 1
    """
    head, assign, if_wrap = TPL[surface]
    if shape == "parens":
        body = assign("(" * n + "value" + ")" * n)
    elif shape == "if":
        body = if_wrap(n, assign("value").strip())
    elif shape == "unary":
        body = assign("-(" * n + "value" + ")" * n)
    elif shape == "chain":
        body = assign(" + ".join(["value"] * n))
    else:
        raise AssertionError(shape)
    return head.replace("{BODY}", body)


def _file(surface: str) -> str:
    return f"P.runar.{surface}"


def _messages(result) -> list[str]:
    return [d.format_message() for d in result.diagnostics]


def _assert_compiles(surface: str, shape: str, n: int) -> None:
    result = compile_from_source_str_with_result(shape_source(surface, shape, n), _file(surface))
    assert result.success and result.script_hex, (surface, shape, n, _messages(result))


def _assert_refused(surface: str, shape: str, n: int) -> None:
    result = compile_from_source_str_with_result(shape_source(surface, shape, n), _file(surface))
    msgs = _messages(result)
    assert not result.success, (surface, shape, n)
    assert any(DIAG in m for m in msgs), (surface, shape, n, msgs)


def test_max_source_nesting_is_128() -> None:
    from runar_compiler.frontend import input_limits

    assert input_limits.MAX_SOURCE_NESTING == 128


# ---------------------------------------------------------------------------
# Boundary shapes, all nine surfaces (in-process, dispatcher-backed entry)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("surface", SURFACES)
def test_parens_at_limit_compiles(surface: str) -> None:
    _assert_compiles(surface, "parens", L - 2)


@pytest.mark.parametrize("surface", SURFACES)
def test_parens_one_past_limit_refused(surface: str) -> None:
    _assert_refused(surface, "parens", L - 1)


@pytest.mark.parametrize("surface", SURFACES)
def test_nested_if_at_limit_compiles(surface: str) -> None:
    _assert_compiles(surface, "if", L - 2)


@pytest.mark.parametrize("surface", SURFACES)
def test_nested_if_one_past_limit_refused(surface: str) -> None:
    _assert_refused(surface, "if", L - 1)


@pytest.mark.parametrize("surface", SURFACES)
def test_unary_at_limit_compiles(surface: str) -> None:
    _assert_compiles(surface, "unary", (L - 2) // 2)


@pytest.mark.parametrize("surface", SURFACES)
def test_unary_one_past_limit_refused(surface: str) -> None:
    _assert_refused(surface, "unary", (L - 2) // 2 + 1)


@pytest.mark.parametrize("surface", SURFACES)
def test_chain_at_limit_compiles(surface: str) -> None:
    _assert_compiles(surface, "chain", L - 1)


@pytest.mark.parametrize("surface", SURFACES)
def test_chain_one_past_limit_refused(surface: str) -> None:
    # A = 2 here: only measure (B) on the finished AST can refuse it.
    _assert_refused(surface, "chain", L)


# ---------------------------------------------------------------------------
# The per-format exports enforce it too (they bypass the dispatcher)
# ---------------------------------------------------------------------------


def _per_format_parser(surface: str):
    from runar_compiler.frontend.parser_go import parse_go
    from runar_compiler.frontend.parser_java import parse_java
    from runar_compiler.frontend.parser_move import parse_move
    from runar_compiler.frontend.parser_python import parse_python
    from runar_compiler.frontend.parser_ruby import parse_ruby
    from runar_compiler.frontend.parser_rust import parse_rust
    from runar_compiler.frontend.parser_sol import parse_sol
    from runar_compiler.frontend.parser_ts import parse_ts
    from runar_compiler.frontend.parser_zig import parse_zig

    return {
        "ts": parse_ts, "sol": parse_sol, "move": parse_move, "go": parse_go,
        "rs": parse_rust, "py": parse_python, "zig": parse_zig, "rb": parse_ruby,
        "java": parse_java,
    }[surface]


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("shape,n", [("parens", L - 1), ("chain", L)])
def test_per_format_parser_refuses_one_past_limit(surface: str, shape: str, n: int) -> None:
    result = _per_format_parser(surface)(shape_source(surface, shape, n), _file(surface))
    assert result.contract is None, (surface, shape)
    msgs = [d.format_message() for d in result.errors]
    assert any(DIAG in m for m in msgs), (surface, shape, msgs)


def test_recursion_limit_is_restored_after_compile() -> None:
    before = sys.getrecursionlimit()
    _assert_compiles("ts", "parens", L - 2)
    _assert_refused("ts", "parens", L - 1)
    assert sys.getrecursionlimit() == before


# ---------------------------------------------------------------------------
# Deep shapes: through the CLI in a subprocess, so a crash cannot take the
# test runner down with it.
# ---------------------------------------------------------------------------


def _cli(tmp_path: Path, surface: str, source: str, *flags: str) -> subprocess.CompletedProcess:
    path = tmp_path / _file(surface)
    path.write_text(source, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "runar_compiler", "--source", str(path), *flags],
        cwd=PYTHON_COMPILER_DIR, capture_output=True, text=True, timeout=600,
    )


def _assert_cli_refused(proc: subprocess.CompletedProcess) -> None:
    assert proc.returncode == 1, (proc.returncode, proc.stderr[-400:])
    assert DIAG in proc.stderr, proc.stderr[-400:]
    assert "Traceback" not in proc.stderr, proc.stderr[-400:]


@pytest.mark.parametrize("surface", SURFACES)
def test_cli_refuses_deep_shapes(tmp_path: Path, surface: str) -> None:
    for shape, n in [("parens", 20000), ("if", 2500 if surface == "py" else 20000),
                     ("unary", 20000), ("chain", 20000)]:
        _assert_cli_refused(_cli(tmp_path, surface, shape_source(surface, shape, n), "--hex"))


@pytest.mark.parametrize("surface", ["ts", "py", "rb"])
def test_cli_refuses_500k_term_chain(tmp_path: Path, surface: str) -> None:
    _assert_cli_refused(_cli(tmp_path, surface, shape_source(surface, "chain", 500000), "--hex"))


def test_cli_parse_only_refuses_deep_parens(tmp_path: Path) -> None:
    _assert_cli_refused(_cli(tmp_path, "sol", shape_source("sol", "parens", 20000), "--parse-only"))
