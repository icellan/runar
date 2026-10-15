"""R-065 regression guard for the Python tier: the for-loop ``update`` clause
is parsed, carried through the whole AST, and then never validated and never
lowered.

``frontend/anf_lower.py``'s ``_extract_loop_step`` only ever understood a UNIT
step: it returns ``1`` for ``IncrementExpr``, ``-1`` for ``DecrementExpr``, and
otherwise falls back to the *comparison direction* — so any other update clause
is silently coerced to ``±1`` and the clause itself is discarded.
``validator.py``'s ``_validate_for_statement`` never looked at ``stmt.update``
at all.

Three shapes of the same hole, all observable from ordinary source:

* ``for (let i = 0n; i < 3n; undefinedFn())`` compiled to byte-identical
  output. A nonexistent function name raised nothing — a hole in the rule that
  only Rúnar builtins and contract methods are callable (CLAUDE.md names
  ``console.log`` explicitly).
* ``for (let i = 0n; i < 3n; this.count++)`` silently DROPPED the state write
  from the emitted script.
* a non-unit step (``i += 2`` in the Go / Zig / Solidity surface formats)
  unrolled 5 times over i = 0..4 instead of 3 times over i = 0,2,4 —
  byte-identical to the ``i++`` loop, with no diagnostic.

``spec/grammar.md`` is authoritative and permits only the unit forms: its
ForStatement production admits ``Identifier ( '++' | '--' )`` and nothing else,
and its Statement Restrictions say "The loop variable MUST use simple increment
(``++``) or decrement (``--``)". So rejecting is the fix rather than lowering:
the ANF ``loop`` node can express exactly ``{count, iterVar, start, step,
body}`` and synthesizes the iterator on unrolled iteration k as
``start + k*step``. There is no slot for an arbitrary update statement, and
appending the update's lowering to the loop body would re-emit ``i++`` as a dead
binding on every loop that already compiles correctly — moving bytes across the
whole corpus to express nothing.

The diagnostic text is shared verbatim with the other six tiers.

What these tests do NOT prove: nothing here says the update clause is
*lowered*; the contract is that a non-representable update is a compile error
instead of silent output. The controls pin the ``bounded-loop`` shape only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

REPO_ROOT = Path(__file__).resolve().parents[3]

# The one correct answer. ``bounded-loop`` sums ``start + i`` for i in 0..4 and
# asserts the total; all nine frontends lower to these exact 42 bytes.
BOUNDED_LOOP_HEX = (
    "000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c93009c"
)

LOOP_UPDATE_DIAGNOSTIC = "must advance the loop variable by one"


def example(rel: str) -> str:
    return (REPO_ROOT / rel).read_text()


def compile_source(source: str, file_name: str):
    result = compile_from_source_str_with_result(source, file_name)
    diags = "\n".join(d.message for d in result.diagnostics)
    return result.success, (result.script_hex or ""), diags


def ts_with_update(update: str) -> str:
    """A stateful contract parameterised on the for-loop update clause."""
    return f"""import {{ StatefulSmartContract, assert }} from 'runar-lang';

class UpdateProbe extends StatefulSmartContract {{
  count: bigint;

  constructor(count: bigint) {{ super(count); this.count = count; }}

  public unlock(expected: bigint): void {{
    let acc: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; {update}) {{
      acc = acc + i;
    }}
    assert(acc === expected);
  }}
}}
"""


# ---------------------------------------------------------------------------
# The defect
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rel,file_name,before,after",
    [
        # The Zig `while (c) : (i += 2)` fold produces the ASSIGNMENT spelling
        # `i = i + 2`.
        (
            "examples/zig/bounded-loop/BoundedLoop.runar.zig",
            "BoundedLoop.runar.zig",
            "i += 1",
            "i += 2",
        ),
        # The Go surface spelling of the same thing.
        (
            "examples/go/bounded-loop/BoundedLoop.runar.go",
            "BoundedLoop.runar.go",
            "i++",
            "i += 2",
        ),
    ],
)
def test_non_unit_step_is_rejected_not_coerced(rel, file_name, before, after):
    source = example(rel).replace(before, after, 1)
    ok, hex_out, diags = compile_source(source, file_name)
    assert not ok, (
        f"`{after}` must not compile: it silently unrolled with step 1 "
        f"({len(hex_out)} hex chars)"
    )
    assert LOOP_UPDATE_DIAGNOSTIC in diags, (
        f"rejection must carry the shared cross-tier diagnostic, got: {diags}"
    )


def test_negative_non_unit_step_is_rejected():
    """Guards against an accepted set that only checks counting up."""
    source = example("examples/zig/bounded-loop/BoundedLoop.runar.zig")
    source = source.replace("var i: i64 = 0;", "var i: i64 = 5;", 1)
    source = source.replace("while (i < 5) : (i += 1)", "while (i > 0) : (i -= 2)", 1)
    ok, _, diags = compile_source(source, "BoundedLoop.runar.zig")
    assert not ok, "`i -= 2` must not compile"
    assert LOOP_UPDATE_DIAGNOSTIC in diags, diags


def test_state_mutation_in_update_is_rejected_not_dropped():
    ok, _, diags = compile_source(ts_with_update("this.count++"), "UpdateProbe.runar.ts")
    assert not ok, (
        "a state mutation in the update clause is not representable in the ANF loop "
        "node, so it must be a compile error — silently dropping it is what this "
        "test forbids"
    )
    assert LOOP_UPDATE_DIAGNOSTIC in diags, diags


def test_update_advancing_another_variable_is_rejected():
    source = """import { SmartContract, assert } from 'runar-lang';

class OtherVar extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) { super(expected); this.expected = expected; }

  public verify(start: bigint): void {
    let sum: bigint = 0n;
    let j: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; j++) {
      sum = sum + start + i;
    }
    assert(sum === this.expected);
  }
}
"""
    ok, _, diags = compile_source(source, "OtherVar.runar.ts")
    assert not ok, "`j++` advances a variable the loop model never binds"
    assert LOOP_UPDATE_DIAGNOSTIC in diags, diags


def test_rejection_is_a_diagnostic_not_a_crash():
    """The rejection path must return diagnostics, never raise."""
    ok, _, diags = compile_source(ts_with_update("this.count++"), "UpdateProbe.runar.ts")
    assert not ok
    assert diags.strip() != "", "rejection must carry a diagnostic, got an empty message"


# ---------------------------------------------------------------------------
# Controls: every shape that compiles today must still compile, byte-identical
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rel,file_name",
    [
        ("examples/ts/bounded-loop/BoundedLoop.runar.ts", "BoundedLoop.runar.ts"),
        ("examples/sol/bounded-loop/BoundedLoop.runar.sol", "BoundedLoop.runar.sol"),
        ("examples/go/bounded-loop/BoundedLoop.runar.go", "BoundedLoop.runar.go"),
        ("examples/move/bounded-loop/BoundedLoop.runar.move", "BoundedLoop.runar.move"),
        ("examples/python/bounded-loop/BoundedLoop.runar.py", "BoundedLoop.runar.py"),
        # `while (i < 5) : (i += 1)` — the assignment spelling `i = i + 1`,
        # which the accepted set has to keep alongside `i++`.
        ("examples/zig/bounded-loop/BoundedLoop.runar.zig", "BoundedLoop.runar.zig"),
        # `i = i.plus(Bigint.ONE)` — the Java surface's unit-step spelling.
        (
            "examples/java/src/main/java/runar/examples/bounded-loop/BoundedLoop.runar.java",
            "BoundedLoop.runar.java",
        ),
    ],
)
def test_control_bounded_loop_bytes_unchanged(rel, file_name):
    ok, hex_out, diags = compile_source(example(rel), file_name)
    assert ok, f"must still compile: {diags}"
    assert hex_out == BOUNDED_LOOP_HEX, "lowering moved bytes"


def test_control_countdown_still_compiles():
    """`i--` with `>`: guards against an accepted set that only counts up."""
    source = """import { SmartContract, assert } from 'runar-lang';

class Countdown extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) { super(expected); this.expected = expected; }

  public verify(start: bigint): void {
    let sum: bigint = 0n;
    for (let i: bigint = 3n; i > 0n; i--) {
      sum = sum + start + i;
    }
    assert(sum === this.expected);
  }
}
"""
    ok, _, diags = compile_source(source, "Countdown.runar.ts")
    assert ok, f"a countdown loop must still compile: {diags}"


# ---------------------------------------------------------------------------
# N-132: an EMPTY update slot on the C-style `.runar.ts` header
# ---------------------------------------------------------------------------


EMPTY_UPDATE_DIAGNOSTIC = "For loop must have an update expression"


def test_n132_empty_ts_update_is_rejected():
    """N-132: ``for (let i = 0n; i < 3n; )`` never advances ``i`` in the source,
    yet this tier filled the empty slot with a ``0n`` placeholder and the
    unrolled loop advanced it anyway (938 hex chars, byte-identical to ``i++``).
    The TS reference refuses it in its parser with the diagnostic below.

    Proves: the Python ``.runar.ts`` parser refuses an empty update slot with
    the reference's text. Does not prove: anything about other surfaces (their
    empty-update shapes are pinned by the conformance negatives N180/N181)."""
    ok, hex_out, diags = compile_source(ts_with_update(""), "UpdateProbe.runar.ts")
    assert not ok, (
        f"an empty for-update must not compile ({len(hex_out)} hex chars emitted)"
    )
    assert EMPTY_UPDATE_DIAGNOSTIC in diags, diags


# ---------------------------------------------------------------------------
# N-116: an update that reads the iterator (or is a literal) without advancing it
# ---------------------------------------------------------------------------


def _zig_continue_reads_iterator() -> str:
    source = example("examples/zig/bounded-loop/BoundedLoop.runar.zig")
    source = source.replace("var i: i64 = 0;", "var i: i64 = 3;", 1)
    return source.replace("while (i < 5) : (i += 1)", "while (i < 5) : (i)", 1)


@pytest.mark.parametrize(
    "source_fn,file_name",
    [
        (_zig_continue_reads_iterator, "BoundedLoop.runar.zig"),
        (lambda: ts_with_update("i"), "UpdateProbe.runar.ts"),
        (lambda: ts_with_update("0n"), "UpdateProbe.runar.ts"),
    ],
    ids=["zig-continue-reads-iterator", "ts-update-reads-iterator", "ts-update-literal"],
)
def test_n116_non_advancing_update_is_rejected(source_fn, file_name):
    """N-116: the validator accepted a bare identifier / literal update as the
    "no-op sentinel" the while-shaped parsers synthesize, and the step was then
    inferred as +1 from the comparison direction -- so ``var i = 3;
    while (i < 5) : (i)``, a source loop that never terminates, unrolled to two
    laps over i = 3, 4.

    Proves: the refusal, with the shared R-065 sentence, on the Zig continue
    expression and the TS for-update surface. Does not prove: anything about
    while loops whose update lives in the body (those keep a placeholder
    iterator and the condition rule refuses them)."""
    ok, hex_out, diags = compile_source(source_fn(), file_name)
    assert not ok, f"a non-advancing update must not compile; got {hex_out}"
    assert LOOP_UPDATE_DIAGNOSTIC in diags, diags


# ---------------------------------------------------------------------------
# N-135: an EMPTY condition slot on the C-style `.runar.ts` header
# ---------------------------------------------------------------------------


EMPTY_CONDITION_DIAGNOSTIC = "For loop must have a condition"


def test_n135_empty_ts_condition_is_rejected():
    """N-135: ``for (let i = 0n; ; i++)`` has no exit test in the source. The TS
    reference refuses it in its parser with the diagnostic below; this tier
    refused it only by accident (the ``let`` declaration consumed its own
    ``;``, a second ``match(;)`` swallowed the empty slot's ``;``, and ``i++``
    was misparsed as the condition).

    Proves: the Python ``.runar.ts`` parser refuses an empty condition slot with
    the reference's text. Does not prove: other surfaces or tiers (pinned by
    the conformance negatives N274/N275)."""
    src = ts_with_update("i++").replace("0n; i < 3n; i++)", "0n; ; i++)")
    ok, hex_out, diags = compile_source(src, "UpdateProbe.runar.ts")
    assert not ok, (
        f"an empty for-condition must not compile ({len(hex_out)} hex chars emitted)"
    )
    assert EMPTY_CONDITION_DIAGNOSTIC in diags, diags


def test_n135_shifted_ts_header_is_rejected():
    """N-135: ``for (let i = 0n;; i < 3n; i++)`` is not valid TypeScript (its
    condition slot is empty and the last two clauses shift left). The second
    ``match(;)`` after the initializer swallowed the empty slot's ``;`` and this
    tier compiled it exactly like ``for (let i = 0n; i < 3n; i++)``.

    Proves: the Python ``.runar.ts`` parser refuses the shifted header with the
    reference's condition diagnostic. Does not prove: other surfaces or tiers
    (pinned by the conformance negative N275)."""
    src = ts_with_update("i++").replace("0n; i < 3n; i++)", "0n;; i < 3n; i++)")
    ok, hex_out, diags = compile_source(src, "UpdateProbe.runar.ts")
    assert not ok, (
        f"a shifted for-header must not compile ({len(hex_out)} hex chars emitted)"
    )
    assert EMPTY_CONDITION_DIAGNOSTIC in diags, diags


# ---------------------------------------------------------------------------
# N-306: a non-declaration for-initializer on the C-style `.runar.ts` header
# ---------------------------------------------------------------------------


NON_DECLARATION_INITIALIZER_DIAGNOSTIC = (
    "For loop must have a variable declaration initializer"
)


def ts_for_initializer(init: str) -> str:
    """A stateful contract parameterised on the for-loop HEADER, with a body
    that never references the loop variable by name -- unlike
    ``ts_with_update``'s body (``acc = acc + i``), so a substituted
    ``_i = 0`` iterator can't be caught by an accidental "undefined variable
    'i'" typecheck error instead of the parser's own diagnostic."""
    return f"""import {{ StatefulSmartContract, assert }} from 'runar-lang';

class InitProbe extends StatefulSmartContract {{
  count: bigint;

  constructor(count: bigint) {{ super(count); this.count = count; }}

  public unlock(expected: bigint): void {{
    let acc: bigint = 0n;
    for ({init}; _i < 3n; _i++) {{
      acc = acc + 1n;
    }}
    assert(acc === expected);
  }}
}}
"""


def test_n306_non_declaration_initializer_is_rejected():
    """N-306: ``for (i = 0n; _i < 3n; _i++)`` has no ``let``/``const`` in the
    initializer slot. The TS reference refuses it in its parser with the
    diagnostic below. This tier's ``_parse_for`` instead silently substituted
    the synthetic ``_i = 0`` iterator for the whole initializer, discarding
    ``i = 0n`` with no diagnostic at all -- invisible as long as the
    condition/update still reference the original name ``i``, because an
    unrelated validator check (the unrolled loop's "condition must compare
    the loop variable" rule) then catches the name mismatch by accident and
    refuses the program anyway. Writing the condition/update against the
    substituted name ``_i`` instead -- exactly what a developer who noticed
    the generated variable would do -- defeats that accidental catch and the
    garbage initializer compiled clean.

    Proves: the Python ``.runar.ts`` parser refuses a non-declaration
    for-initializer with the reference's text, even when the rest of the
    header is written against the substituted name. Does not prove: other
    surfaces or tiers (pinned by the conformance negatives N277-N279)."""
    ok, hex_out, diags = compile_source(
        ts_for_initializer("i = 0n"), "InitProbe.runar.ts"
    )
    assert not ok, (
        f"a non-declaration for-initializer must not compile "
        f"({len(hex_out)} hex chars emitted)"
    )
    assert NON_DECLARATION_INITIALIZER_DIAGNOSTIC in diags, diags


def test_n306_let_initializer_still_compiles():
    """Control: a well-formed ``let`` initializer must keep compiling clean --
    the fix narrows only the non-declaration branch of the initializer
    dispatch."""
    ok, _, diags = compile_source(
        ts_for_initializer("let _i: bigint = 0n"), "InitProbe.runar.ts"
    )
    assert ok, f"a `let` for-initializer must still compile: {diags}"
