"""N-019 (port of R-018, Rust): ``this.arr[i]++`` must be seen as a state mutation.

Two blind spots, both keyed on the operand of an increment/decrement being a
bare ``PropertyAccessExpr``:

1. **Lowering** — ``anf_lower.py`` emits an ``update_prop`` for an increment
   ONLY when the operand is a ``PropertyAccessExpr``. After
   ``expand_fixed_arrays`` has run, ``this.board[i]`` (runtime index) is a
   ternary read chain over the expanded slots, so the new value is computed and
   DISCARDED — the mutation vanishes.

2. **Side-effect summary** — ``_collect_expr`` in ``side_effect_summary.py`` has
   the identical guard, so ``mutates_state`` stays False,
   ``continuation_shape_for`` returns ``is_terminal=True`` and NO continuation
   assertion is injected at all: a method that mutates state emits nothing
   binding that mutation.

The root cause is neither site: pass 3b rewrites only the increment's OPERAND,
leaving a ``TernaryExpr`` where both sites expect a property access.

The control below (``this.count++``, a plain scalar property) is the shape that
already works and must stay unchanged — it discriminates the two paths.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.ast_nodes import (
    AssignmentStmt,
    ContractNode,
    ExpressionStmt,
    PropertyAccessExpr,
)
from runar_compiler.frontend.expand_fixed_arrays import expand_fixed_arrays
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.side_effect_summary import (
    compute_side_effect_summary,
    continuation_shape_for,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Runtime index (``i`` is a parameter), so expand-fixed-arrays cannot fold
# ``this.board[i]`` to a single slot — it becomes a dispatch/ternary chain.
INDEX_INCREMENT = """
class BumpIncr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[i]++;
  }
}
"""

INDEX_DECREMENT = """
class BumpDecr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[i]--;
  }
}
"""

# The hand-written form ``this.board[i]++`` must be equivalent to.
INDEX_EXPLICIT_ADD = """
class BumpIncr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[i] = this.board[i] + 1n;
  }
}
"""

# Literal index — already folds to ``this.board__0``; must be byte-identical.
LITERAL_INDEX_INCREMENT = """
class BumpLit extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[0]++;
  }
}
"""

LITERAL_INDEX_EXPLICIT = """
class BumpLit extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[0] = this.board[0] + 1n;
  }
}
"""

# The most plausible real-world shape: a histogram bump inside a loop.
INDEX_INCREMENT_IN_LOOP = """
class BumpLoop extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bumpAll() {
    for (let i: bigint = 0n; i < 3n; i++) {
      this.board[i]++;
    }
  }
}
"""

# Control: the already-working shape. A plain mutable scalar property.
PLAIN_PROP_INCREMENT = """
class BumpProp extends StatefulSmartContract {
  count: bigint = 0n;

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.count++;
  }
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(src: str, file_name: str) -> ContractNode:
    result = parse_source(src, file_name)
    assert not result.errors, f"parse errors: {result.errors}"
    assert result.contract is not None
    return result.contract


def _expanded(src: str, file_name: str) -> ContractNode:
    """Parse + run pass 3b, exactly as the compiler does before ANF lowering."""
    result = expand_fixed_arrays(_parse(src, file_name))
    assert not result.errors, f"expand-fixed-arrays errors: {result.errors}"
    return result.contract


def _update_prop_names(bindings, out: list[str]) -> None:
    """Every update_prop name anywhere, including if arms and loop bodies."""
    for b in bindings:
        kind = b.value.kind
        if kind == "update_prop":
            out.append(b.value.name)
        elif kind == "if":
            _update_prop_names(b.value.then or [], out)
            _update_prop_names(b.value.else_ or [], out)
        elif kind == "loop":
            _update_prop_names(b.value.body or [], out)


def _method(src: str, file_name: str, method: str):
    program = lower_to_anf(_expanded(src, file_name))
    for m in program.methods:
        if m.name == method:
            return m
    raise AssertionError(f"method {method} not found")


def _updated_props(src: str, file_name: str, method: str) -> list[str]:
    out: list[str] = []
    _update_prop_names(_method(src, file_name, method).body, out)
    return out


def _param_names(src: str, file_name: str, method: str) -> list[str]:
    return [p.name for p in _method(src, file_name, method).params]


def _shape(src: str, file_name: str, method: str):
    summary = compute_side_effect_summary(_expanded(src, file_name))
    eff = summary[method]
    return eff.mutates_state, continuation_shape_for(eff)


def _anf_json(src: str, file_name: str) -> str:
    program = lower_to_anf(_expanded(src, file_name))
    return json.dumps(asdict(program), sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# Control — the shape that already works. Must pass before AND after the fix.
# ---------------------------------------------------------------------------


def test_control_plain_property_increment_updates_state() -> None:
    props = _updated_props(PLAIN_PROP_INCREMENT, "BumpProp.runar.ts", "bump")
    assert "count" in props, (
        f"control regressed: `this.count++` produced no update_prop; got {props}"
    )
    mutates, shape = _shape(PLAIN_PROP_INCREMENT, "BumpProp.runar.ts", "bump")
    assert mutates, "control regressed: `this.count++` is not mutating"
    assert not shape.is_terminal, "control regressed: treated as terminal"


# ---------------------------------------------------------------------------
# Half 1 — lowering: the increment through an index must produce update_prop.
# ---------------------------------------------------------------------------


def test_index_increment_emits_update_prop() -> None:
    props = _updated_props(INDEX_INCREMENT, "BumpIncr.runar.ts", "bump")
    assert props, (
        "`this.board[i]++` produced NO update_prop at all — the mutation was "
        "computed and discarded"
    )
    assert any(p.startswith("board") for p in props), (
        f"`this.board[i]++` produced no update_prop for a board slot; got {props}"
    )


def test_index_decrement_emits_update_prop() -> None:
    props = _updated_props(INDEX_DECREMENT, "BumpDecr.runar.ts", "bump")
    assert any(p.startswith("board") for p in props), (
        f"`this.board[i]--` produced no update_prop for a board slot; got {props}"
    )


# ---------------------------------------------------------------------------
# Half 2 — side-effect summary: the method is NOT terminal.
# ---------------------------------------------------------------------------


def test_index_increment_is_a_state_mutation() -> None:
    mutates, shape = _shape(INDEX_INCREMENT, "BumpIncr.runar.ts", "bump")
    assert mutates, (
        "`this.board[i]++` did not set mutates_state — no continuation is injected"
    )
    assert not shape.is_terminal, (
        "`this.board[i]++` classified terminal: no continuation assertion binds "
        "the mutation"
    )
    assert shape.needs_change
    assert shape.needs_new_amount


def test_index_decrement_is_a_state_mutation() -> None:
    mutates, shape = _shape(INDEX_DECREMENT, "BumpDecr.runar.ts", "bump")
    assert mutates, "`this.board[i]--` did not set mutates_state"
    assert not shape.is_terminal, "`this.board[i]--` classified terminal"


def test_index_increment_inside_a_loop_is_a_state_mutation() -> None:
    props = _updated_props(INDEX_INCREMENT_IN_LOOP, "BumpLoop.runar.ts", "bumpAll")
    assert any(p.startswith("board") for p in props), (
        f"loop-bumped element produced no update_prop; got {props}"
    )
    mutates, shape = _shape(INDEX_INCREMENT_IN_LOOP, "BumpLoop.runar.ts", "bumpAll")
    assert mutates, "loop-bumped array element did not set mutates_state"
    assert not shape.is_terminal, "loop-bumping method classified terminal"


# ---------------------------------------------------------------------------
# The desugar must be FAITHFUL, not merely present.
# ---------------------------------------------------------------------------


def test_index_increment_lowers_identically_to_the_explicit_add() -> None:
    sugar = _anf_json(INDEX_INCREMENT, "BumpIncr.runar.ts")
    explicit = _anf_json(INDEX_EXPLICIT_ADD, "BumpIncr.runar.ts")
    assert sugar == explicit, (
        "`this.board[i]++` must lower identically to "
        "`this.board[i] = this.board[i] + 1n`"
    )


def test_literal_index_increment_is_unchanged() -> None:
    sugar = _anf_json(LITERAL_INDEX_INCREMENT, "BumpLit.runar.ts")
    explicit = _anf_json(LITERAL_INDEX_EXPLICIT, "BumpLit.runar.ts")
    assert sugar == explicit, (
        "literal-index `this.board[0]++` must stay byte-identical to the "
        "explicit form"
    )


def test_index_increment_method_gets_continuation_params() -> None:
    params = _param_names(INDEX_INCREMENT, "BumpIncr.runar.ts", "bump")
    control = _param_names(PLAIN_PROP_INCREMENT, "BumpProp.runar.ts", "bump")
    assert params == control, (
        f"`this.board[i]++` must receive the same continuation params as the "
        f"equivalent `this.count++`; got {params} vs control {control}"
    )


# ---------------------------------------------------------------------------
# Expression position cannot write back through the dispatch chain.
# ---------------------------------------------------------------------------


def test_index_increment_in_expression_position_is_rejected() -> None:
    # The Python compiler's TS parser rejects an assignment whose value is a
    # postfix increment, so drive the AST directly: an assignment whose value
    # is an IncrementExpr over an IndexAccessExpr.
    contract = _parse(INDEX_INCREMENT, "BumpIncr.runar.ts")
    method = next(m for m in contract.methods if m.name == "bump")
    stmt = method.body[0]
    assert isinstance(stmt, ExpressionStmt)
    method.body = [
        AssignmentStmt(
            target=PropertyAccessExpr(property="board__0"),
            value=stmt.expr,
            source_location=stmt.source_location,
        )
    ]
    result = expand_fixed_arrays(contract)
    assert result.errors, (
        "`x = this.board[i]++` was accepted; the array write is silently dropped"
    )
