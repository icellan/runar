"""Regression test: the branch-lift must not zero the matched arm.

``_lift_branch_update_props`` flattens a dispatch chain::

    if (p == 0n) { this.c0 = v; } else if (p == 1n) { this.c1 = v; }
    else { assert(false); }

into one single-valued ``if`` per property plus a top-level ``update_prop``.
The ``if``'s then-arm must evaluate to the assigned value and its else-arm to
the property's old value.

The defect: the then-arm was built from ``branch.value_bindings`` — everything
BEFORE the ``update_prop`` in the original arm. That ends on the assigned value
only when the value was computed INSIDE the arm. When the arm assigns something
bound outside it, ``value_bindings`` is empty, the arm was emitted EMPTY, and
stack lowering padded it with a zero push
(``OP_IF OP_0 OP_ELSE OP_DUP OP_ENDIF``): the MATCHED branch wrote 0.

``examples/ts/tic-tac-toe`` escapes it only because ``this.cN = this.turn``
puts a ``load_prop`` inside the arm — that shape is the control below.
"""

from __future__ import annotations

from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source

LOCAL_VALUE_DISPATCH = """
class LocalValueDispatch extends StatefulSmartContract {
  c0: bigint;
  c1: bigint;

  constructor(c0: bigint, c1: bigint) {
    super(c0, c1);
    this.c0 = c0;
    this.c1 = c1;
  }

  public poke(position: bigint, value: bigint) {
    const doubled: bigint = value + value;
    if (position == 0n) { this.c0 = doubled; }
    else if (position == 1n) { this.c1 = doubled; }
    else { assert(false); }
  }
}
"""

IN_ARM_VALUE_DISPATCH = """
class InArmValueDispatch extends StatefulSmartContract {
  c0: bigint;
  c1: bigint;
  turn: bigint;

  constructor(c0: bigint, c1: bigint, turn: bigint) {
    super(c0, c1, turn);
    this.c0 = c0;
    this.c1 = c1;
    this.turn = turn;
  }

  public poke(position: bigint) {
    if (position == 0n) { this.c0 = this.turn; }
    else if (position == 1n) { this.c1 = this.turn; }
    else { assert(false); }
  }
}
"""


def _lifted_assignments(source: str, file_name: str):
    """Every top-level update_prop whose value is an `if`, with that if's arms."""
    parsed = parse_source(source, file_name)
    assert not parsed.errors, f"parse errors: {parsed.errors}"
    program = lower_to_anf(parsed.contract)

    method = next((m for m in program.methods if m.name == "poke"), None)
    assert method is not None, "method poke not found in lowered program"

    by_name = {b.name: b.value for b in method.body}

    out = []
    for b in method.body:
        if b.value.kind != "update_prop":
            continue
        producer = by_name.get(b.value.value_ref)
        if producer is None or producer.kind != "if":
            continue
        out.append((b.value.name, producer.then or [], producer.else_ or []))
    return out


def test_then_arm_carries_value_bound_outside_the_arm():
    lifted = _lifted_assignments(LOCAL_VALUE_DISPATCH, "LocalValueDispatch.runar.ts")

    # Both properties in the chain must be lifted. If this is 0 the pass has
    # stopped recognising the shape and the arm assertions below would pass
    # vacuously.
    assert len(lifted) == 2, f"expected 2 lifted conditional assignments, got {len(lifted)}"

    for prop, then_arm, else_arm in lifted:
        assert then_arm, (
            f"then-arm for this.{prop} is empty; stack lowering pads it with OP_0, "
            "so the MATCHED branch writes zero instead of the assigned value"
        )
        last = then_arm[-1]
        assert last.value.kind == "load_const" and last.value.const_string == "@ref:doubled", (
            f"then-arm for this.{prop} must end on the assigned local; got {last.value}"
        )
        assert else_arm, f"else-arm for this.{prop} is empty"


def test_in_arm_value_shape_is_unchanged():
    """Control: the TicTacToe shape already computed its value inside the arm
    and was always correct. The fix must add nothing here — a second binding
    would move the checked-in goldens."""
    lifted = _lifted_assignments(IN_ARM_VALUE_DISPATCH, "InArmValueDispatch.runar.ts")

    assert len(lifted) == 2, f"expected 2 lifted conditional assignments, got {len(lifted)}"
    for prop, then_arm, _else_arm in lifted:
        assert len(then_arm) == 1, (
            f"then-arm for this.{prop} should hold exactly the in-arm load_prop, "
            f"got {len(then_arm)} bindings"
        )
        assert then_arm[0].value.kind == "load_prop" and then_arm[0].value.name == "turn", (
            f"then-arm for this.{prop} should be load_prop turn, got {then_arm[0].value}"
        )
