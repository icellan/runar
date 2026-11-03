"""N-048 (external "PrematurePeek") — a computed FixedArray index must keep
source evaluation order.

Pass 3b hoists a computed index to ``const __idx_K`` in front of its whole
statement. In

    assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);

that bound the index BEFORE the increment, so the gate read the
pre-increment slot (an outsider spend at cursor 0 was accepted under the real
@bsv/sdk Spend). The AST has no let-expression, so every hoist that would
reorder evaluation is refused with the diagnostic shared by all seven tiers.

Proves: the same refused / accepted shapes as the TS reference
(packages/runar-compiler/src/__tests__/03b-expand-fixed-arrays.test.ts).
Does not prove on-chain behaviour; the TS VM test and
conformance/negatives/N120-N122 cover that across tiers.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.ast_nodes import ExpressionStmt, VariableDeclStmt
from runar_compiler.frontend.expand_fixed_arrays import expand_fixed_arrays
from runar_compiler.frontend.parser_dispatch import parse_source

DIAG = "FixedArray index would be evaluated out of source order"


def _expand(body: str):
    src = f"""
class Peek extends StatefulSmartContract {{
  readonly enabled: FixedArray<bigint, 2> = [1n, 0n];
  slots: FixedArray<bigint, 2> = [0n, 0n];
  cursor: bigint;
  constructor(cursor: bigint) {{ super(cursor); this.cursor = cursor; }}
  public release(k: bigint, c: boolean) {{
    {body}
  }}
}}
"""
    r = parse_source(src, "Peek.runar.ts")
    assert not r.errors, r.error_strings()
    return expand_fixed_arrays(r.contract)


def _joined(res) -> str:
    return "\n".join(e.message for e in res.errors)


REFUSED = [
    ("the reported shape", "assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);"),
    ("index after an earlier ++", "assert(++this.cursor + this.enabled[this.cursor % 2n] > 0n);"),
    ("index after an output intrinsic", 'assert(this.addRawOutput(1n, toByteString("00")) === this.enabled[this.cursor % 2n]);'),
    ("right operand of &&", "assert(k > 0n && this.enabled[k - 1n] === 1n);"),
    ("right operand of ||", "assert(k === 0n || this.enabled[k - 1n] === 1n);"),
    ("ternary arm", "assert((c ? this.enabled[k + 1n] : 0n) === 0n);"),
    ("own ++ ahead of an earlier read", "assert(this.cursor + this.enabled[++this.cursor % 2n] > 0n);"),
    ("value read after target-index effect", "this.slots[++this.cursor % 2n] = this.enabled[this.cursor % 2n]; assert(true);"),
]

ACCEPTED = [
    ("increment in its own statement", "++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);"),
    ("left operand of &&", "assert(this.enabled[k - 1n] === 1n && k > 0n);"),
    ("ternary condition", "assert((this.enabled[k + 1n] === 1n ? 1n : 0n) === 1n);"),
    ("effect after the read", "assert(this.enabled[this.cursor % 2n] + ++this.cursor > 0n);"),
    ("statement-form read", "const v = this.enabled[k + 1n]; assert(v === 1n);"),
    ("computed write index, effectful value", "this.slots[this.cursor % 2n] = ++this.cursor; assert(true);"),
]


@pytest.mark.parametrize("what,body", REFUSED, ids=[w for w, _ in REFUSED])
def test_n048_refuses_reordering_hoist(what, body):
    assert DIAG in _joined(_expand(body))


@pytest.mark.parametrize("what,body", ACCEPTED, ids=[w for w, _ in ACCEPTED])
def test_n048_accepts_order_preserving_hoist(what, body):
    assert DIAG not in _joined(_expand(body))


def test_n048_split_form_hoists_after_increment():
    res = _expand("++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);")
    assert not res.errors, _joined(res)
    m = next(m for m in res.contract.methods if m.name == "release")
    assert isinstance(m.body[0], ExpressionStmt)
    assert isinstance(m.body[1], VariableDeclStmt)
    assert m.body[1].name.startswith("__idx_")
