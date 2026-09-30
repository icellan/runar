"""F-072 — lowerCall's ``exit`` / ``assert`` branches recorded a stack slot no
opcode produces.

``exit(cond)`` lowers as ``call exit`` (no dedicated ANF node); stack lowering
ran ``cond OP_VERIFY`` and then pushed a slot for the void result. OP_VERIFY
leaves nothing behind, so every later PICK/ROLL addressed the item one below
the one it meant. For
``check(b, a, x, y) { exit(x > 0n); assert(y === 1n); assert(a > 5n); assert(b === 0n); }``
every tier emitted 7c00a0697c519d7c55a0697c9177, which the five-push witness
(0, b=6, a=1, x=1, y=999) spends. ``call assert`` (reachable only through
--ir) hit the same bug; the ``super`` branch is dead (constructors are never
stack-lowered and the loader refuses ``super`` elsewhere).

Proves: the Python tier emits the hand-derived 7c00a069519d55a06991 on the
source path (both fold modes) and on the --ir path for ``call exit`` and
``call assert``.
Does not prove: that the script spends correctly — executed on the @bsv/sdk
engine for all seven tiers in
packages/runar-testing/src/__tests__/f072-exit-phantom-slot-spend.test.ts.
"""
from __future__ import annotations

import json

import pytest

from runar_compiler.compiler import compile_from_ir_bytes, compile_from_source_str_with_result

EXPECTED = "7c00a069519d55a06991"
PRE_FIX = "7c00a0697c519d7c55a0697c9177"

SOURCE = """import { SmartContract, assert } from 'runar-lang';

class ExitAssert4 extends SmartContract {
  constructor() {
    super();
  }

  public check(b: bigint, a: bigint, x: bigint, y: bigint) {
    exit(x > 0n);
    assert(y === 1n);
    assert(a > 5n);
    assert(b === 0n);
  }
}
"""


def _ir(guard: str) -> bytes:
    def b(name, value):
        return {"name": name, "value": value}

    return json.dumps({
        "contractName": "ExitAssert4",
        "properties": [],
        "methods": [
            {"name": "constructor", "isPublic": False, "params": [],
             "body": [b("t0", {"kind": "call", "func": "super", "args": []})]},
            {"name": "check", "isPublic": True,
             "params": [{"name": n, "type": "bigint"} for n in ("b", "a", "x", "y")],
             "body": [
                 b("t0", {"kind": "load_param", "name": "x"}),
                 b("t1", {"kind": "load_const", "value": 0}),
                 b("t2", {"kind": "bin_op", "op": ">", "left": "t0", "right": "t1"}),
                 b("t3", {"kind": "call", "func": guard, "args": ["t2"]}),
                 b("t4", {"kind": "load_param", "name": "y"}),
                 b("t5", {"kind": "load_const", "value": 1}),
                 b("t6", {"kind": "bin_op", "op": "===", "left": "t4", "right": "t5"}),
                 b("t7", {"kind": "assert", "value": "t6"}),
                 b("t8", {"kind": "load_param", "name": "a"}),
                 b("t9", {"kind": "load_const", "value": 5}),
                 b("t10", {"kind": "bin_op", "op": ">", "left": "t8", "right": "t9"}),
                 b("t11", {"kind": "assert", "value": "t10"}),
                 b("t12", {"kind": "load_param", "name": "b"}),
                 b("t13", {"kind": "load_const", "value": 0}),
                 b("t14", {"kind": "bin_op", "op": "===", "left": "t12", "right": "t13"}),
                 b("t15", {"kind": "assert", "value": "t14"}),
             ]},
        ],
    }).encode()


@pytest.mark.parametrize("fold", [False, True])
def test_exit_then_assert_source_reads_right_slots(fold: bool) -> None:
    r = compile_from_source_str_with_result(SOURCE, "ExitAssert4.runar.ts", disable_constant_folding=not fold)
    assert r.success, r.diagnostics
    assert r.script_hex != PRE_FIX, f"phantom slot after exit(): {r.script_asm}"
    assert r.script_hex == EXPECTED, r.script_asm


@pytest.mark.parametrize("guard", ["exit", "assert"])
def test_call_exit_and_call_assert_ir_read_right_slots(guard: str) -> None:
    art = compile_from_ir_bytes(_ir(guard))
    assert art.script == EXPECTED, art.asm
