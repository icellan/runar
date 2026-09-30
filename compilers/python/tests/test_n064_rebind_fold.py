"""N-064 — constant folding must not fold with a constant a name no longer
holds. Port of the reference tier's case in
packages/runar-compiler/src/__tests__/optimizer.test.ts.

The folder recorded a name's constant when a binding produced one and never
dropped it. A name can be bound more than once (a reassignment, or a user
local that shares an earlier compiler temp's name — that collision is N-065
and is not changed here), so with folding ON (the default) later uses folded
with a stale value: Rebind's guard became OP_TRUE (7600a0695151515177777777,
spendable with any p > 0), RebindEq's became OP_FALSE, and a rebinding inside
an if arm or a loop body leaked the same way past the if / into later
iterations.

Proves: this tier compiles each probe to the same bytes in both fold modes,
pinned to the fold-OFF bytes every tier emits. Does NOT prove on-chain
behaviour — the Spend-engine proof for all seven tiers is
packages/runar-testing/src/__tests__/n064-rebind-fold-spend.test.ts.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

PROBES = [
    ("Rebind.runar.ts", """import { SmartContract, assert } from 'runar-lang';
class Rebind extends SmartContract {
  constructor() { super(); }
  public unlock(p: bigint) {
    assert(p > 0n);
    let t1: bigint = p;
    assert(t1 + 1n === 1n);
  }
}
""", "76007c78a0697c8b519c77"),
    ("RebindEq.runar.ts", """import { SmartContract, assert } from 'runar-lang';
class RebindEq extends SmartContract {
  constructor() { super(); }
  public unlock(p: bigint) {
    assert(p > 0n);
    let t1: bigint = p;
    assert(t1 === 5n);
  }
}
""", "76007c78a0697c559c77"),
    ("IfStale.runar.ts", """import { SmartContract, assert } from 'runar-lang';
class IfStale extends SmartContract {
  constructor() { super(); }
  public unlock(p: bigint, c: boolean) {
    let t2: bigint = p;
    assert(p > 0n);
    if (c) {
      t2 = p;
    }
    assert(t2 + 1n === 1n);
  }
}
""", "767600877c51879b69785279007c78a0697b637b677b757668778b519c77"),
    ("LoopStale.runar.ts", """import { SmartContract, assert } from 'runar-lang';
class LoopStale extends SmartContract {
  constructor() { super(); }
  public unlock(p: bigint) {
    let t2: bigint = p;
    assert(p > 0n);
    for (let i: bigint = 0n; i < 2n; i++) {
      assert(t2 + 1n === 1n);
      t2 = p;
    }
    assert(t2 + 1n === 1n);
  }
}
""", "7678007c78a06900517b7c93519d52797751517b7c93519d7b778b519c77"),
]


@pytest.mark.parametrize("disable", [True, False])
@pytest.mark.parametrize("file_name,source,want", PROBES, ids=[p[0] for p in PROBES])
def test_fold_on_does_not_use_a_stale_constant(file_name: str, source: str, want: str, disable: bool) -> None:
    result = compile_from_source_str_with_result(source, file_name, disable_constant_folding=disable)
    if not result.success:
        msgs = "; ".join(d.message for d in result.diagnostics)
        pytest.fail(f"compilation failed: {msgs}")
    assert result.script_hex == want
