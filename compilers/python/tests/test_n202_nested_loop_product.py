"""N-202: the source path bounds the PRODUCT of nested loop counts, not just
each loop's own count.

``_extract_loop_shape`` caps one for-loop at MAX_LOOP_COUNT (10,000). Two loops
of 9,000, one inside the other, each passed that cap while the unrolled work was
81,000,000 iterations: this tier hung with no diagnostic. F-283 refuses the same
nest on the --ir path, so a source contract compiled while its own emitted IR
was refused on replay.

Proves: on the Python source path a 101 x 100 nest is refused with the shared
product diagnostic, also when the inner loop sits in an if arm, a 9000 x 9000
nest is refused inside the watchdog, and a nest of exactly 10,000 still
compiles. Every compile runs in a child process behind a timeout, so a
regression fails instead of hanging.
Does not prove: the other tiers (conformance/negatives/n202-nested-loop-
product-parity.test.ts), or loops reached through a private method call that
stack lowering inlines later -- the bound is per-method nesting in ANF, the same
rule the --ir loader applies.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

WATCHDOG_SECONDS = 60

PY_COMPILER_ROOT = Path(__file__).resolve().parents[1]

CHILD_PROGRAM = """
import json, sys
sys.path.insert(0, sys.argv[1])
from runar_compiler.compiler import compile_from_source_str_with_result
result = compile_from_source_str_with_result(sys.argv[2], "NestedLoops.runar.ts")
sys.stdout.write(json.dumps({
    "success": result.success,
    "diagnostics": [d.message for d in result.diagnostics],
}))
"""


def nested_loop_source(outer: int, inner: int, in_if_arm: bool = False) -> str:
    inner_loop = f"for (let j = 0n; j < {inner}n; j++) {{ acc = acc + x; }}"
    if in_if_arm:
        inner_loop = f"if (x > 0n) {{ {inner_loop} }}"
    return f"""import {{ SmartContract, assert }} from 'runar-lang';

export class NestedLoops extends SmartContract {{
  constructor() {{ super(); }}

  public unlock(x: bigint): void {{
    let acc: bigint = 0n;
    for (let i = 0n; i < {outer}n; i++) {{ {inner_loop} }}
    assert(acc > x);
  }}
}}
"""


def compile_in_child(source: str) -> dict:
    try:
        proc = subprocess.run(
            [sys.executable, "-c", CHILD_PROGRAM, str(PY_COMPILER_ROOT), source],
            capture_output=True,
            text=True,
            timeout=WATCHDOG_SECONDS,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            f"compile did not finish within {WATCHDOG_SECONDS}s -- nested loops "
            "are being unrolled unbounded"
        )
    assert proc.returncode == 0, (
        f"the child compile exited {proc.returncode}.\nstderr: {proc.stderr[-2000:]}"
    )
    return json.loads(proc.stdout)


def product_diag(count: int, enclosing: int) -> str:
    return (
        f"For loop unrolls to {count} iterations nested inside an enclosing loop "
        f"of total count {enclosing}, producing {count * enclosing} total "
        f"iterations, exceeding the maximum loop count of 10000."
    )


@pytest.mark.parametrize("in_if_arm", [False, True])
def test_nested_loop_product_over_max_is_rejected(in_if_arm: bool):
    outcome = compile_in_child(nested_loop_source(101, 100, in_if_arm))
    assert not outcome["success"], "expected the 101 x 100 nest to be refused"
    assert any(product_diag(100, 101) in m for m in outcome["diagnostics"]), outcome["diagnostics"]


def test_nested_loop_9000_by_9000_is_rejected_without_hanging():
    outcome = compile_in_child(nested_loop_source(9000, 9000))
    assert not outcome["success"]
    assert any(product_diag(9000, 9000) in m for m in outcome["diagnostics"]), outcome["diagnostics"]


def test_nested_loop_product_at_max_still_compiles():
    outcome = compile_in_child(nested_loop_source(100, 100))
    assert outcome["success"], outcome["diagnostics"]
