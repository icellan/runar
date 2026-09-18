"""Regression tests for CL-BUG-088 / R-009: nothing bounded the magnitude of an
unrolled loop's iteration count on the SOURCE path, in any tier.

This tier does no narrowing at all — Python integers are arbitrary precision, so
``max(0, count)`` faithfully preserves a bound of 10²⁰ and hands it to the
unroller, which then tries to honour it. Reproduced at HEAD: bounds of 2^63 and
2^64+10 both run past a 20-second wall clock with no diagnostic and no end in
sight. The absence of a truncation bug is exactly what makes this tier hang
instead of silently emitting the wrong script.

The ceiling half of the contract: ``MAX_LOOP_COUNT`` (10000) existed in
``runar_compiler.ir.loader`` but was checked only against ANF IR arriving
pre-built on the ``--ir`` path. A loop written in source could ask for any
count; 10001 compiled happily.

What these tests pin: an over-ceiling loop bound is a compile-time diagnostic,
and a valid loop still compiles to the exact bytes it produced before the guard
existed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

# Watchdog for a single compile, in seconds. The compile is CPU-bound and
# synchronous, so a regression does not fail — it wedges. Nothing inside the
# test process can interrupt it, which is why the out-of-range cases run as
# their own process (the Python analogue of the Go tier's
# goroutine-behind-a-watchdog in bigint_narrowing_guard_test.go).
WATCHDOG_SECONDS = 30

PY_COMPILER_ROOT = Path(__file__).resolve().parents[1]


def loop_bound_source(bound: str) -> str:
    return f"""import {{ SmartContract, assert }} from 'runar-lang';

export class LoopBound extends SmartContract {{
  constructor() {{ super(); }}

  public unlock(x: bigint): void {{
    let acc: bigint = 0n;
    for (let i = 0n; i < {bound}n; i++) {{
      acc = acc + i;
    }}
    assert(acc === x);
  }}
}}
"""


CHILD_PROGRAM = """
import json, sys
sys.path.insert(0, sys.argv[1])
from runar_compiler.compiler import compile_from_source_str_with_result
result = compile_from_source_str_with_result(sys.argv[2], "LoopBound.runar.ts")
sys.stdout.write(json.dumps({
    "success": result.success,
    "script": result.script_hex,
    "diagnostics": [d.message for d in result.diagnostics],
}))
"""


def compile_in_child(bound: str) -> dict:
    """Compile the given bound in a child process behind a hard timeout."""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", CHILD_PROGRAM, str(PY_COMPILER_ROOT), loop_bound_source(bound)],
            capture_output=True,
            text=True,
            timeout=WATCHDOG_SECONDS,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            f"bound {bound} did not produce a diagnostic within {WATCHDOG_SECONDS}s — "
            "the unbounded count is still driving loop unrolling"
        )
    assert proc.returncode == 0, (
        f"bound {bound}: the child compile exited {proc.returncode} instead of "
        f"reporting a diagnostic.\nstderr: {proc.stderr[-2000:]}"
    )
    return json.loads(proc.stdout)


def assert_rejected(outcome: dict, label: str) -> None:
    assert not outcome["success"], (
        f"bound {label}: expected a compile diagnostic, got a successful compile "
        f"(script {outcome['script']})"
    )
    assert any("loop" in m.lower() for m in outcome["diagnostics"]), (
        f"bound {label}: expected a diagnostic mentioning the loop bound, got "
        f"{outcome['diagnostics']}"
    )


@pytest.mark.parametrize("bound,expected_hex", [("3", "537c9c"), ("10", "012d7c9c")])
@pytest.mark.parametrize("disable_constant_folding", [False, True])
def test_loop_bound_control_still_compiles_byte_identically(
    bound: str, expected_hex: str, disable_constant_folding: bool
):
    """Control: a normal small bound must keep compiling, and to the exact bytes
    it produced before the ceiling was added. If a guard moves these, the guard
    is not byte-neutral and the change is a codegen regression, not a fix."""
    result = compile_from_source_str_with_result(
        loop_bound_source(bound),
        "LoopBound.runar.ts",
        disable_constant_folding=disable_constant_folding,
    )
    assert result.success, f"diagnostics: {[d.message for d in result.diagnostics]}"
    assert result.script_hex == expected_hex


def test_loop_bound_2_pow_63_is_rejected_without_hanging():
    assert_rejected(compile_in_child("9223372036854775808"), "2^63")


def test_loop_bound_2_pow_64_plus_10_is_rejected_without_hanging():
    outcome = compile_in_child("18446744073709551626")
    assert_rejected(outcome, "2^64+10")
    # Belt and braces: whatever happens, it must not silently agree with the
    # `i < 10n` contract the way the modular-wrap tiers did.
    assert outcome["script"] != "012d7c9c"


def test_loop_bound_10_pow_20_is_rejected_without_hanging():
    assert_rejected(compile_in_child("100000000000000000000"), "10^20")


def test_loop_bound_exceeding_max_loop_count_is_rejected_on_source_path():
    """The ceiling half of the fix: MAX_LOOP_COUNT must apply to a loop written
    in source, not only to ANF IR arriving pre-built."""
    outcome = compile_in_child("10001")
    assert_rejected(outcome, "10001")
    assert "10000" in " ".join(outcome["diagnostics"]), (
        f"expected the diagnostic to name the maximum loop count, got "
        f"{outcome['diagnostics']}"
    )
