"""R-148 / CL-BUG-059 — the for-loop START had no validation.

The validator checks the BOUND for compile-time-constness with a proper
``Diagnostic`` (``validator.py``'s ``_validate_for_statement``) and ran only the
generic ``_validate_expression`` on ``stmt.init.init``. The start was therefore
checked nowhere until ``_extract_loop_shape`` in ``anf_lower.py``, which raises a
bare ``ValueError``. Measured before the fix::

    compile_from_source(...)                       RAISED ValueError
    compile_from_source_collecting_warnings(...)   RAISED ValueError

Both are the tier's public API. Every other failure in this compiler arrives as
a ``CompilationError`` carrying located diagnostics, so a caller written against
that contract -- ``CompileCheck``, an editor integration, anything that is not
the CLI -- got an exception type it does not catch and cannot read a location
from. The CLI hid it behind a generic ``except Exception``.

The fix puts the check where its sibling already is: the validator rejects a
non-literal start with the same located diagnostic, so the program fails in
validation like every other invalid program. ``_extract_loop_shape``'s raise
stays as the backstop for ``--ir`` inputs, which run no frontend.

The message is the other six tiers' sentence, word for word.

Adjacent findings from the same probe, fixed separately: N-137 (the Zig tier
COMPILED this shape, unrolling from 0) and N-138 (every Zig surface parser read
a negative literal start as 0).
"""

import pytest

from runar_compiler.compiler import (
    CompilationError,
    compile_from_source,
    compile_from_source_str_with_result,
)

LOOP_START_DIAGNOSTIC = (
    "Cannot determine loop start at compile time. "
    "For-loop iterators must start at an integer literal."
)


def ts_with_start(start: str) -> str:
    """A stateful contract parameterised on the for-loop START expression.

    The loop must be LIVE -- ``acc`` feeds a state write -- or DCE removes it
    before the shape is ever examined.
    """
    return f"""import {{ StatefulSmartContract, assert }} from 'runar-lang';

class StartProbe extends StatefulSmartContract {{
  count: bigint;

  constructor(count: bigint) {{ super(count); this.count = count; }}

  public unlock(start: bigint): void {{
    let acc: bigint = this.count;
    for (let i: bigint = {start}; i < 3n; i++) {{
      acc = acc + i;
    }}
    this.count = acc;
    assert(start >= 0n);
  }}
}}
"""


def compile_source(source: str, file_name: str):
    result = compile_from_source_str_with_result(source, file_name)
    diags = "\n".join(d.message for d in result.diagnostics)
    return result.success, (result.script_hex or ""), diags


@pytest.mark.parametrize("start", ["start", "this.count", "start + 1n"])
def test_runtime_start_is_a_diagnostic_not_a_bare_valueerror(start):
    ok, _, diags = compile_source(ts_with_start(start), "StartProbe.runar.ts")
    assert not ok, f"a runtime loop start ({start}) must not compile"
    assert LOOP_START_DIAGNOSTIC in diags, diags


@pytest.mark.parametrize("start", ["start", "this.count"])
def test_the_public_api_raises_CompilationError_not_ValueError(start, tmp_path):
    """The exception TYPE is the finding: a caller catching CompilationError
    saw a ValueError escape."""
    src = tmp_path / "StartProbe.runar.ts"
    src.write_text(ts_with_start(start), encoding="utf8")
    with pytest.raises(CompilationError) as exc:
        compile_from_source(str(src))
    assert LOOP_START_DIAGNOSTIC in str(exc.value)


def test_the_diagnostic_carries_a_location():
    result = compile_from_source_str_with_result(
        ts_with_start("start"), "StartProbe.runar.ts"
    )
    matching = [d for d in result.diagnostics if LOOP_START_DIAGNOSTIC in d.message]
    assert matching, "no loop-start diagnostic at all"
    loc = matching[0].loc
    assert loc is not None, "the loop-start diagnostic has no location"
    assert loc.line and loc.line > 0, f"line is {loc.line!r}"


@pytest.mark.parametrize("start", ["0n", "1n", "-1n", "3n"])
def test_literal_starts_still_compile(start):
    """Controls. A literal start -- negative included -- is unrollable and must
    keep compiling; this is the rule the bound check has always had."""
    ok, hex_out, diags = compile_source(ts_with_start(start), "StartProbe.runar.ts")
    assert ok, diags
    assert hex_out, "a compiling contract must produce script bytes"
