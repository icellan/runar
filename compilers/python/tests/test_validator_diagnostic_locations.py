"""R-149 / CL-BUG-060 — the Python validator's diagnostics had no location.

``typecheck.py`` auto-attaches a location to every error it raises, so the same
contract produced located TYPE errors and unlocated VALIDATION errors. Counted
by bracket-matching every ``self._add_error(`` call in ``validator.py`` and
checking whether it passes a second argument: **11 sites**, including the whole
``asm()``-usage family and "Contract has no public methods".

The root cause the finding names is real and is not fixed here: Python's
``Expression`` nodes carry no ``SourceLocation`` at all (``ast_nodes.py``), so a
check reached from expression validation has nothing of its own to report. The
enclosing STATEMENT does have one, and statement granularity is the difference
between "somewhere in your contract" and "line 14" -- the same trade R-143 made
in the TypeScript typechecker and R-137/R-138 made in Rust.

What is NOT covered, stated so the gap is visible: ``expand_fixed_arrays.py``
still constructs an explicit empty ``SourceLocation()`` at three sites, with the
comment "expression source loc unavailable in Python AST". Those need the
Expression-level locations that R-142 added on the TypeScript side; they are a
separate change.
"""

import re
from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

VALIDATOR = (
    Path(__file__).resolve().parents[1] / "runar_compiler" / "frontend" / "validator.py"
)


def errors_for(source: str, file_name: str = "Probe.runar.ts"):
    result = compile_from_source_str_with_result(source, file_name)
    return [d for d in result.diagnostics if str(d.severity).lower().endswith("error")]


def assert_all_located(source: str, label: str, file_name: str = "Probe.runar.ts"):
    errors = errors_for(source, file_name)
    assert errors, f"{label}: expected at least one error, got none"
    for d in errors:
        assert d.loc is not None, f'{label}: "{d.message}" has no location'
        assert d.loc.line and d.loc.line > 0, f'{label}: "{d.message}" reports line {d.loc.line}'


ASM_CONTRACT = """import {{ UnsafeSmartContract, asm }} from 'runar-lang';

class Probe extends UnsafeSmartContract {{
  constructor() {{
    super();
  }}

  public unlock() {{
    {body}
  }}
}}
"""


# Only the shapes that actually REACH the validator. `body: 51`,
# `in_arity: -1` and `out_arity: -1` are intercepted by `parser_ts.py` first
# ("asm() body must be a hex string literal or an array of opcode names..."),
# whose diagnostics are also unlocated — a parser-layer instance of the same
# class, filed rather than fixed here, because a test that asserts it would be
# crediting this change with a fix it did not make.
@pytest.mark.parametrize(
    "body,label",
    [
        ("asm({ body: '5', in_arity: 0, out_arity: 1 });", "odd hex length"),
        ("asm({ body: '', in_arity: 0, out_arity: 1 });", "empty body"),
    ],
)
def test_asm_usage_diagnostics_are_located(body, label):
    assert_all_located(ASM_CONTRACT.format(body=body), label)


def test_asm_outside_unsafe_contract_is_located():
    assert_all_located(
        """import { SmartContract, asm } from 'runar-lang';

class Probe extends SmartContract {
  constructor() {
    super();
  }

  public unlock() {
    asm({ body: '51', in_arity: 0, out_arity: 1 });
  }
}
""",
        "asm outside UnsafeSmartContract",
    )


def test_for_loop_bound_diagnostic_is_located():
    assert_all_located(
        """import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public go(x: bigint) {
    let acc: bigint = 0n;
    for (let i = 0n; i < x; i++) {
      acc = acc + i;
    }
    assert(acc >= 0n);
  }
}
""",
        "runtime loop bound",
    )


def test_odd_length_bytestring_literal_is_located():
    assert_all_located(
        """import { SmartContract, assert, ByteString, len } from 'runar-lang';

class Probe extends SmartContract {
  readonly b: ByteString;

  constructor(b: ByteString) {
    super(b);
    this.b = b;
  }

  public go() {
    const x: ByteString = 'abc';
    assert(len(x) > 0n);
  }
}
""",
        "odd-length ByteString literal",
    )


def test_a_contract_level_diagnostic_is_located_too():
    """"No public methods" is a class-level complaint with no statement in
    scope. It is anchored at the constructor's declaration explicitly, because
    the fallback would have pointed at the constructor's LAST statement — a
    line with nothing to do with the problem. (The first version of this test
    claimed the site already passed a location; it did not, and the
    falsification run is what showed that, by turning this case red along with
    the rest.)"""
    assert_all_located(
        """import { SmartContract } from 'runar-lang';

class Probe extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }
}
""",
        "no public methods",
    )


def test_the_fallback_mechanism_exists_and_is_used():
    """The behavioural cases above can only reach the shapes they think to
    write. This asserts the mechanism itself: `_add_error` consults
    `current_stmt_loc` when a caller passes no location.

    Deliberately NOT a static scan for "every `_add_error` passes two
    arguments" — that was the first version of this check, and it is the wrong
    question now: the fallback IS the fix, so a site relying on it is correct
    rather than defective.
    """
    from runar_compiler.frontend.ast_nodes import ContractNode, SourceLocation
    from runar_compiler.frontend.validator import _ValidationContext

    ctx = _ValidationContext(contract=ContractNode(name="X"))
    ctx.current_stmt_loc = SourceLocation(file="X.runar.ts", line=42, column=7)
    ctx._add_error("probe")
    assert ctx.errors[0].loc is not None
    assert ctx.errors[0].loc.line == 42

    # An explicit location still wins over the fallback.
    ctx._add_error("probe2", SourceLocation(file="X.runar.ts", line=9, column=1))
    assert ctx.errors[1].loc.line == 9
