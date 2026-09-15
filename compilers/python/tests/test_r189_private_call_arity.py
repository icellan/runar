"""R-189 -- a private method may shadow a builtin, and nothing upstream of ANF
lowering notices when the two disagree about arity.

Typecheck resolves a BARE-IDENTIFIER call against the builtin table BEFORE it
looks at the contract's own methods; ANF lowering resolves the same call
against private methods FIRST. So ``min(x, y)`` against
``private min(a, b, c)`` type-checks as the two-argument BUILTIN ``min`` and
then lowers as the three-parameter METHOD ``min``. No validator forbids the
shadowing.

The zip that bound params to args stopped at the shorter list. When the surplus
parameter was never read the contract compiled CLEAN -- an arity mismatch
silently accepted. When it was read, the defect surfaced two passes later as
"method parameter 'c' is not on the stack", a stack-lowering message about a
pass the author never wrote in.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source

# The silent case: `c` is never read, so nothing downstream ever noticed.
SURPLUS_PARAM_UNREAD = """
class R189Unread extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    min(x, y);
  }
}
"""

# Too many arguments: `y` was evaluated and then dropped on the floor.
TOO_MANY_ARGS = """
class R189Extra extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint): bigint {
    this.count = a;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    min(x, y);
  }
}
"""

# Control 1: the SAME builtin-shadowing private, called at its real arity
# through `this.` -- the bare form cannot reach pass 4 at arity 3, because
# pass 3 checks it against the two-argument BUILTIN `min` and refuses.
CONTROL_SHADOWING_AT_REAL_ARITY = """
class R189ControlShadow extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b + c;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint, z: bigint) {
    this.min(x, y, z);
  }
}
"""

# Control 2: an ordinary private helper, bare-identifier call at matching
# arity -- the Move / Go-DSL lowering path this refusal sits directly on.
# Without the controls, a refusal that simply rejected every private call would
# pass both tests above.
CONTROL_PLAIN_PRIVATE = """
class R189ControlPlain extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private tally(a: bigint, b: bigint): bigint {
    this.count = a + b;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    tally(x, y);
  }
}
"""


def _contract(source: str):
    parsed = parse_source(source, "R189.runar.ts")
    assert not parsed.errors, parsed.errors
    assert parsed.contract is not None
    return parsed.contract


def test_surplus_parameter_is_refused_not_silently_dropped():
    with pytest.raises(ValueError, match=r"private method 'min' expects 3 argument\(s\), got 2\."):
        lower_to_anf(_contract(SURPLUS_PARAM_UNREAD))


def test_surplus_argument_is_refused_not_silently_dropped():
    with pytest.raises(ValueError, match=r"private method 'min' expects 1 argument\(s\), got 2\."):
        lower_to_anf(_contract(TOO_MANY_ARGS))


@pytest.mark.parametrize(
    "name,source",
    [
        ("builtin-shadowing private at its real arity", CONTROL_SHADOWING_AT_REAL_ARITY),
        ("plain private helper, bare-identifier call", CONTROL_PLAIN_PRIVATE),
    ],
)
def test_matching_arity_still_lowers(name, source):
    lower_to_anf(_contract(source))
