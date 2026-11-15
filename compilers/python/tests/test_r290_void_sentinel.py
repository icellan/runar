"""R-290 -- ``_inline_private_method_call`` used to emit a
``load_const "@void"`` sentinel when the inlined body produced no bindings.

No tier's stack lowering recognises ``"@void"`` (unlike ``"@this"``, which IS
special-cased), so the sentinel survived pass 4 and died in the hex decoder:
Go said ``invalid byte: U+0040 '@'``, Rust said ``invalid hex string
length: 5``. Neither names the method or the problem, and both fire only
because the string happens to be odd-length and non-hex -- an even-length
sentinel would decode to zeros in Rust's ``from_str_radix(..).unwrap_or(0)``
and reach the script.

It is reachable. The side-effect summary resolves a called name through a
LAST-WINS map and caches the result under that name, while
``get_private_method`` returns the FIRST match. Declare the public caller
BEFORE two same-named privates and the two disagree: the summary describes the
output-emitting ``helper`` (so ``should_inline_private`` is true) while the
lowerer inlines the empty one.

GK-BUG-015: the validator now refuses a repeated method name, so a SOURCE with
two ``helper`` bodies never reaches pass 4 through the pipeline. The backstop
is still worth pinning because ``lower_to_anf`` is a public entry point: the
duplicate is built by hand here -- the source declares ``helper`` and
``helper2`` and the test renames the second one on the parsed AST.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate

EMPTY_INLINED_BODY = """
class R290Void extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(x: bigint) {
    this.count = x;
    this.helper();
  }

  private helper(): void {
  }

  private helper2(): void {
    this.addOutput(1000n, this.count);
  }
}
"""

# Control: the ordinary shape -- one private helper that really does emit an
# output. The inlining path must still work; a refusal that simply rejected
# every inlined private would pass the test above.
CONTROL_EMITTING_HELPER = """
class R290Control extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(x: bigint) {
    this.count = x;
    this.helper();
  }

  private helper(): void {
    this.addOutput(1000n, this.count);
  }
}
"""


def _contract(source: str):
    parsed = parse_source(source, "R290.runar.ts")
    assert not parsed.errors, parsed.errors
    assert parsed.contract is not None
    return parsed.contract


def _hand_built_duplicate():
    contract = _contract(EMPTY_INLINED_BODY)
    second = next(m for m in contract.methods if m.name == "helper2")
    second.name = "helper"
    return contract


def test_validate_refuses_the_hand_built_duplicate():
    errors = [e.message for e in validate(_hand_built_duplicate()).errors]
    assert "method 'helper' is already declared in this contract and cannot be re-declared" in errors


def test_empty_inlined_body_is_refused_not_sentinelled():
    with pytest.raises(
        ValueError,
        match=r"private method 'helper' was inlined but produced no bindings",
    ):
        lower_to_anf(_hand_built_duplicate())


def test_no_void_sentinel_remains():
    program = lower_to_anf(_contract(CONTROL_EMITTING_HELPER))
    for method in program.methods:
        for binding in method.body:
            assert binding.value.const_string != "@void", (
                f"method {method.name} binding {binding.name} still carries the sentinel"
            )


def test_emitting_helper_still_inlines():
    lower_to_anf(_contract(CONTROL_EMITTING_HELPER))
