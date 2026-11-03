"""N-049 (EXT-2 "TernaryToll") -- an output intrinsic inside a ternary arm.

``_lower_ternary_expr`` lowers each arm into a sub-context whose output refs
are dropped, unlike the if-statement lowering, which merges each arm's refs
into the parent. The continuation hash therefore omitted the arm's output:
measured on every tier, a spend that drops the payee output was accepted and
the honest spend rejected. Fail-closed like R-127: the validator refuses an
output intrinsic (direct, or through an inlined private helper) in either arm
with the shared N-049 diagnostic, and pass 4 refuses it again when reached
unvalidated.

What this proves: this tier refuses the ternary-arm shapes at pass 2 and pass 4
with the shared diagnostic, and still accepts and lowers a ternary that only
selects VALUES.
What it does not prove: anything about emitted bytes (the cross-tier control is
conformance/negatives/ternary-output-control.test.ts).
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate

HEAD = """import { StatefulSmartContract, ByteString } from 'runar-lang';

class ConditionalPayout extends StatefulSmartContract {
  count: bigint;
  readonly payee: ByteString;
  readonly refund: ByteString;

  constructor(count: bigint, payee: ByteString, refund: ByteString) {
    super(count, payee, refund);
    this.count = count;
    this.payee = payee;
    this.refund = refund;
  }
"""

TERNARY_ARMS = """  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.addRawOutput(50000n, this.payee)
                    : this.addRawOutput(50000n, this.refund);
  }"""

VALUE_SELECTING = """  public release() {
    this.addOutput(1000n, this.count);
    this.addRawOutput(50000n, this.count > 0n ? this.payee : this.refund);
  }"""

REFUSAL = (
    "Output intrinsic 'addRawOutput' cannot be called inside a conditional "
    "(ternary) expression arm."
)


def _contract(methods: str):
    result = parse_source(HEAD + methods + "\n}\n", "ConditionalPayout.runar.ts")
    assert not result.errors, result.errors
    return result.contract


def _errors(methods: str) -> str:
    return "\n".join(d.message for d in validate(_contract(methods)).errors)


def test_validator_refuses_output_intrinsic_in_ternary_arm():
    assert REFUSAL in _errors(TERNARY_ARMS)


def test_validator_refuses_helper_output_in_ternary_arm():
    errs = _errors("""  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.payTo(this.payee) : this.payTo(this.refund);
  }

  private payTo(script: ByteString): void {
    this.addRawOutput(50000n, script);
  }""")
    assert (
        "Output intrinsic 'addRawOutput' (reached through private method 'payTo') "
        "cannot be called inside a conditional (ternary) expression arm."
    ) in errs


def test_lowering_refuses_ternary_arm_output_without_validation():
    with pytest.raises(Exception) as exc:
        lower_to_anf(_contract(TERNARY_ARMS))
    assert REFUSAL in str(exc.value)


def test_value_selecting_ternary_still_accepted():
    assert _errors(VALUE_SELECTING) == ""
    lower_to_anf(_contract(VALUE_SELECTING))
