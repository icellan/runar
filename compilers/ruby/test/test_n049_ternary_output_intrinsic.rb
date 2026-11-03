# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/anf_lower"
require "runar_compiler/frontend/parser_ts"

# N-049 (EXT-2 "TernaryToll") -- an output intrinsic inside a ternary arm.
#
# `_lower_ternary_expr` lowers each arm into a sub-context whose output refs
# are dropped, unlike the if-statement lowering, which merges each arm's refs
# into the parent. The continuation hash therefore omitted the arm's output:
# measured on every tier, a spend that drops the payee output was accepted and
# the honest spend rejected. Fail-closed like R-127: the validator refuses an
# output intrinsic (direct, or through an inlined private helper) in either arm
# with the shared N-049 diagnostic, and pass 4 refuses it again when reached
# unvalidated.
#
# What this proves: this tier refuses the ternary-arm shapes at pass 2 and
# pass 4 with the shared diagnostic, and still accepts and lowers a ternary
# that only selects VALUES.
# What it does not prove: anything about emitted bytes (the cross-tier control
# is conformance/negatives/ternary-output-control.test.ts).
class TestN049TernaryOutputIntrinsic < Minitest::Test
  HEAD = <<~TS
    import { StatefulSmartContract, ByteString } from 'runar-lang';

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
  TS

  TERNARY_ARMS = <<~TS
    public release() {
      this.addOutput(1000n, this.count);
      this.count > 0n ? this.addRawOutput(50000n, this.payee)
                      : this.addRawOutput(50000n, this.refund);
    }
  TS

  VALUE_SELECTING = <<~TS
    public release() {
      this.addOutput(1000n, this.count);
      this.addRawOutput(50000n, this.count > 0n ? this.payee : this.refund);
    }
  TS

  REFUSAL = "Output intrinsic 'addRawOutput' cannot be called inside a conditional " \
            "(ternary) expression arm."

  def contract_of(methods)
    parse_result = RunarCompiler.send(:_parse_source, "#{HEAD}#{methods}\n}\n", "ConditionalPayout.runar.ts")
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    parse_result.contract
  end

  def validation_errors(methods)
    RunarCompiler::Frontend.validate(contract_of(methods)).errors.map(&:message).join("\n")
  end

  def lower_unvalidated(methods)
    RunarCompiler::Frontend.lower_to_anf(contract_of(methods))
    nil
  rescue StandardError => e
    e.message
  end

  def test_validator_refuses_output_intrinsic_in_ternary_arm
    assert_includes validation_errors(TERNARY_ARMS), REFUSAL
  end

  def test_validator_refuses_helper_output_in_ternary_arm
    errs = validation_errors(<<~TS)
      public release() {
        this.addOutput(1000n, this.count);
        this.count > 0n ? this.payTo(this.payee) : this.payTo(this.refund);
      }

      private payTo(script: ByteString): void {
        this.addRawOutput(50000n, script);
      }
    TS
    assert_includes errs,
                    "Output intrinsic 'addRawOutput' (reached through private method 'payTo') " \
                    "cannot be called inside a conditional (ternary) expression arm."
  end

  def test_lowering_refuses_ternary_arm_output_without_validation
    msg = lower_unvalidated(TERNARY_ARMS)
    refute_nil msg, "lower_to_anf accepted an output intrinsic inside a ternary arm"
    assert_includes msg, REFUSAL
  end

  def test_value_selecting_ternary_still_accepted
    assert_equal "", validation_errors(VALUE_SELECTING)
    assert_nil lower_unvalidated(VALUE_SELECTING)
  end
end
