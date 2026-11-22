# frozen_string_literal: true

# D25: Frontend.lower_to_anf is a public entry point. A caller that assembles
# its own pipeline (parse -> validate -> type_check -> lower_to_anf) and never
# runs ContinuationBinding.inject would otherwise lower a mixed ("bind")
# contract with no _spentOutpointHash: its continuations would not be bound to
# the spent outpoint, which is the twin-input theft D25 closes.

require_relative "test_helper"

class TestD25LowerInjectsBinding < Minitest::Test
  FIELD = RunarCompiler::Frontend::ContinuationBinding::TWIN_BINDING_FIELD

  MIXED = <<~TS
    import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
    class MixedPot extends StatefulSmartContract {
      count: bigint;
      constructor(count: bigint) { super(count); this.count = count; }
      public increment() { this.count++; }
      public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
    }
  TS

  def frontend
    pr = RunarCompiler.send(:_parse_source, MIXED, "MixedPot.runar.ts")
    assert_empty pr.errors.map(&:format_message)
    contract = pr.contract
    refute_nil contract
    assert_empty RunarCompiler::Frontend.validate(contract).errors.map(&:format_message)
    assert_empty RunarCompiler::Frontend.type_check(contract).errors.map(&:format_message)
    contract
  end

  def test_lower_to_anf_injects_binding_without_caller_injection
    props = RunarCompiler::Frontend.lower_to_anf(frontend).properties
    assert_equal FIELD, props.last&.name, "binding not injected"
  end

  def test_lower_to_anf_does_not_inject_twice
    injected = RunarCompiler::Frontend::ContinuationBinding.inject(frontend)
    props = RunarCompiler::Frontend.lower_to_anf(injected).properties
    assert_equal 1, props.count { |p| p.name == FIELD }
  end
end
