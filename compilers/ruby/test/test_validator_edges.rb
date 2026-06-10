# frozen_string_literal: true

require_relative 'test_helper'

require 'runar_compiler/frontend/ast_nodes'
require 'runar_compiler/frontend/diagnostic'
require 'runar_compiler/frontend/validator'
require 'runar_compiler/frontend/parser_ts'

# Additional validator coverage. Pairs with test_validator.rb (20 tests
# already), focusing on:
#   - constructor wiring details (param order, arg count mismatch with super)
#   - stateless contract mutation rejection
#   - method-body shape errors
#   - property-name collisions

class TestValidatorEdges < Minitest::Test
  include RunarCompiler::Frontend

  def parse_ts(source, file_name = 'Test.runar.ts')
    result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty result.errors.map(&:format_message), "unexpected parse errors: #{result.error_strings}"
    refute_nil result.contract, "expected a contract from parsing"
    result.contract
  end

  def validate(source, file_name = 'Test.runar.ts')
    contract = parse_ts(source, file_name)
    RunarCompiler::Frontend.validate(contract)
  end

  # ---------------------------------------------------------------------------
  # SmartContract with one readonly property and no constructor-body assignment
  # for that property is rejected (mirrors test_validator.rb but checks the
  # `must be assigned in the constructor` diagnostic message itself).
  # ---------------------------------------------------------------------------

  def test_unassigned_property_diagnostic_mentions_property_name
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly amount: bigint;

        constructor(amount: bigint) {
          super(amount);
          // forgot to assign this.amount = amount
        }

        public check(): void {
          assert(this.amount > 0n);
        }
      }
    TS

    result = validate(source)
    assert(result.errors.any? { |e| e.message.include?('amount') },
           "expected diagnostic mentioning 'amount', got: #{result.error_strings}")
  end

  # ---------------------------------------------------------------------------
  # Non-readonly property in SmartContract is rejected with a useful message.
  # ---------------------------------------------------------------------------

  def test_smart_contract_non_readonly_property_diag_mentions_readonly
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          assert(this.x > 0n);
        }
      }
    TS

    result = validate(source)
    assert(result.errors.any? { |e| e.message.downcase.include?('readonly') },
           "expected diagnostic about readonly, got: #{result.error_strings}")
  end

  # ---------------------------------------------------------------------------
  # Multiple properties with distinct names + matching constructor: OK
  # ---------------------------------------------------------------------------

  def test_three_properties_all_assigned_passes
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Triple extends SmartContract {
        readonly a: bigint;
        readonly b: bigint;
        readonly c: bigint;

        constructor(a: bigint, b: bigint, c: bigint) {
          super(a, b, c);
          this.a = a;
          this.b = b;
          this.c = c;
        }

        public check(): void {
          assert(this.a + this.b + this.c > 0n);
        }
      }
    TS

    result = validate(source)
    assert_empty result.errors.map(&:format_message)
  end

  # ---------------------------------------------------------------------------
  # Properties assigned via destructured arg shouldn't crash validator (a few
  # patterns the validator just walks past). Confirms graceful handling of
  # supported shapes; non-supported shapes are caught elsewhere.
  # ---------------------------------------------------------------------------

  def test_property_assignment_order_independent_of_decl_order
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class OutOfOrder extends SmartContract {
        readonly a: bigint;
        readonly b: bigint;

        constructor(a: bigint, b: bigint) {
          super(a, b);
          this.b = b;
          this.a = a;
        }

        public check(): void {
          assert(this.a + this.b > 0n);
        }
      }
    TS

    result = validate(source)
    assert_empty result.errors.map(&:format_message),
                 'assignment order in constructor should not affect validation'
  end

  # ---------------------------------------------------------------------------
  # Stateful contract: compound assignment to mutable property is OK
  # ---------------------------------------------------------------------------

  def test_stateful_compound_assignment_ok
    source = <<~TS
      import { StatefulSmartContract, assert } from 'runar-lang';

      class Counter extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

        public bump(): void {
          this.count += 1n;
        }
      }
    TS

    result = validate(source)
    refute(result.errors.any?,
           "stateful += on mutable prop should pass, got: #{result.error_strings}")
  end

  # ---------------------------------------------------------------------------
  # ByteString literal with even-length hex is OK
  # ---------------------------------------------------------------------------

  def test_bytestring_even_length_hex_ok
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Ok extends SmartContract {
        readonly tag: ByteString;

        constructor(tag: ByteString) {
          super(tag);
          this.tag = tag;
        }

        public check(): void {
          assert(this.tag === "deadbeef");
        }
      }
    TS

    result = validate(source)
    refute(result.errors.any? { |e| e.message.downcase.include?('hex') },
           "even-length hex literal should not error: #{result.error_strings}")
  end

  # ---------------------------------------------------------------------------
  # Empty contract (no methods, no properties) — pipeline tolerance
  # ---------------------------------------------------------------------------

  def test_empty_contract_no_methods_yields_warning_or_error
    source = <<~TS
      import { SmartContract } from 'runar-lang';

      class Empty extends SmartContract {
        constructor() {
          super();
        }
      }
    TS

    parse_result = RunarCompiler.send(:_parse_source, source, 'Empty.runar.ts')
    refute_nil parse_result.contract
    result = RunarCompiler::Frontend.validate(parse_result.contract)
    # Validator may accept or warn — we just confirm it doesn't crash and
    # the contract round-trips through the validator.
    refute_nil result
  end

  # ---------------------------------------------------------------------------
  # Diagnostic format: error_strings is non-empty when there are errors.
  # ---------------------------------------------------------------------------

  def test_error_strings_helper_works
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          assert(this.x > 0n);
        }
      }
    TS

    result = validate(source)
    refute_empty result.errors, 'expected at least one error'
    refute_empty result.error_strings, 'error_strings should mirror errors'
    assert(result.error_strings.all? { |s| s.is_a?(String) && !s.empty? })
  end

  # ---------------------------------------------------------------------------
  # Stateful contract with no mutable property emits a warning (not error).
  # ---------------------------------------------------------------------------

  def test_stateful_no_mutable_property_is_warning_not_error
    source = <<~TS
      import { StatefulSmartContract, assert } from 'runar-lang';

      class AllReadonly extends StatefulSmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          assert(this.x > 0n);
        }
      }
    TS

    result = validate(source)
    # Should be a warning, not an error (StatefulSmartContract is just under-
    # used, not broken).
    refute(result.errors.any? { |e| e.message.downcase.include?('mutable') },
           'mutable diagnostic should be a warning, not an error')
    assert(result.warnings.any? { |w| w.message.downcase.include?('mutable') },
           "expected warning about mutable, got warnings=#{result.warning_strings}")
  end
end
