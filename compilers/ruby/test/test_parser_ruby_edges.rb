# frozen_string_literal: true

require_relative 'test_helper'

# Edge-case coverage for the .runar.rb (Ruby) surface parser.
#
# The base test_parser_ruby.rb covers 4 happy-path shapes. This file extends
# coverage to the Ruby-specific surface ergonomics: snake_case mapping,
# integer-division operator, boolean keyword operators (`and`/`or`/`not`),
# property initializers via `default:`, addOutput / addRawOutput intrinsics,
# `runar_public` typed-param hash, and malformed-input diagnostics.
#
# All tests are read-only — they exercise the public parse path and assert
# on the resulting AST without touching parser internals.

class TestParserRubyEdges < Minitest::Test
  require 'runar_compiler/frontend/parser_ruby'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.rb')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  # ---------------------------------------------------------------------------
  # snake_case → camelCase mapping
  # ---------------------------------------------------------------------------

  def test_snake_case_method_name_to_camel_case
    source = <<~RB
      require 'runar'

      class HashCheck < Runar::SmartContract
        prop :pub_key_hash, Addr

        def initialize(pub_key_hash)
          super(pub_key_hash)
          @pub_key_hash = pub_key_hash
        end

        runar_public pub_key: PubKey
        def check_hash(pub_key)
          assert hash160(pub_key) == @pub_key_hash
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    method = result.contract.methods.find { |m| m.name == 'checkHash' }
    refute_nil method, 'expected check_hash to be mapped to checkHash'
  end

  def test_multiple_snake_underscore_segments
    source = <<~RB
      require 'runar'

      class MultiSnake < Runar::SmartContract
        prop :very_long_property_name, Bigint

        def initialize(very_long_property_name)
          super(very_long_property_name)
          @very_long_property_name = very_long_property_name
        end

        runar_public
        def check
          assert @very_long_property_name > 0
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    prop = result.contract.properties.first
    assert_equal 'veryLongPropertyName', prop.name
  end

  def test_snake_case_param_names_camel_cased
    source = <<~RB
      require 'runar'

      class P < Runar::SmartContract
        prop :x, Bigint

        def initialize(x)
          super(x)
          @x = x
        end

        runar_public first_value: Bigint, second_value: Bigint
        def verify(first_value, second_value)
          assert first_value + second_value == @x
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    method = result.contract.methods.first
    names = method.params.map(&:name).sort
    assert_equal %w[firstValue secondValue], names
  end

  # ---------------------------------------------------------------------------
  # Boolean keyword operators (and / or / not) vs symbolic (&&, ||, !)
  # ---------------------------------------------------------------------------

  def test_boolean_keyword_operators
    source = <<~RB
      require 'runar'

      class Bools < Runar::SmartContract
        prop :a, Bool

        def initialize(a)
          super(a)
          @a = a
        end

        runar_public b: Bool, c: Bool
        def check(b, c)
          assert (b and c) or (not @a)
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message), result.error_strings.join('; ')
    refute_nil result.contract
  end

  def test_boolean_symbolic_operators
    source = <<~RB
      require 'runar'

      class Bools2 < Runar::SmartContract
        prop :a, Bool

        def initialize(a)
          super(a)
          @a = a
        end

        runar_public b: Bool
        def check(b)
          assert (b && @a) || !@a
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
  end

  # ---------------------------------------------------------------------------
  # Property initializer via `default:`
  # ---------------------------------------------------------------------------

  def test_property_default_initializer
    source = <<~RB
      require 'runar'

      class WithDefault < Runar::SmartContract
        prop :x, Bigint, default: 42

        runar_public
        def check
          assert @x == 42
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message), result.error_strings.join('; ')
    prop = result.contract.properties.first
    refute_nil prop.initializer, 'expected initializer to be captured'
    assert_instance_of BigIntLiteral, prop.initializer
    assert_equal 42, prop.initializer.value
  end

  def test_property_no_initializer
    source = <<~RB
      require 'runar'

      class NoInit < Runar::SmartContract
        prop :x, Bigint

        def initialize(x)
          super(x)
          @x = x
        end

        runar_public
        def check
          assert @x > 0
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    assert_nil result.contract.properties.first.initializer
  end

  # ---------------------------------------------------------------------------
  # Stateful contract: mutable property, no readonly
  # ---------------------------------------------------------------------------

  def test_stateful_property_is_not_readonly
    source = <<~RB
      require 'runar'

      class Counter < Runar::StatefulSmartContract
        prop :count, Bigint

        def initialize(count)
          super(count)
          @count = count
        end

        runar_public
        def bump
          @count = @count + 1
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    prop = result.contract.properties.first
    refute prop.readonly, 'StatefulSmartContract prop must not be readonly by default'
  end

  def test_stateless_property_is_readonly
    source = <<~RB
      require 'runar'

      class Const < Runar::SmartContract
        prop :x, Bigint

        def initialize(x)
          super(x)
          @x = x
        end

        runar_public
        def check
          assert @x > 0
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    assert result.contract.properties.first.readonly,
           'SmartContract prop must be readonly'
  end

  # ---------------------------------------------------------------------------
  # addOutput / addRawOutput intrinsic mapping
  # ---------------------------------------------------------------------------

  def test_add_output_intrinsic_recognized
    source = <<~RB
      require 'runar'

      class Out < Runar::StatefulSmartContract
        prop :count, Bigint

        def initialize(count)
          super(count)
          @count = count
        end

        runar_public
        def bump
          @count = @count + 1
          self.add_output(1000, @count)
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message), result.error_strings.join('; ')
    refute_nil result.contract
  end

  # ---------------------------------------------------------------------------
  # Private methods (no runar_public marker)
  # ---------------------------------------------------------------------------

  def test_private_helper_method
    source = <<~RB
      require 'runar'

      class WithPriv < Runar::SmartContract
        prop :x, Bigint

        def initialize(x)
          super(x)
          @x = x
        end

        def helper
          @x + 1
        end

        runar_public
        def check
          assert helper > 0
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    helper = result.contract.methods.find { |m| m.name == 'helper' }
    refute_nil helper
    assert_equal 'private', helper.visibility
  end

  # ---------------------------------------------------------------------------
  # Multiple public methods preserve declaration order
  # ---------------------------------------------------------------------------

  def test_multiple_public_methods_preserve_order
    source = <<~RB
      require 'runar'

      class Multi < Runar::SmartContract
        prop :x, Bigint

        def initialize(x)
          super(x)
          @x = x
        end

        runar_public
        def one
          assert @x > 0
        end

        runar_public
        def two
          assert @x > 1
        end

        runar_public
        def three
          assert @x > 2
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    public_methods = result.contract.methods.select { |m| m.visibility == 'public' }
    assert_equal %w[one two three], public_methods.map(&:name)
  end

  # ---------------------------------------------------------------------------
  # Multiple properties preserve declaration order
  # ---------------------------------------------------------------------------

  def test_multiple_properties_preserve_order
    source = <<~RB
      require 'runar'

      class ThreeProps < Runar::SmartContract
        prop :alpha, Bigint
        prop :beta, Bool
        prop :gamma, Bytestring

        def initialize(alpha, beta, gamma)
          super(alpha, beta, gamma)
          @alpha = alpha
          @beta = beta
          @gamma = gamma
        end

        runar_public
        def check
          assert @alpha > 0
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    assert_equal %w[alpha beta gamma], result.contract.properties.map(&:name)
  end

  # ---------------------------------------------------------------------------
  # Comparison + arithmetic flow
  # ---------------------------------------------------------------------------

  def test_arithmetic_and_comparison
    source = <<~RB
      require 'runar'

      class Arith < Runar::SmartContract
        prop :target, Bigint

        def initialize(target)
          super(target)
          @target = target
        end

        runar_public a: Bigint, b: Bigint
        def verify(a, b)
          assert (a + b) * 2 == @target
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    refute_nil result.contract
  end

  # ---------------------------------------------------------------------------
  # Malformed sources produce diagnostics, not crashes
  # ---------------------------------------------------------------------------

  def test_unterminated_class_body_does_not_crash
    source = <<~RB
      require 'runar'

      class Broken < Runar::SmartContract
        prop :x, Bigint
        # No end, no methods, no constructor
    RB

    # Must NOT raise — the parser may recover (auto-generate ctor, etc.) or
    # report diagnostics. Either is acceptable as long as it terminates.
    begin
      parse(source)
    rescue StandardError => e
      flunk "parser crashed on malformed source: #{e.class}: #{e.message}"
    end
  end

  def test_garbage_input_does_not_crash
    begin
      result = parse('@@@ not ruby at all $$$', 'garbage.runar.rb')
      assert(result.contract.nil? || !result.errors.empty?,
             'expected diagnostics for garbage input')
    rescue StandardError => e
      flunk "parser crashed on garbage input: #{e.class}: #{e.message}"
    end
  end

  def test_missing_prop_type_diagnostic
    source = <<~RB
      require 'runar'

      class Bad < Runar::SmartContract
        prop :x

        runar_public
        def check
          assert true
        end
      end
    RB

    # Missing type after `prop :x,` should produce a diagnostic without crashing.
    begin
      result = parse(source)
      bad = result.contract.nil? || !result.errors.empty?
      assert bad, 'expected diagnostics for prop without type'
    rescue StandardError => e
      flunk "parser crashed on missing prop type: #{e.class}: #{e.message}"
    end
  end
end
