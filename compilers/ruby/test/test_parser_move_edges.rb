# frozen_string_literal: true

require_relative 'test_helper'

# Edge-case coverage for the .runar.move (Move-style) surface parser.

class TestParserMoveEdges < Minitest::Test
  require 'runar_compiler/frontend/parser_move'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.move')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def test_resource_struct_is_stateful
    source = <<~MOVE
      module Counter {
          use runar::StatefulSmartContract;

          resource struct Counter {
              count: &mut Int,
          }

          public fun bump(contract: &mut Counter) {
              contract.count = contract.count + 1;
          }
      }
    MOVE

    result = parse(source, 'Counter.runar.move')
    assert_empty result.errors.map(&:format_message)
    assert_equal 'StatefulSmartContract', result.contract.parent_class
  end

  def test_plain_struct_is_stateless
    source = <<~MOVE
      module Demo {
          use runar::SmartContract;

          struct Demo has SmartContract {
              x: bigint,
          }

          public fun check(contract: &Demo) {
              assert!(contract.x > 0);
          }
      }
    MOVE

    result = parse(source, 'Demo.runar.move')
    assert_empty result.errors.map(&:format_message)
    assert_equal 'SmartContract', result.contract.parent_class
  end

  def test_multiple_properties_preserve_order
    source = <<~MOVE
      module M {
          use runar::SmartContract;

          struct M has SmartContract {
              alpha: bigint,
              beta: bigint,
              gamma: bigint,
          }

          public fun check(contract: &M) {
              assert!(contract.alpha + contract.beta + contract.gamma > 0);
          }
      }
    MOVE

    result = parse(source, 'M.runar.move')
    assert_empty result.errors.map(&:format_message)
    assert_equal %w[alpha beta gamma], result.contract.properties.map(&:name)
  end

  def test_method_with_multiple_params
    source = <<~MOVE
      module Add {
          use runar::SmartContract;

          struct Add has SmartContract {
              target: bigint,
          }

          public fun verify(contract: &Add, a: bigint, b: bigint, c: bigint) {
              assert!(a + b + c == contract.target);
          }
      }
    MOVE

    result = parse(source, 'Add.runar.move')
    assert_empty result.errors.map(&:format_message)
    m = result.contract.methods.first
    # `contract: &Add` is the self receiver and must be filtered out.
    assert_equal 3, m.params.length
    assert_equal %w[a b c], m.params.map(&:name)
  end

  def test_garbage_input_does_not_crash
    begin
      parse('@@@ not move !!!', 'garbage.runar.move')
    rescue StandardError => e
      flunk "parser crashed: #{e.class}: #{e.message}"
    end
  end

  def test_methods_distinct_param_counts
    source = <<~MOVE
      module Multi {
          use runar::SmartContract;

          struct Multi has SmartContract {
              x: bigint,
          }

          public fun nilary(contract: &Multi) {
              assert!(contract.x > 0);
          }

          public fun unary(contract: &Multi, a: bigint) {
              assert!(a == contract.x);
          }

          public fun binary(contract: &Multi, a: bigint, b: bigint) {
              assert!(a + b == contract.x);
          }
      }
    MOVE

    result = parse(source, 'Multi.runar.move')
    assert_empty result.errors.map(&:format_message)
    by_name = result.contract.methods.each_with_object({}) { |m, h| h[m.name] = m }
    assert_equal 0, by_name['nilary'].params.length
    assert_equal 1, by_name['unary'].params.length
    assert_equal 2, by_name['binary'].params.length
  end
end
