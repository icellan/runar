# frozen_string_literal: true

require_relative 'test_helper'

# Edge-case coverage for the .runar.sol (Solidity-like) surface parser.

class TestParserSolEdges < Minitest::Test
  require 'runar_compiler/frontend/parser_sol'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.sol')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def test_immutable_keyword_flags_readonly
    source = <<~SOL
      pragma runar ^1.0.0;
      import "runar-lang";

      contract Demo is SmartContract {
          Addr immutable owner;

          constructor(Addr _owner) {
              owner = _owner;
          }

          function check() public {
              require(true);
          }
      }
    SOL

    result = parse(source, 'Demo.runar.sol')
    assert_empty result.errors.map(&:format_message)
    owner = result.contract.properties.find { |p| p.name == 'owner' }
    refute_nil owner
    assert owner.readonly, 'immutable Solidity field must be readonly in AST'
  end

  def test_stateful_no_immutable_is_mutable
    source = <<~SOL
      pragma runar ^1.0.0;
      import "runar-lang";

      contract Counter is StatefulSmartContract {
          int count;

          constructor(int _count) {
              count = _count;
          }

          function bump() public {
              count = count + 1;
          }
      }
    SOL

    result = parse(source, 'Counter.runar.sol')
    assert_empty result.errors.map(&:format_message)
    count = result.contract.properties.find { |p| p.name == 'count' }
    refute_nil count
    refute count.readonly, 'non-immutable stateful prop must NOT be readonly'
  end

  def test_multiple_methods
    source = <<~SOL
      pragma runar ^1.0.0;
      import "runar-lang";

      contract Multi is SmartContract {
          int immutable x;

          constructor(int _x) {
              x = _x;
          }

          function one() public { require(x > 0); }
          function two() public { require(x > 1); }
          function three() public { require(x > 2); }
      }
    SOL

    result = parse(source, 'Multi.runar.sol')
    assert_empty result.errors.map(&:format_message)
    names = result.contract.methods.map(&:name)
    assert_equal %w[one two three], names
  end

  def test_bool_type_parses
    source = <<~SOL
      pragma runar ^1.0.0;
      import "runar-lang";

      contract B is SmartContract {
          bool immutable flag;

          constructor(bool _flag) {
              flag = _flag;
          }

          function check() public {
              require(flag);
          }
      }
    SOL

    result = parse(source, 'B.runar.sol')
    assert_empty result.errors.map(&:format_message)
    flag = result.contract.properties.find { |p| p.name == 'flag' }
    refute_nil flag
    assert_equal 'boolean', flag.type.name
  end

  def test_bytes_type_parses
    source = <<~SOL
      pragma runar ^1.0.0;
      import "runar-lang";

      contract Bytes is SmartContract {
          ByteString immutable data;

          constructor(ByteString _data) {
              data = _data;
          }

          function check() public {
              require(data == data);
          }
      }
    SOL

    result = parse(source, 'Bytes.runar.sol')
    assert_empty result.errors.map(&:format_message)
    data = result.contract.properties.find { |p| p.name == 'data' }
    refute_nil data
  end

  def test_garbage_input_does_not_crash
    begin
      parse('@@@ not solidity !!!', 'garbage.runar.sol')
    rescue StandardError => e
      flunk "parser crashed: #{e.class}: #{e.message}"
    end
  end

  def test_arithmetic_in_method_body
    source = <<~SOL
      pragma runar ^1.0.0;
      import "runar-lang";

      contract Arith is SmartContract {
          int immutable target;

          constructor(int _target) {
              target = _target;
          }

          function verify(int a, int b) public {
              require((a + b) * 2 == target);
          }
      }
    SOL

    result = parse(source, 'Arith.runar.sol')
    assert_empty result.errors.map(&:format_message)
  end

  def test_methods_with_distinct_param_counts
    source = <<~SOL
      pragma runar ^1.0.0;
      import "runar-lang";

      contract M is SmartContract {
          int immutable x;

          constructor(int _x) {
              x = _x;
          }

          function nilary() public { require(x > 0); }
          function unary(int a) public { require(a == x); }
          function binary(int a, int b) public { require(a + b == x); }
      }
    SOL

    result = parse(source, 'M.runar.sol')
    assert_empty result.errors.map(&:format_message)
    by_name = result.contract.methods.each_with_object({}) { |m, h| h[m.name] = m }
    assert_equal 0, by_name['nilary'].params.length
    assert_equal 1, by_name['unary'].params.length
    assert_equal 2, by_name['binary'].params.length
  end
end
