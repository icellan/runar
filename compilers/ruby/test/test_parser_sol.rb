# frozen_string_literal: true

require_relative 'test_helper'

# Tests for the .runar.sol (Solidity-like) parser. Mirrors the Go suite at
# compilers/go/frontend/parser_sol_test.go so all 7 compilers exercise the
# same surface shape on the same inputs.

class TestParserSol < Minitest::Test
  require 'runar_compiler/frontend/parser_sol'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.sol')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  # ---------------------------------------------------------------------------
  # Basic Solidity-like P2PKH
  # ---------------------------------------------------------------------------

  def test_parses_p2pkh_contract
    source = <<~SOL
      // SPDX-License-Identifier: MIT
      pragma runar ^1.0.0;

      import "runar-lang";

      contract P2PKH is SmartContract {
          Addr immutable pubKeyHash;

          constructor(Addr _pubKeyHash) {
              pubKeyHash = _pubKeyHash;
          }

          function unlock(Sig sig, PubKey pubKey) public {
              require(hash160(pubKey) == pubKeyHash);
              require(checkSig(sig, pubKey));
          }
      }
    SOL

    result = parse(source, 'P2PKH.runar.sol')
    assert_empty result.errors.map(&:format_message),
                 'P2PKH should parse without errors'
    refute_nil result.contract

    c = result.contract
    assert_equal 'P2PKH', c.name
    assert_equal 'SmartContract', c.parent_class
    assert_equal 1, c.properties.length
    assert_equal 'pubKeyHash', c.properties.first.name
  end

  # ---------------------------------------------------------------------------
  # Methods + params
  # ---------------------------------------------------------------------------

  def test_methods_and_params
    source = <<~SOL
      pragma runar ^1.0.0;
      import "runar-lang";

      contract Adder is SmartContract {
          int immutable target;

          constructor(int _target) {
              target = _target;
          }

          function verify(int a, int b) public {
              require(a + b == target);
          }
      }
    SOL

    result = parse(source, 'Adder.runar.sol')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 1, c.methods.length
    method = c.methods.first
    assert_equal 'verify', method.name
    assert_equal 'public', method.visibility
    assert_equal 2, method.params.length
  end

  # ---------------------------------------------------------------------------
  # Stateful contract
  # ---------------------------------------------------------------------------

  def test_stateful_contract
    source = <<~SOL
      pragma runar ^1.0.0;
      import "runar-lang";

      contract Counter is StatefulSmartContract {
          int count;

          constructor(int _count) {
              count = _count;
          }

          function increment() public {
              count = count + 1;
          }
      }
    SOL

    result = parse(source, 'Counter.runar.sol')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 'Counter', c.name
    assert_equal 'StatefulSmartContract', c.parent_class
  end

  # ---------------------------------------------------------------------------
  # Invalid syntax produces errors (or a nil contract)
  # ---------------------------------------------------------------------------

  def test_invalid_syntax_errors
    source = <<~SOL
      contract {
          // missing name and parent
      }
    SOL

    result = parse(source, 'bad.runar.sol')
    invalid = result.contract.nil? || !result.errors.empty?
    assert invalid, 'expected errors for invalid Solidity-like syntax'
  end

  # ---------------------------------------------------------------------------
  # Multiple properties preserve declaration order
  # ---------------------------------------------------------------------------

  def test_multiple_properties_preserve_order
    source = <<~SOL
      pragma runar ^1.0.0;
      import "runar-lang";

      contract TwoProps is SmartContract {
          Addr immutable addr;
          PubKey immutable key;

          constructor(Addr _addr, PubKey _key) {
              addr = _addr;
              key = _key;
          }

          function check(int x) public {
              require(x == 1);
          }
      }
    SOL

    result = parse(source, 'TwoProps.runar.sol')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 2, c.properties.length
    assert_equal 'addr', c.properties[0].name
    assert_equal 'key',  c.properties[1].name
  end
end
