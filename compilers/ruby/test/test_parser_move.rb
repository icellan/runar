# frozen_string_literal: true

require_relative 'test_helper'

# Tests for the .runar.move (Move-style) parser. Mirrors the Go suite at
# compilers/go/frontend/parser_move_test.go so all 7 compilers exercise the
# same surface shape on the same inputs.

class TestParserMove < Minitest::Test
  require 'runar_compiler/frontend/parser_move'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.move')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  # ---------------------------------------------------------------------------
  # Basic Move-style P2PKH
  # ---------------------------------------------------------------------------

  def test_parses_p2pkh_contract
    source = <<~MOVE
      module P2PKH {
          use runar::SmartContract;
          use runar::hash160;
          use runar::checkSig;

          struct P2PKH has SmartContract {
              pub_key_hash: Addr,
          }

          public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
              assert!(hash160(pub_key) == contract.pub_key_hash);
              assert!(checkSig(sig, pub_key));
          }
      }
    MOVE

    result = parse(source, 'P2PKH.runar.move')
    assert_empty result.errors.map(&:format_message),
                 'P2PKH should parse without errors'
    refute_nil result.contract

    c = result.contract
    assert_equal 'P2PKH', c.name
    assert_equal 'SmartContract', c.parent_class
  end

  # ---------------------------------------------------------------------------
  # Properties + methods
  # ---------------------------------------------------------------------------

  def test_properties_and_methods
    source = <<~MOVE
      module Adder {
          use runar::SmartContract;

          struct Adder has SmartContract {
              target: bigint,
          }

          public fun verify(contract: &Adder, a: bigint, b: bigint) {
              assert!(a + b == contract.target);
          }
      }
    MOVE

    result = parse(source, 'Adder.runar.move')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    refute_empty c.properties
    assert_equal 'target', c.properties[0].name
    refute_empty c.methods
    assert_equal 'verify', c.methods[0].name
  end

  # ---------------------------------------------------------------------------
  # Stateful resource struct
  # ---------------------------------------------------------------------------

  def test_stateful_contract
    source = <<~MOVE
      module Counter {
          use runar::StatefulSmartContract;

          resource struct Counter {
              count: &mut Int,
          }

          public fun increment(contract: &mut Counter) {
              contract.count = contract.count + 1;
          }
      }
    MOVE

    result = parse(source, 'Counter.runar.move')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 'StatefulSmartContract', c.parent_class
  end

  # ---------------------------------------------------------------------------
  # Invalid syntax → errors or nil contract
  # ---------------------------------------------------------------------------

  def test_invalid_syntax_errors
    source = <<~MOVE
      module {
          // missing name
      }
    MOVE

    result = parse(source, 'bad.runar.move')
    invalid = result.contract.nil? || !result.errors.empty?
    assert invalid, 'expected errors for invalid Move-style syntax'
  end

  # ---------------------------------------------------------------------------
  # Multiple public functions
  # ---------------------------------------------------------------------------

  def test_multiple_methods
    source = <<~MOVE
      module Multi {
          use runar::SmartContract;

          struct Multi has SmartContract {
              x: bigint,
          }

          public fun method1(contract: &Multi, a: bigint) {
              assert!(a == contract.x);
          }

          public fun method2(contract: &Multi, b: bigint) {
              assert!(b == contract.x);
          }
      }
    MOVE

    result = parse(source, 'Multi.runar.move')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 2, c.methods.length
  end
end
