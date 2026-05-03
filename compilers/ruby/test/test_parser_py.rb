# frozen_string_literal: true

require_relative 'test_helper'

# Tests for the .runar.py parser. Mirrors the Go suite at
# compilers/go/frontend/parser_python_test.go so all 7 compilers exercise the
# same surface shape on the same inputs.

class TestParserPy < Minitest::Test
  require 'runar_compiler/frontend/parser_python'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.py')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  # ---------------------------------------------------------------------------
  # Basic Python P2PKH
  # ---------------------------------------------------------------------------

  def test_parses_p2pkh_contract
    source = <<~PY
      from runar import SmartContract, assert_, hash160, check_sig, Addr, Sig, PubKey

      class P2PKH(SmartContract):
          pub_key_hash: Addr

          def __init__(self, pub_key_hash: Addr):
              super().__init__(pub_key_hash)
              self.pub_key_hash = pub_key_hash

          @public
          def unlock(self, sig: Sig, pub_key: PubKey):
              assert_(hash160(pub_key) == self.pub_key_hash)
              assert_(check_sig(sig, pub_key))
    PY

    result = parse(source, 'P2PKH.runar.py')
    assert_empty result.errors.map(&:format_message),
                 'P2PKH should parse without errors'
    refute_nil result.contract

    c = result.contract
    assert_equal 'P2PKH', c.name
    assert_equal 'SmartContract', c.parent_class
    refute_empty c.properties
    # snake_case pub_key_hash → camelCase pubKeyHash
    assert_equal 'pubKeyHash', c.properties[0].name
  end

  # ---------------------------------------------------------------------------
  # Method params: 'self' must be filtered out
  # ---------------------------------------------------------------------------

  def test_method_params_drop_self
    source = <<~PY
      from runar import SmartContract, assert_

      class Adder(SmartContract):
          target: int

          def __init__(self, target: int):
              super().__init__(target)
              self.target = target

          @public
          def verify(self, a: int, b: int):
              assert_(a + b == self.target)
    PY

    result = parse(source, 'Adder.runar.py')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    refute_empty c.methods
    method = c.methods.first
    assert_equal 'verify', method.name
    assert_equal 'public', method.visibility
    refute(method.params.any? { |p| p.name == 'self' },
           "'self' should not appear as a method param")
  end

  # ---------------------------------------------------------------------------
  # Stateful contract
  # ---------------------------------------------------------------------------

  def test_stateful_contract
    source = <<~PY
      from runar import StatefulSmartContract

      class Counter(StatefulSmartContract):
          count: int

          def __init__(self, count: int):
              super().__init__(count)
              self.count = count

          @public
          def increment(self):
              self.count = self.count + 1
    PY

    result = parse(source, 'Counter.runar.py')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 'Counter', c.name
    assert_equal 'StatefulSmartContract', c.parent_class
  end

  # ---------------------------------------------------------------------------
  # Invalid syntax → errors or nil contract
  # ---------------------------------------------------------------------------

  def test_invalid_syntax_errors
    source = <<~PY
      class (SmartContract):
          pass
    PY

    result = parse(source, 'bad.runar.py')
    invalid = result.contract.nil? || !result.errors.empty?
    assert invalid, 'expected errors for invalid Python syntax'
  end

  # ---------------------------------------------------------------------------
  # snake_case → camelCase property + method conversion
  # ---------------------------------------------------------------------------

  def test_snake_to_camel_conversion
    source = <<~PY
      from runar import SmartContract, assert_, hash160, Addr, PubKey

      class HashCheck(SmartContract):
          pub_key_hash: Addr

          def __init__(self, pub_key_hash: Addr):
              super().__init__(pub_key_hash)
              self.pub_key_hash = pub_key_hash

          @public
          def check_hash(self, pub_key: PubKey):
              assert_(hash160(pub_key) == self.pub_key_hash)
    PY

    result = parse(source, 'HashCheck.runar.py')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    refute_empty c.properties
    assert_equal 'pubKeyHash', c.properties[0].name
    refute_empty c.methods
    assert_equal 'checkHash', c.methods[0].name
  end
end
