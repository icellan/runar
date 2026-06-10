# frozen_string_literal: true

require_relative 'test_helper'

# Edge-case coverage for the .runar.py (Python) surface parser, executed from
# the Ruby compiler tier. Each of the 7 compilers ships its own Python parser
# and must agree with the others; this file widens Ruby's local coverage of
# the Python-specific surface features: `//` integer division, `and`/`or`/
# `not` boolean keywords, `assert_` vs bare `assert`, `Readonly[T]` for
# read-only stateful props, decorators (@public / @private), and snake_case
# → camelCase mapping.

class TestParserPyEdges < Minitest::Test
  require 'runar_compiler/frontend/parser_python'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.py')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  # ---------------------------------------------------------------------------
  # Integer division: `//` must be accepted (and distinct from `/`)
  # ---------------------------------------------------------------------------

  def test_integer_division_operator
    source = <<~PY
      from runar import SmartContract, assert_

      class Div(SmartContract):
          target: int

          def __init__(self, target: int):
              super().__init__(target)
              self.target = target

          @public
          def verify(self, a: int, b: int):
              assert_(a // b == self.target)
    PY

    result = parse(source, 'Div.runar.py')
    assert_empty result.errors.map(&:format_message),
                 "expected `//` to parse cleanly, got: #{result.error_strings}"
    refute_nil result.contract
  end

  # ---------------------------------------------------------------------------
  # Boolean keywords: and / or / not
  # ---------------------------------------------------------------------------

  def test_boolean_keyword_and
    source = <<~PY
      from runar import SmartContract, assert_

      class A(SmartContract):
          x: int

          def __init__(self, x: int):
              super().__init__(x)
              self.x = x

          @public
          def check(self, a: bool, b: bool):
              assert_(a and b)
    PY

    result = parse(source, 'A.runar.py')
    assert_empty result.errors.map(&:format_message)
  end

  def test_boolean_keyword_or
    source = <<~PY
      from runar import SmartContract, assert_

      class O(SmartContract):
          x: int

          def __init__(self, x: int):
              super().__init__(x)
              self.x = x

          @public
          def check(self, a: bool, b: bool):
              assert_(a or b)
    PY

    result = parse(source, 'O.runar.py')
    assert_empty result.errors.map(&:format_message)
  end

  def test_boolean_keyword_not
    source = <<~PY
      from runar import SmartContract, assert_

      class N(SmartContract):
          x: int

          def __init__(self, x: int):
              super().__init__(x)
              self.x = x

          @public
          def check(self, a: bool):
              assert_(not a or self.x > 0)
    PY

    result = parse(source, 'N.runar.py')
    assert_empty result.errors.map(&:format_message)
  end

  # ---------------------------------------------------------------------------
  # Bare `assert` statement form is accepted
  # ---------------------------------------------------------------------------

  def test_bare_assert_keyword_form
    source = <<~PY
      from runar import SmartContract

      class Bare(SmartContract):
          x: int

          def __init__(self, x: int):
              super().__init__(x)
              self.x = x

          @public
          def check(self, a: int):
              assert a == self.x
    PY

    result = parse(source, 'Bare.runar.py')
    assert_empty result.errors.map(&:format_message),
                 "expected bare `assert` to parse, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # `Readonly[T]` annotation for stateful read-only props
  # ---------------------------------------------------------------------------

  def test_readonly_annotation_on_stateful
    source = <<~PY
      from runar import StatefulSmartContract
      from typing import Readonly

      class RO(StatefulSmartContract):
          count: int
          owner: Readonly[int]

          def __init__(self, count: int, owner: int):
              super().__init__(count, owner)
              self.count = count
              self.owner = owner

          @public
          def bump(self):
              self.count = self.count + 1
    PY

    result = parse(source, 'RO.runar.py')
    assert_empty result.errors.map(&:format_message), result.error_strings.join('; ')
    owner = result.contract.properties.find { |p| p.name == 'owner' }
    refute_nil owner
    assert owner.readonly, 'Readonly[int] property must be flagged readonly'

    count = result.contract.properties.find { |p| p.name == 'count' }
    refute count.readonly, 'plain int property on stateful must not be readonly'
  end

  # ---------------------------------------------------------------------------
  # Snake_case method name conversion
  # ---------------------------------------------------------------------------

  def test_snake_case_method_to_camel
    source = <<~PY
      from runar import SmartContract, assert_

      class M(SmartContract):
          target: int

          def __init__(self, target: int):
              super().__init__(target)
              self.target = target

          @public
          def do_check_thing(self, a: int):
              assert_(a == self.target)
    PY

    result = parse(source, 'M.runar.py')
    assert_empty result.errors.map(&:format_message)
    method = result.contract.methods.find { |m| m.name == 'doCheckThing' }
    refute_nil method, 'expected do_check_thing → doCheckThing'
  end

  # ---------------------------------------------------------------------------
  # Multiple decorators / private helpers (no @public marker)
  # ---------------------------------------------------------------------------

  def test_private_helper_method
    source = <<~PY
      from runar import SmartContract, assert_

      class WithPriv(SmartContract):
          x: int

          def __init__(self, x: int):
              super().__init__(x)
              self.x = x

          def _helper(self) -> int:
              return self.x + 1

          @public
          def check(self):
              assert_(self._helper() > 0)
    PY

    result = parse(source, 'WithPriv.runar.py')
    assert_empty result.errors.map(&:format_message)
    helper = result.contract.methods.find { |m| m.name == '_helper' || m.name == 'helper' }
    refute_nil helper, 'expected helper to be parsed'
  end

  # ---------------------------------------------------------------------------
  # Multiple properties preserve declaration order
  # ---------------------------------------------------------------------------

  def test_multiple_properties_preserve_order
    source = <<~PY
      from runar import SmartContract, assert_

      class Three(SmartContract):
          a: int
          b: bool
          c: int

          def __init__(self, a: int, b: bool, c: int):
              super().__init__(a, b, c)
              self.a = a
              self.b = b
              self.c = c

          @public
          def check(self):
              assert_(self.a > 0)
    PY

    result = parse(source, 'Three.runar.py')
    assert_empty result.errors.map(&:format_message)
    assert_equal %w[a b c], result.contract.properties.map(&:name)
  end

  # ---------------------------------------------------------------------------
  # `self` MUST be filtered out of every method's param list
  # ---------------------------------------------------------------------------

  def test_self_filtered_from_methods
    source = <<~PY
      from runar import SmartContract, assert_

      class S(SmartContract):
          x: int

          def __init__(self, x: int):
              super().__init__(x)
              self.x = x

          @public
          def m1(self, a: int):
              assert_(a == self.x)

          @public
          def m2(self, a: int, b: int):
              assert_(a + b == self.x)
    PY

    result = parse(source, 'S.runar.py')
    assert_empty result.errors.map(&:format_message)
    result.contract.methods.each do |m|
      assert(m.params.none? { |p| p.name == 'self' },
             "method #{m.name} still has 'self' in params")
    end
  end

  # ---------------------------------------------------------------------------
  # snake_case constructor param names get camel-cased on properties
  # ---------------------------------------------------------------------------

  def test_snake_case_property_names_camel_cased
    source = <<~PY
      from runar import SmartContract, assert_

      class P(SmartContract):
          pub_key_hash: int
          spending_limit: int

          def __init__(self, pub_key_hash: int, spending_limit: int):
              super().__init__(pub_key_hash, spending_limit)
              self.pub_key_hash = pub_key_hash
              self.spending_limit = spending_limit

          @public
          def check(self):
              assert_(self.pub_key_hash > 0)
              assert_(self.spending_limit > 0)
    PY

    result = parse(source, 'P.runar.py')
    assert_empty result.errors.map(&:format_message)
    names = result.contract.properties.map(&:name).sort
    assert_equal %w[pubKeyHash spendingLimit], names
  end

  # ---------------------------------------------------------------------------
  # Garbage / malformed input does not crash
  # ---------------------------------------------------------------------------

  def test_garbage_input_does_not_crash
    begin
      result = parse('@@@ not python at all !!!', 'garbage.runar.py')
      assert(result.contract.nil? || !result.errors.empty?,
             'expected diagnostics for garbage input')
    rescue StandardError => e
      flunk "parser crashed on garbage input: #{e.class}: #{e.message}"
    end
  end

  def test_missing_colon_after_class_header
    source = <<~PY
      from runar import SmartContract

      class Bad(SmartContract)
          x: int
    PY

    begin
      result = parse(source, 'bad.runar.py')
      bad = result.contract.nil? || !result.errors.empty?
      assert bad, 'expected diagnostics for missing colon'
    rescue StandardError => e
      flunk "parser crashed on missing colon: #{e.class}: #{e.message}"
    end
  end

  # ---------------------------------------------------------------------------
  # Stateful + addOutput intrinsic
  # ---------------------------------------------------------------------------

  def test_stateful_with_add_output
    source = <<~PY
      from runar import StatefulSmartContract

      class C(StatefulSmartContract):
          count: int

          def __init__(self, count: int):
              super().__init__(count)
              self.count = count

          @public
          def bump(self):
              self.count = self.count + 1
              self.add_output(1000, self.count)
    PY

    result = parse(source, 'C.runar.py')
    assert_empty result.errors.map(&:format_message),
                 "expected add_output to parse cleanly, got: #{result.error_strings}"
  end
end
