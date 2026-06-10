# frozen_string_literal: true

require_relative 'test_helper'

# Edge-case coverage for the .runar.go (Go DSL) surface parser. Mirrors
# compilers/go/frontend/parser_go_test.go.

class TestParserGoEdges < Minitest::Test
  require 'runar_compiler/frontend/parser_go'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.go')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  # ---------------------------------------------------------------------------
  # Basic stateless P2PKH-style contract via struct embedding
  # ---------------------------------------------------------------------------

  def test_parses_basic_p2pkh
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type P2PKH struct {
        runar.SmartContract
        PubKeyHash runar.Addr `runar:"readonly"`
      }

      func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
        runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
        runar.Assert(runar.CheckSig(sig, pubKey))
      }
    GO

    result = parse(source, 'P2PKH.runar.go')
    assert_empty result.errors.map(&:format_message), result.error_strings.join('; ')
    refute_nil result.contract
    assert_equal 'P2PKH', result.contract.name
    assert_equal 'SmartContract', result.contract.parent_class
    prop = result.contract.properties.find { |p| p.name == 'pubKeyHash' }
    refute_nil prop, 'expected pubKeyHash property'
    assert prop.readonly, 'readonly tag must flag the property'
  end

  # ---------------------------------------------------------------------------
  # Stateful contract: omitting `runar:"readonly"` leaves field mutable
  # ---------------------------------------------------------------------------

  def test_stateful_mutable_field
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type Counter struct {
        runar.StatefulSmartContract
        Count runar.Bigint
      }

      func (c *Counter) Bump() {
        c.Count = c.Count + runar.Bigint(1)
      }
    GO

    result = parse(source, 'Counter.runar.go')
    assert_empty result.errors.map(&:format_message)
    assert_equal 'StatefulSmartContract', result.contract.parent_class

    count = result.contract.properties.find { |p| p.name == 'count' }
    refute_nil count
    refute count.readonly, 'unmarked field on Stateful must NOT be readonly'
  end

  # ---------------------------------------------------------------------------
  # Multiple properties preserve declaration order
  # ---------------------------------------------------------------------------

  def test_multiple_properties_preserve_order
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type Three struct {
        runar.SmartContract
        Alpha runar.Bigint  `runar:"readonly"`
        Beta  runar.Bool    `runar:"readonly"`
        Gamma runar.Addr    `runar:"readonly"`
      }

      func (c *Three) Check() {
        runar.Assert(c.Alpha > runar.Bigint(0))
      }
    GO

    result = parse(source, 'Three.runar.go')
    assert_empty result.errors.map(&:format_message)
    names = result.contract.properties.map(&:name)
    assert_equal %w[alpha beta gamma], names
  end

  # ---------------------------------------------------------------------------
  # Multiple methods preserve declaration order
  # ---------------------------------------------------------------------------

  def test_multiple_methods_preserve_order
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type Multi struct {
        runar.SmartContract
        X runar.Bigint `runar:"readonly"`
      }

      func (c *Multi) One() {
        runar.Assert(c.X > runar.Bigint(0))
      }

      func (c *Multi) Two() {
        runar.Assert(c.X > runar.Bigint(1))
      }

      func (c *Multi) Three() {
        runar.Assert(c.X > runar.Bigint(2))
      }
    GO

    result = parse(source, 'Multi.runar.go')
    assert_empty result.errors.map(&:format_message)
    names = result.contract.methods.map(&:name)
    assert_equal %w[one two three], names
  end

  # ---------------------------------------------------------------------------
  # Pascal-case method on Go side becomes camelCase in AST
  # ---------------------------------------------------------------------------

  def test_pascal_method_to_camel
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type Hash struct {
        runar.SmartContract
        Target runar.Bigint `runar:"readonly"`
      }

      func (c *Hash) DoCheck(a runar.Bigint) {
        runar.Assert(a == c.Target)
      }
    GO

    result = parse(source, 'Hash.runar.go')
    assert_empty result.errors.map(&:format_message)
    method = result.contract.methods.first
    assert_equal 'doCheck', method.name
  end

  # ---------------------------------------------------------------------------
  # Boolean type alias
  # ---------------------------------------------------------------------------

  def test_bool_type_alias
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type B struct {
        runar.SmartContract
        Flag runar.Bool `runar:"readonly"`
      }

      func (c *B) Check() {
        runar.Assert(c.Flag)
      }
    GO

    result = parse(source, 'B.runar.go')
    assert_empty result.errors.map(&:format_message)
    flag = result.contract.properties.find { |p| p.name == 'flag' }
    refute_nil flag
    assert_instance_of RunarCompiler::Frontend::PrimitiveType, flag.type
    assert_equal 'boolean', flag.type.name
  end

  # ---------------------------------------------------------------------------
  # Garbage source does not crash the parser
  # ---------------------------------------------------------------------------

  def test_garbage_input_does_not_crash
    # The parser may recover (skip non-struct content) or report errors.
    # Either is acceptable; the contract just must not crash.
    begin
      parse('@@@ not go !!!', 'garbage.runar.go')
    rescue StandardError => e
      flunk "parser crashed on garbage input: #{e.class}: #{e.message}"
    end
  end

  def test_missing_package_declaration_does_not_crash
    source = <<~GO
      // No package declaration at all
      import "github.com/icellan/runar/packages/runar-go"

      type Bad struct {
        runar.SmartContract
      }
    GO

    begin
      parse(source, 'bad.runar.go')
    rescue StandardError => e
      flunk "parser crashed: #{e.class}: #{e.message}"
    end
  end
end
