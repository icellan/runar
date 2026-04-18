# frozen_string_literal: true

require_relative 'test_helper'

class TestParserGo < Minitest::Test
  def parse(source, file_name = 'Test.runar.go')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def test_bigint_big_maps_to_bigint
    # runar.BigintBig is the big.Int-backed alias used by Go-mock helpers for
    # arbitrary-precision arithmetic. Script semantics are identical to
    # runar.Bigint, so the DSL parser must map both to the bigint primitive.
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type BigMath struct {
        runar.SmartContract
        Target runar.BigintBig `runar:"readonly"`
      }

      func (c *BigMath) Check(a runar.Bigint, b runar.BigintBig) {
        runar.Assert(a + b == c.Target)
      }
    GO

    result = parse(source, 'BigMath.runar.go')
    assert_empty result.errors.map(&:format_message), "should parse without errors"
    refute_nil result.contract

    target = result.contract.properties.find { |p| p.name == 'target' }
    refute_nil target, "expected 'target' property"
    assert_instance_of RunarCompiler::Frontend::PrimitiveType, target.type
    assert_equal 'bigint', target.type.name

    method = result.contract.methods.first
    param_b = method.params[1]
    assert_instance_of RunarCompiler::Frontend::PrimitiveType, param_b.type
    assert_equal 'bigint', param_b.type.name
  end

  def test_bytestring_literal_hex_encodes_raw_bytes
    # runar.ByteString("\x00\x6a") emits a ByteStringLiteral whose value is the
    # hex encoding of the two raw literal bytes.
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type LitDemo struct {
        runar.SmartContract
        Expected runar.ByteString `runar:"readonly"`
      }

      func (c *LitDemo) Check() {
        runar.Assert(runar.ByteString("\\x00\\x6a") == c.Expected)
      }
    GO

    result = parse(source, 'LitDemo.runar.go')
    assert_empty result.errors.map(&:format_message), "should parse without errors"
    refute_nil result.contract
    method = result.contract.methods.first

    lit = find_bytestring_literal(method.body)
    refute_nil lit, "expected a ByteStringLiteral in method body"
    assert_equal '006a', lit.value
  end

  def test_bytestring_of_variable_unwraps
    # runar.ByteString(variable) is a no-op type conversion; the inner
    # identifier must flow through unchanged.
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type VarDemo struct {
        runar.SmartContract
        Expected runar.ByteString `runar:"readonly"`
      }

      func (c *VarDemo) Check(data runar.ByteString) {
        runar.Assert(runar.ByteString(data) == c.Expected)
      }
    GO

    result = parse(source, 'VarDemo.runar.go')
    assert_empty result.errors.map(&:format_message), "should parse without errors"
    refute_nil result.contract

    assert contains_plain_data_ident?(result.contract.methods.first.body),
           "runar.ByteString(data) should unwrap to identifier 'data'"
  end

  private

  def find_bytestring_literal(stmts)
    stmts.each do |s|
      next unless s.is_a?(RunarCompiler::Frontend::ExpressionStmt)

      hit = walk_for_bs_lit(s.expr)
      return hit unless hit.nil?
    end
    nil
  end

  def walk_for_bs_lit(expr)
    case expr
    when RunarCompiler::Frontend::ByteStringLiteral then expr
    when RunarCompiler::Frontend::CallExpr
      expr.args.each do |a|
        hit = walk_for_bs_lit(a)
        return hit unless hit.nil?
      end
      nil
    when RunarCompiler::Frontend::BinaryExpr
      walk_for_bs_lit(expr.left) || walk_for_bs_lit(expr.right)
    end
  end

  def contains_plain_data_ident?(stmts)
    stmts.any? do |s|
      next false unless s.is_a?(RunarCompiler::Frontend::ExpressionStmt)
      walk_for_data_ident(s.expr)
    end
  end

  def walk_for_data_ident(expr)
    case expr
    when RunarCompiler::Frontend::Identifier
      expr.name == 'data'
    when RunarCompiler::Frontend::BinaryExpr
      walk_for_data_ident(expr.left) || walk_for_data_ident(expr.right)
    when RunarCompiler::Frontend::CallExpr
      # Must NOT be a lingering byteString(data) call masquerading as unwrap.
      if expr.callee.is_a?(RunarCompiler::Frontend::Identifier) && expr.callee.name == 'byteString'
        return false
      end
      expr.args.any? { |a| walk_for_data_ident(a) } || walk_for_data_ident(expr.callee)
    else
      false
    end
  end
end
