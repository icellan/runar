# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/anf_lower"
require "runar_compiler/frontend/parser_go"

# N-060 -- a `-0` index evades the literal gate and silently DELETES the
# covenant.
#
# The typecheck index gate accepts `UnaryExpr("-", BigIntLiteral)` only so that
# a negative index reports "must be >= 0" instead of the misleading "must be an
# integer literal". `-0` negates to `0`, so it passes that bound check -- but
# ANF lowering matches on a BARE BigIntLiteral and, finding a UnaryExpr, falls
# through to `load_const ""`: no witness param, no hash assertion, NO COVENANT,
# and no diagnostic. A contract whose whole purpose is the covenant compiles to
# a script that does not carry it.
#
# Mirrors compilers/rust/tests/intent_intrinsics_bounds.rs (R-068).
class TestIntentIntrinsicsNegZero < Minitest::Test
  EPS_NEG_ZERO_SRC = <<~GO
    package x

    import runar "github.com/icellan/runar/packages/runar-go"

    type Cov struct {
    \trunar.StatefulSmartContract
    \tH     runar.ByteString
    \tCount runar.Bigint
    }

    func (c *Cov) Bind() {
    \ts := runar.ExtractPrevOutputScript(-0, c.H)
    \trunar.Assert(runar.Len(s) > 0)
    \tc.Count = c.Count + 1
    }
  GO

  ROP_NEG_ZERO_SRC = <<~GO
    package x

    import runar "github.com/icellan/runar/packages/runar-go"

    type Cov struct {
    \trunar.StatefulSmartContract
    \tPKH   runar.ByteString
    \tAmt   runar.Bigint
    \tCount runar.Bigint
    }

    func (c *Cov) Pay() {
    \trunar.RequireOutputP2PKH(-0, c.PKH, c.Amt)
    \tc.Count = c.Count + 1
    }
  GO

  def typecheck_messages(source)
    parse_result = RunarCompiler::Frontend.parse_go(source, "Test.runar.go")
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract
    RunarCompiler::Frontend.type_check(parse_result.contract).errors.map(&:format_message)
  end

  def expect_typecheck_error(source, substr)
    msgs = typecheck_messages(source)
    assert msgs.any? { |m| m.include?(substr) },
           "expected typecheck error containing #{substr.inspect}, got: #{msgs.inspect}"
  end

  # Lower to ANF and return every method's param names, or nil when typecheck
  # rejected the source.
  def lowered_param_names(source)
    parse_result = RunarCompiler::Frontend.parse_go(source, "Test.runar.go")
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    return nil unless RunarCompiler::Frontend.type_check(parse_result.contract).errors.empty?

    prog = RunarCompiler::Frontend.lower_to_anf(parse_result.contract)
    prog.methods.flat_map { |m| m.params.map(&:name) }
  end

  def test_extract_prev_output_script_negative_zero_index_rejects
    expect_typecheck_error(EPS_NEG_ZERO_SRC, "must be an integer literal")
  end

  def test_require_output_p2pkh_negative_zero_index_rejects
    expect_typecheck_error(ROP_NEG_ZERO_SRC, "must be an integer literal")
  end

  # The funds-safety half of the pair: a `-0` index must never reach codegen,
  # because when it does the intrinsic lowers to a bare empty-string constant
  # and the covenant it was supposed to install is simply absent.
  def test_negative_zero_index_never_silently_drops_the_covenant
    [["extractPrevOutputScript", EPS_NEG_ZERO_SRC],
     ["requireOutputP2PKH", ROP_NEG_ZERO_SRC]].each do |label, src|
      names = lowered_param_names(src)
      next if names.nil?

      flunk "#{label}(-0, ...) compiled with NO diagnostic; covenant params present: " \
            "#{names.select { |n| n.start_with?('_prevOutScript_') || n == '_serialisedOutputs' }.inspect}"
    end
  end

  # Controls -- the valid forms must keep lowering exactly as before.

  def test_control_literal_zero_index_still_installs_the_covenant
    eps = EPS_NEG_ZERO_SRC.sub("ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(0,")
    names = lowered_param_names(eps)
    refute_nil names, "valid eps contract must lower"
    assert_includes names, "_prevOutScript_0",
                    "extractPrevOutputScript(0, ...) must still auto-inject its witness param"

    rop = ROP_NEG_ZERO_SRC.sub("RequireOutputP2PKH(-0,", "RequireOutputP2PKH(1,")
    names = lowered_param_names(rop)
    refute_nil names, "valid rop contract must lower"
    assert_includes names, "_serialisedOutputs",
                    "requireOutputP2PKH(1, ...) must still auto-inject _serialisedOutputs"
  end

  def test_control_plain_negative_index_still_reports_the_bound_message
    src = EPS_NEG_ZERO_SRC.sub("ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(-3,")
    expect_typecheck_error(src, "must be >= 0")
  end
end
