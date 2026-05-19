# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/parser_go"

# R-2 / R-4 typecheck bounds checks for the BSVM intent sub-covenant
# intrinsics in the Ruby compiler tier. Direct port of the four
# bounds-check cases in compilers/go/frontend/intent_intrinsics_test.go.
class TestIntentIntrinsicsBounds < Minitest::Test
  # Parse a Go-DSL source, run typecheck, and assert that one of the emitted
  # error messages contains substr.
  def expect_typecheck_error(source, substr)
    parse_result = RunarCompiler::Frontend.parse_go(source, "Test.runar.go")
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract

    tc_result = RunarCompiler::Frontend.type_check(parse_result.contract)
    msgs = tc_result.errors.map(&:format_message)
    assert msgs.any? { |m| m.include?(substr) },
           "expected typecheck error containing #{substr.inspect}, got: #{msgs.inspect}"
  end

  # R-2: requireOutputP2PKH outputIndex bounded to <= 1000.
  def test_require_output_p2pkh_output_index_above_bound_rejects
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tPKH runar.ByteString `runar:"readonly"`
      \tA   runar.Bigint     `runar:"readonly"`
      }

      func (c *Cov) Pay() {
      \t// 2000 > 1000 bound -- should be rejected at typecheck.
      \trunar.RequireOutputP2PKH(2000, c.PKH, c.A)
      }
    GO
    expect_typecheck_error(source, "bound to <= 1000")
  end

  # R-2: requireOutputP2PKH negative outputIndex rejected.
  def test_require_output_p2pkh_negative_index_rejects
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tPKH runar.ByteString `runar:"readonly"`
      \tA   runar.Bigint     `runar:"readonly"`
      }

      func (c *Cov) Pay() {
      \trunar.RequireOutputP2PKH(-1, c.PKH, c.A)
      }
    GO
    expect_typecheck_error(source, "must be >= 0")
  end

  # R-4: extractPrevOutputScript prefixLen must be >= 32.
  def test_extract_prev_output_script_prefix_len_too_small_rejects
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tH runar.ByteString `runar:"readonly"`
      }

      func (c *Cov) Bind() {
      \t// prefixLen=16 < 32 (hash size) -- should be rejected.
      \t_ = runar.ExtractPrevOutputScript(0, c.H, 16)
      }
    GO
    expect_typecheck_error(source, "must be >= 32")
  end

  # R-4: extractPrevOutputScript prefixLen must be <= MAX_SCRIPT_BYTES (4 MiB).
  def test_extract_prev_output_script_prefix_len_too_large_rejects
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tH runar.ByteString `runar:"readonly"`
      }

      func (c *Cov) Bind() {
      \t// prefixLen=10485760 > 4 MiB -- should be rejected.
      \t_ = runar.ExtractPrevOutputScript(0, c.H, 10485760)
      }
    GO
    expect_typecheck_error(source, "MAX_SCRIPT_BYTES")
  end
end
