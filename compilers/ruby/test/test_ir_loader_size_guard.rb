# frozen_string_literal: true

# BUG-008 follow-up: IR-loader size-guard regression tests.

require_relative "test_helper"
require "runar_compiler/ir/input_limits"
require "runar_compiler/ir/loader"

class TestIRLoaderSizeGuard < Minitest::Test
  MAX_BYTES = RunarCompiler::IR::InputLimits::MAX_IR_BYTES
  MAX_DEPTH = RunarCompiler::IR::InputLimits::MAX_IR_NESTING
  SIZE_ERR = RunarCompiler::IR::InputLimits::IRSizeExceededError
  NEST_ERR = RunarCompiler::IR::InputLimits::IRNestingExceededError

  def test_load_ir_rejects_oversized_input
    oversized = " " * (MAX_BYTES + 1)
    err = assert_raises(SIZE_ERR) do
      RunarCompiler::IR.load_ir(oversized)
    end
    assert_equal MAX_BYTES, err.limit
    assert_equal MAX_BYTES + 1, err.actual
  end

  def test_load_ir_rejects_deeply_nested_input
    depth = MAX_DEPTH + 50
    body = "1"
    depth.times { body = '{"n":' + body + "}" }
    err = assert_raises(NEST_ERR) do
      RunarCompiler::IR.load_ir(body)
    end
    assert_equal MAX_DEPTH, err.limit
  end

  def test_depth_walk_ignores_braces_inside_strings
    open_braces = "{" * 1000
    bad =
      '{"contractName":"X","properties":[],"methods":[],"_note":"' +
      open_braces + '"}'
    # Neither DoS-bound guard should fire. Downstream parse should
    # succeed (X has the required shape).
    program = RunarCompiler::IR.load_ir(bad)
    assert_equal "X", program.contract_name
  end

  def test_load_ir_accepts_minimal_program
    minimal = '{"contractName":"X","properties":[],"methods":[]}'
    program = RunarCompiler::IR.load_ir(minimal)
    assert_equal "X", program.contract_name
  end

  def test_assert_ir_bytes_under_limit_typed_error
    assert_raises(SIZE_ERR) do
      RunarCompiler::IR::InputLimits.assert_ir_bytes_under_limit("x" * (MAX_BYTES + 1))
    end
  end

  def test_assert_ir_nesting_under_limit_typed_error
    body = "1"
    (MAX_DEPTH + 1).times { body = "[" + body + "]" }
    assert_raises(NEST_ERR) do
      RunarCompiler::IR::InputLimits.assert_ir_nesting_under_limit(body)
    end
  end
end
