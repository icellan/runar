# frozen_string_literal: true

# N-113 — the two shapes the Go tier rejected alone (R-079 / R-081).
#
# Both are `--ir`-only: the source path refuses each shape in
# frontend/validator.rb, and validate_ir is reachable only from the IR loader.
# Go grew these guards first (compilers/go/ir/loader.go) and was deliberately,
# transiently stricter than its six peers until N-113;
# conformance/negatives/ir-rejection-parity.test.ts is the gate that now
# compares the six.

require_relative "test_helper"
require "json"
require "runar_compiler/ir/loader"

class TestN113IRTrustBoundary < Minitest::Test
  # A one-method contract parameterised on the two fields under test, so every
  # case below differs from the VALID control in exactly one way.
  def ir_json(is_public: true, raw_bytes: "51", out_arity: 1)
    JSON.generate(
      "contractName" => "Anyone",
      "properties" => [],
      "methods" => [
        {
          "name" => "unlock",
          "params" => [],
          "isPublic" => is_public,
          "body" => [
            {
              "name" => "t0",
              "value" => {
                "kind" => "raw_script",
                "bytes" => raw_bytes,
                "in_arity" => 0,
                "out_arity" => out_arity
              }
            }
          ]
        }
      ]
    )
  end

  # The control every case below is derived from. A probe whose control also
  # fails proves nothing.
  def test_control_valid_ir_is_accepted
    program = RunarCompiler::IR.load_ir(ir_json)
    assert_equal "Anyone", program.contract_name
  end

  # R-079: lowering pops in_arity and pushes out_arity on the stack model while
  # emission writes nothing for a zero-length span. The span degrades to the
  # identity function and a DIFFERENT WITNESS spends the output. Measured on
  # @bsv/sdk's Spend: `8f01859c` accepts x=5 and rejects x=-5; with the body
  # erased, `01859c` does the opposite.
  def test_rejects_empty_raw_script_body
    err = assert_raises(ArgumentError) do
      RunarCompiler::IR.load_ir(ir_json(raw_bytes: ""))
    end
    assert_includes err.message, "empty bytes body"
  end

  # The degenerate in=0/out=0 case is harmless on its own and is rejected
  # anyway: mirroring the source validator exactly beats a narrower
  # arity-conditional rule that would differ from the rule one pass earlier.
  def test_rejects_empty_raw_script_body_even_at_zero_arity
    assert_raises(ArgumentError) do
      RunarCompiler::IR.load_ir(ir_json(raw_bytes: "", out_arity: 0))
    end
  end

  # R-081: emission succeeds with an EMPTY locking script, which is
  # anyone-can-spend. On @bsv/sdk's Spend under full consensus wrappers,
  # lock="" with unlock=OP_1 (0x51) validates.
  def test_rejects_no_public_methods
    err = assert_raises(ArgumentError) do
      RunarCompiler::IR.load_ir(ir_json(is_public: false))
    end
    assert_includes err.message, "no public methods"
  end

  def test_rejects_empty_method_list
    err = assert_raises(ArgumentError) do
      RunarCompiler::IR.load_ir('{"contractName":"Empty","properties":[],"methods":[]}')
    end
    assert_includes err.message, "no public methods"
  end

  # Ordering matters and is asserted, not assumed: when a binding is ALSO
  # malformed, the malformed binding is the more actionable diagnostic. load_ir
  # raises errors[0], so the entry-point error is APPENDED last. Same ordering
  # as compilers/go/ir/loader.go.
  def test_structural_errors_keep_priority_over_the_entry_point_error
    err = assert_raises(ArgumentError) do
      RunarCompiler::IR.load_ir(ir_json(is_public: false, raw_bytes: "515"))
    end
    assert_includes err.message, "odd hex length"
  end
end
