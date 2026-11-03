# frozen_string_literal: true

# F-283 (CL-GAP-164) — the `--ir` loader bounds each loop's iteration count
# individually (MAX_LOOP_COUNT = 10_000) but never the PRODUCT across nested
# loops. Two loop bindings of 10_000 each, one nested inside the other, each
# independently pass the per-binding check even though the real unrolled
# iteration count is 10_000 x 10_000 = 100_000_000 -- a count that, if this
# IR ever reached stack lowering, drives the unroller into multi-GB memory
# growth (measured upstream at 5m07s / 3.7GB RSS and still climbing, on a
# 1,175-byte payload). This test asserts the LOADER refuses it; it must never
# call compile_from_ir / lowering on the hostile payload itself.
#
# What this proves: the loader's structural validation rejects a nested-loop
# IR whose counts each individually satisfy MAX_LOOP_COUNT but whose PRODUCT
# does not, with a diagnostic naming the overflow, before any lowering pass
# sees the program.
#
# What this does NOT prove: that stack lowering or the unroller themselves are
# safe against a hostile product that slips past this guard (e.g. via a
# different node shape) -- only that this specific documented route is closed.
# It also does not prove the other six tiers behave identically; that is
# covered by each tier's own port of this test (ESCALATION RULE).

require_relative "test_helper"
require "json"
require "runar_compiler/ir/loader"

class TestF283IRLoopProductBound < Minitest::Test
  # A minimal single-public-method contract (mirrors the N-113 pattern):
  # no properties, no constructor, one public method ending in assert().
  def ir_json(outer_count:, inner_count:, inner_body: nil)
    inner_body ||= [
      { "name" => "t0", "value" => { "kind" => "load_const", "value" => 1 } }
    ]
    JSON.generate(
      "contractName" => "Anyone",
      "properties" => [],
      "methods" => [
        {
          "name" => "unlock",
          "params" => [],
          "isPublic" => true,
          "body" => [
            {
              "name" => "outer",
              "value" => {
                "kind" => "loop",
                "count" => outer_count,
                "iterVar" => "i",
                "start" => 0,
                "step" => 1,
                "body" => [
                  {
                    "name" => "inner",
                    "value" => {
                      "kind" => "loop",
                      "count" => inner_count,
                      "iterVar" => "j",
                      "start" => 0,
                      "step" => 1,
                      "body" => inner_body
                    }
                  }
                ]
              }
            },
            { "name" => "tTrue", "value" => { "kind" => "load_const", "value" => true } },
            { "name" => "tAssert", "value" => { "kind" => "assert", "value" => "tTrue" } }
          ]
        }
      ]
    )
  end

  # Control: a single, unnested loop at the per-binding ceiling still loads.
  def test_control_single_loop_at_max_is_accepted
    program = RunarCompiler::IR.load_ir(ir_json(outer_count: 1, inner_count: RunarCompiler::IR::MAX_LOOP_COUNT))
    assert_equal "Anyone", program.contract_name
  end

  # The hostile case: 10_000 x 10_000, each individually within
  # MAX_LOOP_COUNT, product 100_000_000 far over it. Must be refused by the
  # loader -- never reach compile_from_ir/lowering.
  def test_rejects_nested_loops_whose_product_exceeds_max
    err = assert_raises(ArgumentError) do
      RunarCompiler::IR.load_ir(ir_json(outer_count: 10_000, inner_count: 10_000))
    end
    assert_includes err.message, "100000000",
                     "expected the diagnostic to name the total iteration count, got: #{err.message}"
    assert_includes err.message, RunarCompiler::IR::MAX_LOOP_COUNT.to_s
  end

  # Smaller counts, neither of which trips the per-binding ceiling alone
  # (101 and 100 are both << 10_000), but whose product (10_100) does. Proves
  # the new rule is the PRODUCT, not a disguised re-check of the single bound.
  def test_rejects_small_counts_whose_product_exceeds_max
    err = assert_raises(ArgumentError) do
      RunarCompiler::IR.load_ir(ir_json(outer_count: 101, inner_count: 100))
    end
    assert_includes err.message, "10100"
  end

  # Three levels deep: loop -> loop -> loop, 100 x 100 x 100 = 1_000_000.
  # Proves the accumulator survives more than one level of nesting.
  def test_rejects_triple_nested_loops_whose_product_exceeds_max
    innermost = [
      {
        "name" => "deepest",
        "value" => {
          "kind" => "loop",
          "count" => 100,
          "iterVar" => "k",
          "start" => 0,
          "step" => 1,
          "body" => [
            { "name" => "t0", "value" => { "kind" => "load_const", "value" => 1 } }
          ]
        }
      }
    ]
    err = assert_raises(ArgumentError) do
      RunarCompiler::IR.load_ir(ir_json(outer_count: 100, inner_count: 100, inner_body: innermost))
    end
    assert_includes err.message, "1000000"
  end
end
