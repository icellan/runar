# frozen_string_literal: true

# R-034 / CL-BUG-028 -- `ec-add-negate-cancel-reversed` was a Go-only rule.
#
#     optimizer/ec-rules.json:
#       ec-add-negate-cancel           ecAdd($x, ecNegate($x))  -> INFINITY
#       ec-add-negate-cancel-reversed  ecAdd(ecNegate($x), $x)  -> INFINITY
#
# Neither carries a "supported" tag, so both are required in every tier. The Go
# engine is data-driven off that JSON and performed both; the six hand-ported
# tiers -- Ruby among them -- implemented only the forward direction, so the same
# ANF compiled to a 1808-byte script in Go and a 26140-byte one here.
#
# Note this rule is unreachable from SOURCE in every tier: pass 04 gives each
# occurrence of a variable its own load_param/load_prop binding, so $x binds to
# two different names and no matcher unifies them. The divergence is reachable
# through the `--ir` path, which accepts arbitrary ANF -- the same surface as
# test_repeated_operand_consume.rb.

require_relative "test_helper"
require "runar_compiler/frontend/anf_optimize"

class TestR034ECAddNegateCancelReversed < Minitest::Test
  POINT_HEX = "ab" * 64
  OTHER_POINT_HEX = "cd" * 64
  INFINITY_HEX = "0" * 128

  def load_const_hex(name, hex)
    v = RunarCompiler::IR::ANFValue.new(kind: "load_const")
    v.const_string = hex
    v.raw_value = hex
    RunarCompiler::IR::ANFBinding.new(name: name, value: v)
  end

  def call_binding(name, func, args)
    v = RunarCompiler::IR::ANFValue.new(kind: "call")
    v.func = func
    v.args = args
    RunarCompiler::IR::ANFBinding.new(name: name, value: v)
  end

  def optimize(bindings)
    program = RunarCompiler::IR::ANFProgram.new(
      contract_name: "Test",
      properties: [],
      methods: [
        RunarCompiler::IR::ANFMethod.new(name: "test", params: [], is_public: true, body: bindings)
      ]
    )
    RunarCompiler::Frontend::ANFOptimize.optimize_ec(program).methods[0].body
  end

  # Control: the already-implemented sibling. If this ever goes red the port
  # below broke rule ordering rather than the rule itself.
  def test_forward_direction_still_cancels
    body = optimize([
                      load_const_hex("t0", POINT_HEX),
                      call_binding("t1", "ecNegate", ["t0"]),
                      call_binding("t2", "ecAdd", %w[t0 t1]),
                      call_binding("t3", "assert", ["t2"])
                    ])
    t2 = body.find { |b| b.name == "t2" }
    assert_equal "load_const", t2.value.kind
    assert_equal INFINITY_HEX, t2.value.const_string
  end

  def test_reversed_direction_cancels
    body = optimize([
                      load_const_hex("t0", POINT_HEX),
                      call_binding("t1", "ecNegate", ["t0"]),
                      call_binding("t2", "ecAdd", %w[t1 t0]),
                      call_binding("t3", "assert", ["t2"])
                    ])
    t2 = body.find { |b| b.name == "t2" }
    assert_equal "load_const", t2.value.kind,
                 "ecAdd(ecNegate(x), x) must fold to the point at infinity"
    assert_equal INFINITY_HEX, t2.value.const_string
  end

  # CONTROL: distinct points must NOT cancel. Folding this would be a wrong
  # answer, not a faster one.
  def test_distinct_points_do_not_cancel
    body = optimize([
                      load_const_hex("p", POINT_HEX),
                      load_const_hex("q", OTHER_POINT_HEX),
                      call_binding("neg", "ecNegate", ["q"]),
                      call_binding("t0", "ecAdd", %w[neg p]),
                      call_binding("t1", "assert", ["t0"])
                    ])
    t0 = body.find { |b| b.name == "t0" }
    assert_equal "call", t0.value.kind
    assert_equal "ecAdd", t0.value.func
  end
end
