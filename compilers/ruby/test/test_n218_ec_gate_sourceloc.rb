# frozen_string_literal: true

# N-218: port of F-343 to this tier.
#
# The TS reference's optimizeBodyOnce
# (packages/runar-compiler/src/optimizer/anf-ec.ts) keeps the rewritten
# binding's source location on every helper binding a rule mints -- the
# N-104 operand gate, the N-251 neg-cancel gate, and the fused-scalar helper
# -- because stack lowering maps opcodes through binding.source_loc. Before
# this fix, optimize_method appended every helper binding with no
# source_loc regardless of the rewritten binding's own location, so none of
# a rewritten EC call's gate opcodes reached the source map.
#
# Proves: a located ecMul(p, 0) rewrite's mul gate (5 bindings), a located
# ecAdd(p, ecNegate(p)) rewrite's neg-cancel gate (7 bindings), and a located
# nested-ecMul fusion's _k helper all carry the rewritten binding's
# source_loc; an unlocated rewrite mints unlocated helpers (no source_loc
# invented from nothing).
#
# Does not prove: exact file/line/column assignment upstream in the ANF
# lowerer, or end-to-end script-map behavior -- that is covered by the TS
# test f343-ec-optimizer-source-loc.test.ts and by conformance, which strips
# sourceLoc as debug-only and so cannot regress from this change.

require_relative "test_helper"
require "runar_compiler/frontend/anf_optimize"

class TestN218ECGateSourceLoc < Minitest::Test
  LOC = RunarCompiler::IR::SourceLocation.new(file: "T.runar.ts", line: 7, column: 4)

  def binding(name, kind, source_loc: nil, **fields)
    v = RunarCompiler::IR::ANFValue.new(kind: kind)
    fields.each { |k, val| v.public_send("#{k}=", val) }
    RunarCompiler::IR::ANFBinding.new(name: name, value: v, source_loc: source_loc)
  end

  def find(body, name)
    body.find { |b| b.name == name } || raise("missing binding #{name}")
  end

  def optimize(body)
    program = RunarCompiler::IR::ANFProgram.new(
      contract_name: "Test", properties: [],
      methods: [RunarCompiler::IR::ANFMethod.new(name: "test", params: [], is_public: true, body: body)]
    )
    RunarCompiler::Frontend::ANFOptimize.optimize_ec(program).methods[0].body
  end

  def test_rule4_mul_gate_carries_source_loc
    body = [
      binding("p", "load_param", name: "pt"),
      binding("zero", "load_const", const_big_int: 0, const_int: 0, raw_value: "0"),
      binding("t", "call", func: "ecMul", args: %w[p zero], source_loc: LOC),
      binding("a", "assert", value_ref: "t", raw_value: JSON.generate("t"))
    ]
    out = optimize(body)
    %w[t_inf t_isinf t_oncurve t_ok t_gate].each do |name|
      b = find(out, name)
      assert_equal LOC, b.source_loc, "#{name}: source_loc mismatch"
    end
    assert_equal LOC, find(out, "t").source_loc, "t: source_loc mismatch"
  end

  def test_rule8_neg_cancel_gate_carries_source_loc
    body = [
      binding("p", "load_param", name: "pt"),
      binding("n", "call", func: "ecNegate", args: %w[p]),
      binding("t", "call", func: "ecAdd", args: %w[p n], source_loc: LOC),
      binding("a", "assert", value_ref: "t", raw_value: JSON.generate("t"))
    ]
    out = optimize(body)
    %w[t_px t_py t_zero t_pxz t_pynz t_ok t_gate].each do |name|
      b = find(out, name)
      assert_equal LOC, b.source_loc, "#{name}: source_loc mismatch"
    end
  end

  def test_rule9_fused_scalar_helper_carries_source_loc
    body = [
      binding("p", "load_param", name: "pt"),
      binding("k1", "load_const", const_big_int: 3, const_int: 3, raw_value: "3"),
      binding("k2", "load_const", const_big_int: 5, const_int: 5, raw_value: "5"),
      binding("inner", "call", func: "ecMul", args: %w[p k1]),
      binding("outer", "call", func: "ecMul", args: %w[inner k2], source_loc: LOC),
      binding("a", "assert", value_ref: "outer", raw_value: JSON.generate("outer"))
    ]
    out = optimize(body)
    assert_equal LOC, find(out, "outer_k").source_loc, "outer_k: source_loc mismatch"
    assert_equal LOC, find(out, "outer").source_loc, "outer: source_loc mismatch"
  end

  def test_unlocated_rewrite_mints_unlocated_helpers
    body = [
      binding("p", "load_param", name: "pt"),
      binding("zero", "load_const", const_big_int: 0, const_int: 0, raw_value: "0"),
      binding("t", "call", func: "ecMul", args: %w[p zero]),
      binding("a", "assert", value_ref: "t", raw_value: JSON.generate("t"))
    ]
    out = optimize(body)
    out.each { |b| assert_nil b.source_loc, "#{b.name}: expected no source_loc" }
  end
end
