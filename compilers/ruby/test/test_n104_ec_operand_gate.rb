# frozen_string_literal: true

# N-104 -- the EC identity rewrites R1-R4 (ecAdd(q, O) -> q, ecAdd(O, q) -> q,
# ecMul(q, 1) -> q, ecMul(q, 0) -> O) must keep the replaced builtin's operand
# validation in place of the call. They used to drop it, so a malformed or
# off-curve q was accepted by the optimized script and aborted by the
# unoptimized one.
#
# Pins the exact gate bindings -- names, kinds, operands, order -- every tier
# emits (the "gate" entries in optimizer/ec-rules.json), so the seven tiers
# stay ANF- and hex-identical. Proves this tier emits the gate; the gate's
# script semantics are executed on the real Spend engine by
# packages/runar-testing/src/__tests__/n104-ec-optimizer-operand-gate.test.ts.

require_relative "test_helper"
require "runar_compiler/frontend/anf_optimize"

class TestN104ECOperandGate < Minitest::Test
  INFINITY_HEX = "0" * 128
  FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

  ADD_GATE = [
    "t_px = call ecPointX p",
    "t_py = call ecPointY p",
    "t_fp = const #{FIELD_P}",
    "t_pxok = bin_op < t_px t_fp",
    "t_pyok = bin_op < t_py t_fp",
    "t_ok = bin_op && t_pxok t_pyok",
    "t_gate = assert t_ok"
  ].freeze

  MUL_GATE = [
    "t_inf = const INFINITY",
    "t_isinf = bin_op === p t_inf bytes",
    "t_oncurve = call ecOnCurve p",
    "t_ok = bin_op || t_isinf t_oncurve",
    "t_gate = assert t_ok"
  ].freeze

  def binding(name, kind, **fields)
    v = RunarCompiler::IR::ANFValue.new(kind: kind)
    fields.each { |k, val| v.public_send("#{k}=", val) }
    RunarCompiler::IR::ANFBinding.new(name: name, value: v)
  end

  def describe(b)
    v = b.value
    d = case v.kind
        when "load_param" then "load_param #{v.name}"
        when "load_const"
          s = v.const_string
          if s.nil? then "const #{v.const_big_int}"
          elsif s == INFINITY_HEX then "const INFINITY"
          elsif s.start_with?("@ref:") then "ref #{s[5..]}"
          else "const #{s}"
          end
        when "call" then "call #{v.func} #{v.args.join(' ')}"
        when "bin_op" then ["bin_op", v.op, v.left, v.right, v.result_type].compact.join(" ")
        when "assert" then "assert #{v.value_ref}"
        else v.kind
        end
    "#{b.name} = #{d}"
  end

  def run_rule(second, func, args)
    body = [
      binding("p", "load_param", name: "pt"),
      second,
      binding("t", "call", func: func, args: args),
      binding("a", "assert", value_ref: "t", raw_value: JSON.generate("t"))
    ]
    program = RunarCompiler::IR::ANFProgram.new(
      contract_name: "Test", properties: [],
      methods: [RunarCompiler::IR::ANFMethod.new(name: "test", params: [], is_public: true, body: body)]
    )
    RunarCompiler::Frontend::ANFOptimize.optimize_ec(program).methods[0].body.map { |b| describe(b) }
  end

  def inf
    binding("inf", "load_const", const_string: INFINITY_HEX, raw_value: INFINITY_HEX)
  end

  def int(name, n)
    binding(name, "load_const", const_big_int: n, const_int: n, raw_value: n.to_s)
  end

  def expected(gate, result)
    ["p = load_param pt", *gate, "t = #{result}", "a = assert t"]
  end

  def test_ec_add_identity_right_keeps_gate
    assert_equal expected(ADD_GATE, "ref p"), run_rule(inf, "ecAdd", %w[p inf])
  end

  def test_ec_add_identity_left_keeps_gate
    assert_equal expected(ADD_GATE, "ref p"), run_rule(inf, "ecAdd", %w[inf p])
  end

  def test_ec_mul_one_keeps_gate
    assert_equal expected(MUL_GATE, "ref p"), run_rule(int("one", 1), "ecMul", %w[p one])
  end

  def test_ec_mul_zero_keeps_gate
    assert_equal expected(MUL_GATE, "const INFINITY"), run_rule(int("zero", 0), "ecMul", %w[p zero])
  end
end
