# frozen_string_literal: true

require_relative "../test_helper"
require "runar_compiler/ir/types"
require "runar_compiler/frontend/constant_fold"
# const_to_anf_value calls Frontend._bigint_json_value, defined in anf_lower.
require "runar_compiler/frontend/anf_lower"

# F-160: 'aa' and 'AA' decode to the same byte, so the script's OP_EQUAL over
# them is true and the folder must fold `===` to true and `!==` to false.
#
# Proves the Ruby folder's verdict on mixed-case hex; not the emitted script
# (conformance/negatives/f160-bytestring-case-fold-parity.test.ts pins every
# tier's bytes, and the TS optimizer test executes them on @bsv/sdk).
class TestF160BytestringCaseFold < Minitest::Test
  IR = RunarCompiler::IR

  def mk_str(s)
    v = IR::ANFValue.new(kind: "load_const")
    v.raw_value = JSON.generate(s)
    v.const_string = s
    v
  end

  def fold(op)
    cmp = IR::ANFValue.new(kind: "bin_op")
    cmp.op = op
    cmp.left = "t0"
    cmp.right = "t1"
    body = [
      IR::ANFBinding.new(name: "t0", value: mk_str("aa")),
      IR::ANFBinding.new(name: "t1", value: mk_str("AA")),
      IR::ANFBinding.new(name: "t2", value: cmp)
    ]
    method = IR::ANFMethod.new(name: "m", params: [], body: body, is_public: true)
    program = IR::ANFProgram.new(contract_name: "Test", properties: [], methods: [method])
    RunarCompiler::Frontend::ConstantFold.fold_constants(program).methods[0].body.last.value
  end

  def test_equality_ignores_hex_case
    value = fold("===")
    assert_equal "load_const", value.kind
    assert_equal true, value.const_bool
  end

  def test_inequality_ignores_hex_case
    value = fold("!==")
    assert_equal "load_const", value.kind
    assert_equal false, value.const_bool
  end
end
