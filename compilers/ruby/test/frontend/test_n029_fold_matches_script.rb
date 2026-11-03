# frozen_string_literal: true

require_relative "../test_helper"
require "runar_compiler/ir/types"
require "runar_compiler/frontend/constant_fold"
# const_to_anf_value calls Frontend._bigint_json_value, defined in anf_lower.
require "runar_compiler/frontend/anf_lower"

# N-029: every folded value must be what the emitted script computes.
#
# clamp lowers to `<v> <lo> OP_MAX <hi> OP_MIN` = min(max(v, lo), hi), which
# differs from [lo, [v, hi].min].max once lo > hi (clamp(5, 10, 0) is 0
# on-chain and folded to 10). gcd unrolls 256 Euclid steps, so past those the
# script returns a partial value and the folder must decline. log2 is exact for
# every n > 0 since N-103 and aborts for n <= 0, so the folder folds every
# positive operand and declines the rest. Expected values were executed on @bsv/sdk
# Spend.validate by
# packages/runar-testing/src/__tests__/n029-fold-builtin-script-parity.test.ts.
#
# Proves the Ruby folder's value/decline decisions; not the script itself.
class TestN029FoldMatchesScript < Minitest::Test
  IR = RunarCompiler::IR

  def fib(n)
    a, c = 0, 1
    n.times { a, c = c, a + c }
    a
  end

  # ANFValue.new takes only +kind+; every other field is set by accessor.
  def mk_int(n)
    v = IR::ANFValue.new(kind: "load_const")
    v.raw_value = n.to_s
    v.const_big_int = n
    v.const_int = n
    v
  end

  def fold(args, func)
    body = args.each_with_index.map { |a, i| IR::ANFBinding.new(name: "t#{i}", value: mk_int(a)) }
    call = IR::ANFValue.new(kind: "call")
    call.func = func
    call.args = args.each_index.map { |i| "t#{i}" }
    body << IR::ANFBinding.new(name: "r", value: call)
    method = IR::ANFMethod.new(name: "m", params: [], body: body, is_public: true)
    program = IR::ANFProgram.new(contract_name: "Test", properties: [], methods: [method])
    RunarCompiler::Frontend::ConstantFold.fold_constants(program).methods[0].body.last.value
  end

  def assert_folded(value, expected)
    assert_equal "load_const", value.kind
    assert_equal expected, value.const_big_int
  end

  def test_clamp_lo_above_hi_matches_script
    assert_folded fold([5, 10, 0], "clamp"), 0
    assert_folded fold([0, 3, -3], "clamp"), -3
    assert_folded fold([-20, 10, 0], "clamp"), 0
  end

  # N-103 (user decision R86): this used to pin the decline past 64 halvings
  # (2^65 and 2^70 not folded). The script is now exact with no cap, and
  # n <= 0 (which it aborts on) is declined instead of folded to 0.
  def test_log2_exact_and_declines_non_positive
    assert_folded fold([1 << 64], "log2"), 64
    assert_folded fold([(1 << 65) - 1], "log2"), 64
    assert_folded fold([1 << 65], "log2"), 65
    assert_folded fold([1 << 70], "log2"), 70
    assert_equal "call", fold([0], "log2").kind
    assert_equal "call", fold([-1], "log2").kind
  end

  def test_gcd_declines_past_256_steps
    assert_folded fold([fib(258), fib(257)], "gcd"), 1
    assert_equal "call", fold([fib(259), fib(258)], "gcd").kind
    assert_equal "call", fold([fib(300), fib(299)], "gcd").kind
  end
end
