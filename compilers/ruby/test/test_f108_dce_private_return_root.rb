# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/ir/types"
require "runar_compiler/frontend/dce"

# F-108 — DCE must treat a PRIVATE method's last binding as a liveness root.
#
# Stack lowering inlines a private helper at each +method_call+ and takes the
# helper's LAST binding as the call's result. Nothing inside the helper
# references that binding, so a pure return expression (+return n + 1n+) was
# deleted whenever DCE ran — which in this tier happens to every method once any
# EC rewrite fires anywhere in the program. The helper was emptied and the
# contract failed to compile ("value \"t2\" not found on stack").
#
# What this proves: +eliminate_dead_bindings+ keeps a private method's final
# binding and its inputs, still drops a genuinely dead binding ahead of it, and
# still drops an unreferenced pure final binding of a PUBLIC method.
# What it does not prove: spendability — conformance/dce/private-return.test.ts
# executes the compiled script on all seven tiers.
class TestF108DcePrivateReturnRoot < Minitest::Test
  include RunarCompiler::IR

  # ANFValue#initialize accepts only +kind:+; assign fields afterwards.
  def const_of(name, n)
    v = ANFValue.new(kind: "load_const")
    v.raw_value = n
    v.const_big_int = n
    ANFBinding.new(name: name, value: v)
  end

  def add1(is_public)
    param = ANFValue.new(kind: "load_param")
    param.name = "n"
    sum = ANFValue.new(kind: "bin_op")
    sum.op = "+"
    sum.left = "t0"
    sum.right = "t1"
    ANFMethod.new(
      name: is_public ? "pub_m" : "add1",
      params: [ANFParam.new(name: "n", type: "bigint")],
      body: [
        const_of("dead", 7),
        ANFBinding.new(name: "t0", value: param),
        const_of("t1", 1),
        ANFBinding.new(name: "t2", value: sum)
      ],
      is_public: is_public
    )
  end

  def test_dce_keeps_private_method_return_value
    m = add1(false)
    RunarCompiler::Frontend::DCE.eliminate_dead_bindings(m)
    assert_equal %w[t0 t1 t2], m.body.map(&:name),
                 "DCE emptied a private helper's return value"
  end

  def test_dce_still_drops_public_method_pure_last_binding
    m = add1(true)
    RunarCompiler::Frontend::DCE.eliminate_dead_bindings(m)
    assert_equal [], m.body.map(&:name)
  end
end
