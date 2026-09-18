# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/ir/types"
require "runar_compiler/frontend/dce"

# R-140 / CL-BUG-027 — +if+ and +loop+ were unconditionally side-effecting here.
#
# +SIDE_EFFECT_KINDS+ listed +if+ and +loop+, so an unreferenced branch or loop
# whose bodies are entirely pure was kept in this tier and deleted by the Go,
# Java, Rust and TypeScript tiers. Measured on the predicate itself, which is
# the only place the disagreement is visible: no shipped path reaches DCE with
# that shape today, so the conformance suite cannot see it.
#
#   go  HasSideEffect(pure if)   = false     zig hasSideEffect(pure if)   = true
#   go  HasSideEffect(pure loop) = false     zig hasSideEffect(pure loop) = true
#
# The reference tier recurses, and the reason it gives is the reason recursion
# is correct rather than merely different: nested bindings live inside the
# parent node rather than flattened into the method body, so dropping an
# effectful +if+ would take every nested assert / check_preimage / add_output
# with it. Retention is all-or-nothing; recursing is what makes it precise.
class TestDcePureBranchParity < Minitest::Test
  include RunarCompiler::IR

  # +ANFValue#initialize+ accepts only +kind:+ and silently discards every other
  # keyword (it sets all FIELDS to nil, then assigns @kind), so these helpers
  # assign after construction. Building one with +ANFValue.new(kind: "if",
  # then: [...])+ yields an EMPTY if — which is how the first version of this
  # test managed to exercise nothing.
  def binding_of(name, value)
    ANFBinding.new(name: name, value: value)
  end

  def pure(kind = "load_const")
    ANFValue.new(kind: kind)
  end

  def effectful
    v = ANFValue.new(kind: "assert")
    v.value_ref = "c"
    v
  end

  def if_value(then_b, else_b)
    v = ANFValue.new(kind: "if")
    v.cond = "c"
    v.then = then_b
    v.else_ = else_b
    v
  end

  def loop_value(body_b)
    v = ANFValue.new(kind: "loop")
    v.count = 2
    v.iter_var = "i"
    v.body = body_b
    v
  end

  def test_if_with_pure_branches_is_not_side_effecting
    v = if_value([binding_of("t1", pure)], [binding_of("t2", pure)])
    refute RunarCompiler::Frontend::DCE.has_side_effect?(v)
  end

  def test_loop_with_a_pure_body_is_not_side_effecting
    v = loop_value([binding_of("t1", pure("bin_op"))])
    refute RunarCompiler::Frontend::DCE.has_side_effect?(v)
  end

  def test_if_keeps_an_effectful_then_branch
    v = if_value([binding_of("t1", effectful)], [binding_of("t2", pure)])
    assert RunarCompiler::Frontend::DCE.has_side_effect?(v)
  end

  def test_if_keeps_an_effectful_else_branch
    v = if_value([binding_of("t1", pure)], [binding_of("t2", effectful)])
    assert RunarCompiler::Frontend::DCE.has_side_effect?(v)
  end

  def test_loop_keeps_an_effectful_body
    v = loop_value([binding_of("t1", effectful)])
    assert RunarCompiler::Frontend::DCE.has_side_effect?(v)
  end

  # The case a top-level-only scan would miss.
  def test_recursion_reaches_a_nested_branch
    inner = if_value([binding_of("t2", effectful)], [])
    outer = if_value([binding_of("t1", inner)], [binding_of("t3", pure)])
    assert RunarCompiler::Frontend::DCE.has_side_effect?(outer)
  end

  def test_an_empty_if_is_pure
    refute RunarCompiler::Frontend::DCE.has_side_effect?(if_value([], []))
  end
end
