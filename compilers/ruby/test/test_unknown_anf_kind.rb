# frozen_string_literal: true

# Regression test for F-003: every ANF-kind dispatch in the Ruby compiler
# must raise UnknownANFKindError when it encounters a kind it doesn't
# recognize, instead of silently returning an empty / no-op result.
#
# Each test drives one dispatch site with a synthetic ANFValue whose
# `kind` discriminator is not in the schema, then asserts the resulting
# raise is the typed error and carries the synthetic kind name.
#
# If a new ANFValue variant is added in the future, the dispatch sites
# below must be updated; this test guards against silently shipping an
# unhandled variant.

require_relative "test_helper"

require "set"
require "runar_compiler/ir/types"
require "runar_compiler/ir/unknown_anf_kind_error"
require "runar_compiler/codegen/stack"
require "runar_compiler/frontend/constant_fold"
require "runar_compiler/frontend/anf_optimize"
require "runar_compiler/frontend/anf_lower"

class TestUnknownAnfKind < Minitest::Test
  SYNTHETIC_KIND = "synthetic_test_kind_for_regression_only"

  def synthetic_value
    RunarCompiler::IR::ANFValue.new(kind: SYNTHETIC_KIND)
  end

  def synthetic_binding
    RunarCompiler::IR::ANFBinding.new(name: "t0", value: synthetic_value)
  end

  def make_program(bindings)
    method = RunarCompiler::IR::ANFMethod.new(
      name: "m",
      params: [],
      body: bindings,
      is_public: true
    )
    RunarCompiler::IR::ANFProgram.new(
      contract_name: "Test",
      properties: [],
      methods: [method]
    )
  end

  # -------------------------------------------------------------------
  # stack-lower
  # -------------------------------------------------------------------

  def test_collect_refs_raises_on_unknown_kind
    err = assert_raises(RunarCompiler::IR::UnknownANFKindError) do
      RunarCompiler::Codegen.collect_refs(synthetic_value)
    end
    assert_equal SYNTHETIC_KIND, err.kind
    assert_equal "stack-lower.collectRefs", err.location
  end

  def test_lower_to_stack_raises_on_unknown_kind
    program = make_program([synthetic_binding])

    err = assert_raises(RunarCompiler::IR::UnknownANFKindError) do
      RunarCompiler::Codegen.lower_to_stack(program)
    end
    assert_equal SYNTHETIC_KIND, err.kind
    # collect_refs runs first (compute_last_uses) -- that's where we expect
    # the raise -- but lower_binding is the fallback. Both are acceptable.
    assert_includes(
      ["stack-lower.collectRefs", "stack-lower.lowerBinding"],
      err.location
    )
  end

  # -------------------------------------------------------------------
  # constant-fold
  # -------------------------------------------------------------------

  def test_fold_constants_raises_on_unknown_kind
    program = make_program([synthetic_binding])

    err = assert_raises(RunarCompiler::IR::UnknownANFKindError) do
      RunarCompiler::Frontend::ConstantFold.fold_constants(program)
    end
    assert_equal SYNTHETIC_KIND, err.kind
    assert_equal "constant-fold.foldValue", err.location
  end

  def test_collect_refs_from_value_raises_on_unknown_kind
    used = Set.new
    err = assert_raises(RunarCompiler::IR::UnknownANFKindError) do
      RunarCompiler::Frontend::ConstantFold.collect_refs_from_value(
        synthetic_value, used
      )
    end
    assert_equal SYNTHETIC_KIND, err.kind
    assert_equal "constant-fold.collectRefsFromValue", err.location
  end

  def test_has_side_effect_raises_on_unknown_kind
    err = assert_raises(RunarCompiler::IR::UnknownANFKindError) do
      RunarCompiler::Frontend::ConstantFold.has_side_effect(synthetic_value)
    end
    assert_equal SYNTHETIC_KIND, err.kind
    assert_equal "constant-fold.hasSideEffect", err.location
  end

  # -------------------------------------------------------------------
  # anf-lower / EC optimizer
  # -------------------------------------------------------------------

  def test_remap_value_refs_raises_on_unknown_kind
    err = assert_raises(RunarCompiler::IR::UnknownANFKindError) do
      RunarCompiler::Frontend.send(:_remap_value_refs, synthetic_value, {})
    end
    assert_equal SYNTHETIC_KIND, err.kind
    assert_equal "anf-lower.remapValueRefs", err.location
  end

  def test_anf_optimize_collect_refs_raises_on_unknown_kind
    used = Set.new
    err = assert_raises(RunarCompiler::IR::UnknownANFKindError) do
      RunarCompiler::Frontend::ANFOptimize.send(
        :collect_refs, synthetic_value, used
      )
    end
    assert_equal SYNTHETIC_KIND, err.kind
    assert_equal "anf-optimize.collectRefs", err.location
  end

  def test_anf_optimize_has_side_effect_raises_on_unknown_kind
    err = assert_raises(RunarCompiler::IR::UnknownANFKindError) do
      RunarCompiler::Frontend::ANFOptimize.send(
        :has_side_effect?, synthetic_value
      )
    end
    assert_equal SYNTHETIC_KIND, err.kind
    assert_equal "anf-optimize.hasSideEffect", err.location
  end

  # -------------------------------------------------------------------
  # Error shape
  # -------------------------------------------------------------------

  def test_error_message_references_developer_recipe
    err = RunarCompiler::IR::UnknownANFKindError.new(
      SYNTHETIC_KIND, "unit-test.location"
    )
    assert_includes err.message, SYNTHETIC_KIND
    assert_includes err.message, "unit-test.location"
    assert_includes err.message, "Adding a New ANF Value Kind"
  end
end
