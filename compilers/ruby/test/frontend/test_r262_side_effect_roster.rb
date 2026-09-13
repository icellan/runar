# frozen_string_literal: true

require_relative "../test_helper"
require "runar_compiler/frontend/dce"
require "runar_compiler/frontend/constant_fold"

# R-262 (CL-GAP-010): constant_fold.rb carried a second, hand-maintained copy of
# dce.rb's side-effect roster and free-kind list.
#
# They had already drifted. R-140 taught DCE to decide `if` and `loop` by
# recursing into their arms rather than treating them as unconditionally
# side-effecting; this copy kept the old flat entries. It was harmless only
# because nothing in lib/ calls constant_fold's `has_side_effect` — the tests do,
# to pin the F-003 unknown-kind guard and its cross-tier location strings.
#
# The lists are derived from DCE's now. These tests pin the RELATIONSHIP rather
# than two copies of the contents, which is the thing that can go wrong.
class TestR262SideEffectRoster < Minitest::Test
  CF = RunarCompiler::Frontend::ConstantFold
  DCE = RunarCompiler::Frontend::DCE

  def test_free_kinds_are_dces_list
    assert_equal DCE::SIDE_EFFECT_FREE_KINDS.sort, CF::SIDE_EFFECT_FREE_KINDS.sort,
                 "the folder's free-kind list must be DCE's, not a copy of it"
  end

  def test_side_effect_kinds_are_dces_plus_if_and_loop
    cf = CF::SIDE_EFFECT_KINDS.to_a
    dce = DCE::SIDE_EFFECT_KINDS.to_a
    extra = cf - dce
    missing = dce - cf

    assert_equal [], missing,
                 "DCE treats these as side-effecting and the folder does not; " \
                 "the folder does not recurse, so it must be a SUPERSET"
    assert_equal %w[if loop].sort, extra.sort,
                 "the only deliberate difference is `if` and `loop`: DCE decides " \
                 "them by recursing into the arms, the folder cannot, so it " \
                 "lists them flat to avoid raising on a legitimate conditional"
  end

  def test_the_folder_still_answers_for_if_and_loop
    # The reason the superset exists: these must not raise.
    %w[if loop].each do |kind|
      value = RunarCompiler::IR::ANFValue.new(kind: kind)
      assert CF.has_side_effect(value),
             "#{kind} must be reported side-effecting by the non-recursing folder"
    end
  end
end
