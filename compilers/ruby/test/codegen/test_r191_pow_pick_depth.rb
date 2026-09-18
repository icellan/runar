# frozen_string_literal: true

require_relative "../test_helper"

# R-191 (CL-BUG-166): `pow` emitted the only depth-less `{ op: "pick" }` in the
# stack lowerer.
#
# Everywhere else in this file a `pick` carries the depth it was picked at —
# `emit_pick(depth)` pushes the literal and then records `depth:` on the op. In
# `pow` the depth is the literal 2 pushed on the preceding line, and the op was
# emitted with no depth at all: the same op name meaning a different thing.
#
# Byte-neutral, because the emitter renders both as a bare OP_PICK. The reason
# to fix it is the one the finding gives: a latent divergence trap if a
# push+pick fold ever lands, since the fold would see a `pick` whose depth it
# cannot read. The TS reference and the go / python / java tiers all spell this
# as a raw OP_PICK opcode; this tier now does too.
class TestR191PowPickDepth < Minitest::Test
  STACK_RB = File.expand_path(
    "../../lib/runar_compiler/codegen/stack.rb", __dir__
  )

  def test_no_depthless_pick_op_remains
    offenders = []
    File.readlines(STACK_RB).each_with_index do |line, i|
      next if line.strip.start_with?("#")
      # A structured pick op with no depth: field.
      offenders << "stack.rb:#{i + 1}: #{line.strip}" if line =~ /op:\s*"pick"\s*\}/
    end
    assert_equal [], offenders,
                 "a `pick` op without a depth: field is a different op wearing " \
                 "the same name; emit a raw OP_PICK opcode instead"
  end

  def test_every_structured_pick_carries_a_depth
    picks = File.readlines(STACK_RB).grep(/op:\s*"pick"/).reject { |l| l.strip.start_with?("#") }
    refute_empty picks, "no pick ops found — the scan broke, not the code"
    picks.each do |line|
      assert_match(/depth:/, line,
                   "structured pick without a depth: #{line.strip}")
    end
  end
end
