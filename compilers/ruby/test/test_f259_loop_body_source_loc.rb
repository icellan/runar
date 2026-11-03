# frozen_string_literal: true

require_relative "test_helper"
require "runar_compiler/compiler"

# F-259 -- an unrolled loop body's opcodes map to the body statement's line,
# not to the `for` line.
#
# Before the fix `_lower_loop` lowered every body binding without updating
# `@current_source_loc`, so every opcode of every unrolled iteration inherited
# the enclosing loop binding's location (the `for` line). Mirrors
# packages/runar-compiler/src/__tests__/f259-loop-body-source-loc.test.ts.
#
# Convention (same in all 7 tiers): each body binding's own location is used
# while it lowers; a body binding without one keeps the loop's location. The
# per-iteration iteration-variable push stays on the `for` line.
#
# What this proves: end to end on the Ruby surface of
# examples/ruby/bounded-loop, every body op of all five unrolled iterations
# maps to the body line and column, and only the five iteration-variable
# pushes (OP_0..OP_4) map to the `for` line.
#
# What this does not prove: anything about the other tiers, nested loops, or
# body bindings the ANF lowerer leaves without a location. It equates ASM
# token index with opcodeIndex, which holds for this contract (no raw spans).
class TestF259LoopBodySourceLoc < Minitest::Test
  SOURCE = File.expand_path("../../../examples/ruby/bounded-loop/BoundedLoop.runar.rb", __dir__)

  def test_loop_body_ops_map_to_the_body_line
    src = File.read(SOURCE)
    artifact = RunarCompiler.compile_from_source(SOURCE, disable_constant_folding: true)

    lines = src.split("\n")
    find = lambda do |needle, anchor|
      i = lines.index { |l| l.include?(needle) }
      refute_nil i, "needle #{needle.inspect} not in source"
      [i + 1, lines[i].index(anchor)]
    end
    for_line, for_col = find.call("for i in", "for")
    body_line, body_col = find.call("sum = sum + start + i", "sum")

    asm = artifact.asm.split
    iter_pushes = { 1 => "OP_0", 9 => "OP_1", 17 => "OP_2", 25 => "OP_3", 33 => "OP_4" }
    assert_equal iter_pushes, iter_pushes.keys.to_h { |i| [i, asm[i]] }, artifact.asm

    loop_ops = (artifact.source_map || []).select { |m| (1..39).cover?(m.opcode_index) }
    assert_equal 39, loop_ops.size

    loop_ops.each do |m|
      want = iter_pushes.key?(m.opcode_index) ? [for_line, for_col] : [body_line, body_col]
      assert_equal [m.opcode_index, *want], [m.opcode_index, m.line, m.column],
                   "opcode #{m.opcode_index} (#{asm[m.opcode_index]})"
    end
  end
end
