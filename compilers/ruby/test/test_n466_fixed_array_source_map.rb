# frozen_string_literal: true

require_relative "test_helper"
require "json"
require "runar_compiler/compiler"

# N-466 -- the Ruby tier mapped 284 opcodes of the TicTacToe v2 example to
# 0:0 where the TypeScript reference maps them to a real statement.
#
# `lower_statements` rewrites `if (c) { ...; return x; } rest...` into an `if`
# whose else-branch holds `rest`. The rewritten IfStmt was built without the
# original statement's source_location, so the `if` binding (and everything
# lowered under it) lost its location. The TypeScript pass spreads the
# original statement (`{ ...stmt, else: remaining }`) and keeps it.
#
# The reference is the TypeScript tier, pinned in n466_ts_reference_map.json as
# runs [firstOpcode, lastOpcode, line, column]. Regenerate with
# `runar compile examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts -o <dir>
# --disable-constant-folding --emit-source-map <out.json>`.
#
# What this proves: compiling the same .runar.ts source with constant folding
# off, the Ruby source map maps exactly the opcodes TS maps, each to the same
# line and column.
#
# What this does not prove: anything about other contracts, other tiers, or
# fold-ON maps (the TS map is pinned, not recomputed). The 90-example sweep in
# remediation-logs/N-394 covers the other examples.
class TestN466FixedArraySourceMap < Minitest::Test
  SOURCE = File.expand_path("../../../examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts", __dir__)
  REFERENCE = File.expand_path("n466_ts_reference_map.json", __dir__)

  def ts_reference
    JSON.parse(File.read(REFERENCE))["tic-tac-toe-v2"].each_with_object({}) do |(first, last, line, col), h|
      (first..last).each { |op| h[op] = [line, col] }
    end
  end

  def test_early_return_if_keeps_its_source_location_like_ts
    artifact = RunarCompiler.compile_from_source(SOURCE, disable_constant_folding: true)
    got = (artifact.source_map || []).each_with_object({}) do |m, h|
      h[m.opcode_index] = [m.line, m.column]
    end
    want = ts_reference
    diffs = (want.keys | got.keys).sort.reject { |i| want[i] == got[i] }
                                  .map { |i| "##{i}: TS #{want[i].inspect} / Ruby #{got[i].inspect}" }
    assert_empty diffs, "#{diffs.size} opcodes differ from the TS map: #{diffs.first(10)}"
  end
end
