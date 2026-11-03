# frozen_string_literal: true

# F-072 — lowerCall's `exit` / `assert` branches recorded a stack slot no
# opcode produces.
#
# `exit(cond)` lowers as `call exit` (no dedicated ANF node); stack lowering
# ran `cond OP_VERIFY` and then pushed a slot for the void result. OP_VERIFY
# leaves nothing behind, so every later PICK/ROLL addressed the item one below
# the one it meant. For
#   check(b, a, x, y) { exit(x > 0n); assert(y === 1n); assert(a > 5n); assert(b === 0n); }
# every tier emitted 7c00a0697c519d7c55a0697c9177, which the five-push witness
# (0, b=6, a=1, x=1, y=999) spends. `call assert` (reachable only through --ir)
# hit the same bug; the `super` branch is dead (constructors are never
# stack-lowered and the loader refuses `super` elsewhere).
#
# What this proves: the Ruby tier emits the hand-derived 7c00a069519d55a06991
# on the source path (both fold modes) and on the --ir path for `call exit`
# and `call assert`.
# What it does NOT prove: that the script spends correctly — executed on the
# @bsv/sdk engine for all seven tiers in
# packages/runar-testing/src/__tests__/f072-exit-phantom-slot-spend.test.ts.

require_relative "test_helper"
require "json"
require "tmpdir"

class TestF072ExitPhantomSlot < Minitest::Test
  EXPECTED = "7c00a069519d55a06991"
  PRE_FIX = "7c00a0697c519d7c55a0697c9177"

  SOURCE = <<~TS
    import { SmartContract, assert } from 'runar-lang';

    class ExitAssert4 extends SmartContract {
      constructor() {
        super();
      }

      public check(b: bigint, a: bigint, x: bigint, y: bigint) {
        exit(x > 0n);
        assert(y === 1n);
        assert(a > 5n);
        assert(b === 0n);
      }
    }
  TS

  def ir(guard)
    b = ->(name, value) { { name: name, value: value } }
    JSON.generate(
      contractName: "ExitAssert4",
      properties: [],
      methods: [
        { name: "constructor", isPublic: false, params: [],
          body: [b.call("t0", { kind: "call", func: "super", args: [] })] },
        { name: "check", isPublic: true,
          params: %w[b a x y].map { |n| { name: n, type: "bigint" } },
          body: [
            b.call("t0", { kind: "load_param", name: "x" }),
            b.call("t1", { kind: "load_const", value: 0 }),
            b.call("t2", { kind: "bin_op", op: ">", left: "t0", right: "t1" }),
            b.call("t3", { kind: "call", func: guard, args: ["t2"] }),
            b.call("t4", { kind: "load_param", name: "y" }),
            b.call("t5", { kind: "load_const", value: 1 }),
            b.call("t6", { kind: "bin_op", op: "===", left: "t4", right: "t5" }),
            b.call("t7", { kind: "assert", value: "t6" }),
            b.call("t8", { kind: "load_param", name: "a" }),
            b.call("t9", { kind: "load_const", value: 5 }),
            b.call("t10", { kind: "bin_op", op: ">", left: "t8", right: "t9" }),
            b.call("t11", { kind: "assert", value: "t10" }),
            b.call("t12", { kind: "load_param", name: "b" }),
            b.call("t13", { kind: "load_const", value: 0 }),
            b.call("t14", { kind: "bin_op", op: "===", left: "t12", right: "t13" }),
            b.call("t15", { kind: "assert", value: "t14" })
          ] }
      ]
    )
  end

  def test_exit_then_assert_source_reads_right_slots
    Dir.mktmpdir do |dir|
      path = File.join(dir, "ExitAssert4.runar.ts")
      File.write(path, SOURCE)
      [false, true].each do |fold|
        art = RunarCompiler.compile_from_source(path, disable_constant_folding: !fold)
        refute_equal PRE_FIX, art.script, "fold=#{fold}: phantom slot after exit(): #{art.asm}"
        assert_equal EXPECTED, art.script, "fold=#{fold}: #{art.asm}"
      end
    end
  end

  def test_call_exit_and_call_assert_ir_read_right_slots
    %w[exit assert].each do |guard|
      art = RunarCompiler.compile_from_ir_bytes(ir(guard))
      assert_equal EXPECTED, art.script, "call #{guard}: #{art.asm}"
    end
  end
end
