# frozen_string_literal: true

require_relative "test_helper"
require "tmpdir"
require "runar_compiler/compiler"

# N-005 — an assert that is not the method's last binding must be lowered with
# OP_VERIFY. Port of the reference tier's case in
# packages/runar-compiler/src/__tests__/asm-surface.test.ts.
#
# Stack lowering treated the LAST assert of a public method as terminal (its
# value left as the script result) even when a terminal asm() followed it. The
# asm pushed OP_1, the end-of-method cleanup NIPped the comparison away, and
# the method compiled to 012a9c5177 (<42> OP_NUMEQUAL OP_1 OP_NIP): spendable
# with ANY x. The hand-derived fixed script is 012a9d51
# (<42> OP_NUMEQUALVERIFY OP_1).
#
# Proves: this tier's bytes for the shape in both fold modes, and that a truly
# final assert still stays the method result. Does NOT prove on-chain
# behaviour — the Spend-engine proof for all seven tiers is
# packages/runar-testing/src/__tests__/n005-assert-then-asm-spend.test.ts.
class TestN005AssertThenAsm < Minitest::Test
  ASSERT_THEN_ASM = <<~TS
    import { UnsafeSmartContract, assert, asm } from 'runar-lang';

    class AssertThenAsm extends UnsafeSmartContract {
      constructor() {
        super();
      }

      public unlock(x: bigint) {
        assert(x === 42n);
        asm({ body: '51', in_arity: 0, out_arity: 1 });
      }
    }
  TS

  ASM_THEN_ASSERT = <<~TS
    import { UnsafeSmartContract, assert, asm } from 'runar-lang';

    class AsmThenAssert extends UnsafeSmartContract {
      constructor() {
        super();
      }

      public unlock(x: bigint) {
        asm({ body: '51', in_arity: 0, out_arity: 1 });
        assert(x === 42n);
      }
    }
  TS

  def script_hex(source, disable_constant_folding)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "AssertThenAsm.runar.ts")
      File.write(path, source)
      RunarCompiler.compile_from_source(path, disable_constant_folding: disable_constant_folding).script
    end
  end

  def test_assert_before_terminal_asm_is_verified
    [true, false].each do |disable|
      got = script_hex(ASSERT_THEN_ASM, disable)
      refute_equal "012a9c5177", got, "disable_fold=#{disable}: assert left unenforced"
      assert_equal "012a9d51", got, "disable_fold=#{disable}: want <42> OP_NUMEQUALVERIFY OP_1"
    end
  end

  def test_final_assert_stays_the_result
    # OP_1 OP_SWAP <42> OP_NUMEQUAL (terminal, no OP_VERIFY) OP_NIP
    assert_equal "517c012a9c77", script_hex(ASM_THEN_ASSERT, true)
  end
end
