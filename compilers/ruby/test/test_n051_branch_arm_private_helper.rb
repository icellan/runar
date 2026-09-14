# frozen_string_literal: true

require_relative "test_helper"

require "tmpdir"
require "runar_compiler/compiler"

# Port of the TypeScript reference test
# packages/runar-compiler/src/__tests__/n051-branch-arm-private-helper.test.ts.
#
# N-051 -- a private-helper call inside a BRANCH ARM must inline the callee.
#
# spec/semantics.md §6.3 defines a private method as source-level substitution
# at every call site, and its canonical example is a helper call in EXPRESSION
# position:
#
#   private square(x: bigint): bigint { return x * x; }
#   public verify(n: bigint): void { assert(this.square(n) < 100n); }
#   // After inlining:
#   public verify(n: bigint): void { assert(n * n < 100n); }
#
# spec/ir-format.md §4.7 keeps `method_call` in the canonical ANF ("Inlining
# happens in a later compiler phase"), so the substitution is stack lowering's
# job -- and stack lowering lowers an `if`'s arms in a FRESH context.
#
# Ruby was already correct: codegen/stack.rb's `lower_if` copies
# `@private_methods` into the arm contexts. Go, Rust and Python did not, and
# each improvised a different answer for the same source:
#
#   const v: bigint = p > 0n ? this.bump(p) : 0n;   // bump(x) = x + 1n
#
#   ts / zig / ruby / java   7600a0638b6700776800a2         (correct)
#   go                       7600a063006700776800a2         (silently wrong)
#   python                   7600a063007c00776700776800a2   (silently wrong)
#   rust                     rejected: "unknown function 'bump'"
#
# This test exists in Ruby to hold that line: the tier that was right must fail
# loudly if it ever drifts.
#
# The hexes are the SEVEN-TIER agreed output. Every tier pins the same strings,
# which is what makes this a parity gate.
class TestN051BranchArmPrivateHelper < Minitest::Test
  PRELUDE = <<~SRC
    import { SmartContract, assert } from 'runar-lang';

    class C extends SmartContract {
      readonly s: bigint;

      constructor(s: bigint) { super(s); this.s = s; }
  SRC

  # Helper called from a ternary arm.
  TERNARY_ARM_PLUS_1 = PRELUDE + <<~SRC
      private bump(x: bigint): bigint { return x + 1n; }

      public m(p: bigint): void {
        const v: bigint = p > 0n ? this.bump(p) : 0n;
        assert(v >= this.s);
      }
    }
  SRC

  # Same shape, different callee body -- the body-independence probe.
  TERNARY_ARM_PLUS_2 = PRELUDE + <<~SRC
      private bump(x: bigint): bigint { return x + 2n; }

      public m(p: bigint): void {
        const v: bigint = p > 0n ? this.bump(p) : 0n;
        assert(v >= this.s);
      }
    }
  SRC

  # Control: the same program with the helper inlined by hand.
  TERNARY_ARM_MANUAL_INLINE = PRELUDE + <<~SRC
      public m(p: bigint): void {
        const v: bigint = p > 0n ? p + 1n : 0n;
        assert(v >= this.s);
      }
    }
  SRC

  # Helper called from an `if` STATEMENT arm.
  IF_STATEMENT_ARM = PRELUDE + <<~SRC
      private bump(x: bigint): bigint { return x + 1n; }

      public m(p: bigint): void {
        let v: bigint = 0n;
        if (p > 0n) {
          v = this.bump(p);
        } else {
          v = 0n;
        }
        assert(v >= this.s);
      }
    }
  SRC

  # Control: the same `if` with no helper call in either arm.
  IF_STATEMENT_ARM_NO_HELPER = PRELUDE + <<~SRC
      public m(p: bigint): void {
        let v: bigint = 0n;
        if (p > 0n) {
          v = p + 1n;
        } else {
          v = 0n;
        }
        assert(v >= this.s);
      }
    }
  SRC

  # Control: a helper call in ordinary statement position, outside any arm.
  STATEMENT_POSITION = PRELUDE + <<~SRC
      private bump(x: bigint): bigint { return x + 1n; }

      public m(p: bigint): void {
        const v: bigint = this.bump(p);
        assert(v >= this.s);
      }
    }
  SRC

  def compile_script_hex(source, disable_constant_folding)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "C.runar.ts")
      File.write(path, source)
      artifact = RunarCompiler.compile_from_source(
        path, disable_constant_folding: disable_constant_folding
      )
      artifact.script
    end
  end

  def test_seven_tier_script
    cases = [
      ["ternary-arm/+1", TERNARY_ARM_PLUS_1, "7600a0638b6700776800a2"],
      ["ternary-arm/+2", TERNARY_ARM_PLUS_2, "7600a06352936700776800a2"],
      ["ternary-arm-manual-inline", TERNARY_ARM_MANUAL_INLINE, "7600a0638b6700776800a2"],
      ["if-statement-arm", IF_STATEMENT_ARM,
       "007800a0637c8b767676537a757777670076537a7577687c7500a2"],
      ["if-statement-arm-no-helper", IF_STATEMENT_ARM_NO_HELPER,
       "007800a0637c8b7677670076537a7577687c7500a2"],
      ["statement-position", STATEMENT_POSITION, "8b00a2"]
    ]

    cases.each do |label, source, want|
      [true, false].each do |disable|
        got = compile_script_hex(source, disable)
        assert_equal want, got,
                     "#{label} (disable_constant_folding=#{disable}): " \
                     "script hex diverged from the seven-tier agreed output"
      end
    end
  end

  # spec/semantics.md §6.3: inlining IS substitution, so a helper call in a
  # ternary arm and the hand-substituted program are the same program.
  def test_ternary_arm_matches_manual_inline
    [true, false].each do |disable|
      assert_equal compile_script_hex(TERNARY_ARM_MANUAL_INLINE, disable),
                   compile_script_hex(TERNARY_ARM_PLUS_1, disable),
                   "helper-in-arm and hand-inlined source differ " \
                   "(disable_constant_folding=#{disable})"
    end
  end

  # The tier-independent oracle. No reference tier is consulted: a compiler that
  # emits the same bytes for `x + 1n` and `x + 2n` has dropped the callee body,
  # whatever its peers do.
  def test_callee_body_reaches_the_arm
    [true, false].each do |disable|
      refute_equal compile_script_hex(TERNARY_ARM_PLUS_1, disable),
                   compile_script_hex(TERNARY_ARM_PLUS_2, disable),
                   "two different helper bodies compiled to the same script " \
                   "(disable_constant_folding=#{disable})"
    end
  end
end
