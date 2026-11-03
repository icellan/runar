# frozen_string_literal: true

# N-007 — a method parameter that shadows a MUTABLE property must stay the
# parameter inside an `if` / ternary arm.
#
# Port of packages/runar-compiler/src/__tests__/n007-param-shadow-branch-arm.test.ts.
#
# Issue #130 (stack layer): deserialize_state pushes each mutable property
# under its own name, so LoweringContext#initialize renames a same-named method
# parameter's slot to `__param_<name>` and records it in @renamed_params;
# _lower_load_param resolves through that map.
#
# The defect: _lower_if built then_ctx / else_ctx with LoweringContext.new,
# whose @renamed_params starts EMPTY. The arm's cloned stack still carries the
# `__param_<name>` slot, so a load_param inside the arm resolved the bare name
# to the deserialized PROPERTY slot — the stale on-chain state — instead of the
# caller's witness argument:
#
#   public set(count: bigint, flag: boolean) {
#     if (flag) { assert(count == 5n); }     // arm read this.count (stale)
#     this.count = count;
#   }
#
# With on-chain count = 5, set(7n, true) passed a guard the source says must
# fail. Real-engine proof:
# packages/runar-testing/src/__tests__/n007-param-shadow-branch-arm-vm.test.ts.
#
# Oracle (needs no reference tier): a parameter's NAME is not part of the
# program, so alpha-renaming count -> newCount must give byte-identical script.
#
# Proves: Ruby resolves a shadowing parameter to the same slot inside an
# if-then arm, an if-else arm and a ternary arm as for a non-colliding name, in
# both fold modes. Does NOT prove: that the renamed program is itself correct
# on-chain (the VM test), or anything about other tiers.

require_relative "test_helper"
require "tmpdir"
require "runar_compiler/compiler"

class TestN007ParamShadowBranchArm < Minitest::Test
  PRELUDE = <<~SRC
    import { StatefulSmartContract, assert } from 'runar-lang';

    class Probe extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) { super(count); this.count = count; }

  SRC

  THEN_ARM = <<~SRC
      public set(count: bigint, flag: boolean) {
        if (flag) {
          assert(count == 5n);
        }
        this.count = count;
      }
    }
  SRC

  ELSE_ARM = <<~SRC
      public set(count: bigint, flag: boolean) {
        if (flag) {
          assert(flag);
        } else {
          assert(count > 10n);
        }
        this.count = count;
      }
    }
  SRC

  TERNARY_ARM = <<~SRC
      public set(count: bigint, flag: boolean) {
        const v: bigint = flag ? count + 1n : 0n;
        assert(v != 3n);
        this.count = count;
      }
    }
  SRC

  # Control: the parameter is read only OUTSIDE any arm (already correct before
  # the fix; pins that the oracle is not vacuous).
  NO_ARM = <<~SRC
      public set(count: bigint, flag: boolean) {
        assert(count != 3n);
        assert(flag);
        this.count = count;
      }
    }
  SRC

  CASES = [
    ["then-arm", THEN_ARM],
    ["else-arm", ELSE_ARM],
    ["ternary-arm", TERNARY_ARM],
    ["control/no-arm", NO_ARM]
  ].freeze

  def alpha_rename(body)
    body.sub("set(count: bigint", "set(newCount: bigint")
        .sub("this.count = count;", "this.count = newCount;")
        .sub("(count ", "(newCount ")
        .sub("? count ", "? newCount ")
  end

  def compile_script_hex(body, disable_constant_folding)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "Probe.runar.ts")
      File.write(path, PRELUDE + body)
      artifact = RunarCompiler.compile_from_source(
        path, disable_constant_folding: disable_constant_folding
      )
      artifact.script.downcase
    end
  end

  def test_shadowing_param_is_alpha_equivalent_in_branch_arm
    CASES.each do |label, body|
      renamed = alpha_rename(body)
      # The rename must actually have removed every read of the shadowing name.
      refute_match(/(?<![.\w])count\b/, renamed)
      [true, false].each do |disable|
        assert_equal compile_script_hex(renamed, disable), compile_script_hex(body, disable),
                     "#{label} (disable_constant_folding=#{disable}): a parameter that shadows " \
                     "mutable property 'count' compiled differently from the renamed program — " \
                     "the arm read the deserialized state slot, not the witness argument"
      end
    end
  end
end
