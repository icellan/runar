# frozen_string_literal: true

# Regression test (N-024): the branch-lift must remap a reassigned LOCAL
# variable's own alias when hoisting a branch into a flat conditional.
#
# `_lift_branch_update_props` flattens
#
#   let x = n;
#   if (flag > 0n) { x = x + 1n; this.count = this.count + x; }
#   else { this.count = this.count - 1n; }
#
# into one single-valued `if` per property plus a top-level `update_prop`,
# copying each arm's non-`update_prop` bindings under FRESH names via
# `_remap_value_refs`. `x = x + 1n` lowers to a `load_const` binding named
# literally `x` whose value is the alias string `"@ref:<pre-lift temp>"`.
# `_remap_value_refs`'s `load_const` case checked `value.raw_value` for the
# `"@ref:"` prefix, but `raw_value` is the JSON-ENCODED form (quote marks
# included) for every freshly-constructed `load_const`, so the prefix check
# never matched and the alias was copied into the lifted arm UNCHANGED --
# still pointing at the pre-lift temp name, which no longer exists after the
# lift renumbers everything. Stack lowering then rejected the dangling
# reference: "value 't15' referenced by 't44' is not on the stack".
#
# TS (and the other five tiers) accept this shape; Ruby refused it -- a
# frontend parity break, not a language restriction.
#
# The compiler is invoked via subprocess for the same reason as
# test_branch_lift_then_arm.rb: the Ruby compiler's TS and Ruby parsers share
# a constant namespace, so running them in-process corrupts tokenization.

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class BranchLiftReassignedLocalTest < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby')

  REASSIGNED_LOCAL_COND = <<~TS
    class ReassignedLocalCond extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      public bump(flag: bigint, n: bigint) {
        let x = n;
        if (flag > 0n) {
          x = x + 1n;
          this.count = this.count + x;
        } else {
          this.count = this.count - 1n;
        }
        this.addOutput(1000n, this.count);
      }
    }
  TS

  def compile_hex(source, file_name, disable_constant_folding: true)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)

      args = ['--source', path, '--hex']
      args << '--disable-constant-folding' if disable_constant_folding
      Open3.capture3(RbConfig.ruby, RUBY_CLI, *args)
    end
  end

  def test_reassigned_local_referenced_by_branch_update_compiles_fold_off
    stdout, stderr, status = compile_hex(REASSIGNED_LOCAL_COND, 'ReassignedLocalCond.runar.ts',
                                          disable_constant_folding: true)

    # What this proves: a `let`-local reassigned INSIDE one arm of a 2-branch
    # if/else, then read by that SAME arm's final property update, survives
    # the branch-update-props lift without leaving a dangling pre-lift temp
    # reference. Before the fix this failed every time (not flaky) with
    # "Stack lowering: value 't15' referenced by 't44' is not on the stack".
    #
    # What it does NOT prove: that the emitted hex matches the other six
    # tiers byte for byte (checked separately, out of band, against the
    # TS/Go/Rust/Python/Zig/Java CLIs for this exact fixture during
    # remediation -- all seven agreed in both fold modes) or that the
    # compiled script executes correctly on a real VM/chain. It only proves
    # the compiler accepts the shape and emits a non-empty script.
    assert status.success?, "compiler exited #{status.exitstatus}: #{stderr}"
    refute_empty stdout.strip, 'expected non-empty compiled hex'
  end

  def test_reassigned_local_referenced_by_branch_update_compiles_fold_on
    stdout, stderr, status = compile_hex(REASSIGNED_LOCAL_COND, 'ReassignedLocalCond.runar.ts',
                                          disable_constant_folding: false)

    assert status.success?, "compiler exited #{status.exitstatus}: #{stderr}"
    refute_empty stdout.strip, 'expected non-empty compiled hex'
  end
end
