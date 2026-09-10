# frozen_string_literal: true

# Regression test: the branch-lift must not zero the matched arm.
#
# `_lift_branch_update_props` flattens a dispatch chain
#
#   if (p == 0n) { this.c0 = v; } else if (p == 1n) { this.c1 = v; }
#   else { assert(false); }
#
# into one single-valued `if` per property plus a top-level `update_prop`. The
# `if`'s then-arm must evaluate to the assigned value and its else-arm to the
# property's old value.
#
# The defect: the then-arm was built from `branch[:value_bindings]` — everything
# BEFORE the `update_prop` in the original arm. That ends on the assigned value
# only when the value was computed INSIDE the arm. When the arm assigns
# something bound outside it, `value_bindings` is empty, the arm was emitted
# EMPTY, and stack lowering padded it with a zero push
# (OP_IF OP_0 OP_ELSE OP_DUP OP_ENDIF): the MATCHED branch wrote 0.
#
# `examples/ts/tic-tac-toe` escapes it only because `this.cN = this.turn` puts a
# load_prop inside the arm — that shape is the control below.
#
# The compiler is invoked via subprocess for the same reason as
# test_conformance_goldens.rb: the Ruby compiler's TS and Ruby parsers share a
# constant namespace, so running them in-process corrupts tokenization.

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class BranchLiftThenArmTest < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby')

  LOCAL_VALUE_DISPATCH = <<~TS
    class LocalValueDispatch extends StatefulSmartContract {
      c0: bigint;
      c1: bigint;

      constructor(c0: bigint, c1: bigint) {
        super(c0, c1);
        this.c0 = c0;
        this.c1 = c1;
      }

      public poke(position: bigint, value: bigint) {
        const doubled: bigint = value + value;
        if (position == 0n) { this.c0 = doubled; }
        else if (position == 1n) { this.c1 = doubled; }
        else { assert(false); }
      }
    }
  TS

  IN_ARM_VALUE_DISPATCH = <<~TS
    class InArmValueDispatch extends StatefulSmartContract {
      c0: bigint;
      c1: bigint;
      turn: bigint;

      constructor(c0: bigint, c1: bigint, turn: bigint) {
        super(c0, c1, turn);
        this.c0 = c0;
        this.c1 = c1;
        this.turn = turn;
      }

      public poke(position: bigint) {
        if (position == 0n) { this.c0 = this.turn; }
        else if (position == 1n) { this.c1 = this.turn; }
        else { assert(false); }
      }
    }
  TS

  # Every top-level update_prop whose value is an `if` binding, paired with that
  # `if`'s two arms. Returns [prop_name, then_bindings, else_bindings] triples.
  def lifted_assignments(source, file_name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)

      stdout, stderr, status = Open3.capture3(
        RbConfig.ruby, RUBY_CLI,
        '--source', path, '--emit-ir', '--disable-constant-folding'
      )
      assert status.success?, "compiler exited #{status.exitstatus}: #{stderr}"

      ir = JSON.parse(stdout)
      method = ir['methods'].find { |m| m['name'] == 'poke' }
      refute_nil method, 'method poke not found in lowered program'

      by_name = method['body'].each_with_object({}) { |b, h| h[b['name']] = b['value'] }

      method['body'].filter_map do |b|
        next unless b['value']['kind'] == 'update_prop'

        producer = by_name[b['value']['value']]
        next unless producer && producer['kind'] == 'if'

        [b['value']['name'], producer['then'] || [], producer['else'] || []]
      end
    end
  end

  def test_then_arm_carries_value_bound_outside_the_arm
    lifted = lifted_assignments(LOCAL_VALUE_DISPATCH, 'LocalValueDispatch.runar.ts')

    # Both properties in the chain must be lifted. If this is 0 the pass has
    # stopped recognising the shape and the arm assertions below would pass
    # vacuously.
    assert_equal 2, lifted.length, 'expected 2 lifted conditional assignments'

    lifted.each do |prop, then_arm, else_arm|
      refute_empty then_arm,
                   "then-arm for this.#{prop} is empty; stack lowering pads it with OP_0, " \
                   'so the MATCHED branch writes zero instead of the assigned value'
      last = then_arm.last
      assert_equal 'load_const', last['value']['kind'],
                   "then-arm for this.#{prop} must end on the assigned local"
      assert_equal '@ref:doubled', last['value']['value'],
                   "then-arm for this.#{prop} must end on the assigned local"
      refute_empty else_arm, "else-arm for this.#{prop} is empty"
    end
  end

  # Control: the TicTacToe shape already computed its value inside the arm and
  # was always correct. The fix must add nothing here — a second binding would
  # move the checked-in goldens.
  def test_in_arm_value_shape_is_unchanged
    lifted = lifted_assignments(IN_ARM_VALUE_DISPATCH, 'InArmValueDispatch.runar.ts')

    assert_equal 2, lifted.length, 'expected 2 lifted conditional assignments'
    lifted.each do |prop, then_arm, _else_arm|
      assert_equal 1, then_arm.length,
                   "then-arm for this.#{prop} should hold exactly the in-arm load_prop"
      assert_equal 'load_prop', then_arm[0]['value']['kind'],
                   "then-arm for this.#{prop} should be load_prop turn"
      assert_equal 'turn', then_arm[0]['value']['name'],
                   "then-arm for this.#{prop} should be load_prop turn"
    end
  end
end
