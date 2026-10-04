# frozen_string_literal: true

require_relative "../test_helper"
require "tempfile"

# ---------------------------------------------------------------------------
# F-097: a property initialized to `false` is still an initialized property.
#
# Stack lowering picked the constructor-param properties with
# `@properties.reject { |p| p.initial_value }`. In Ruby `false` is falsy, so a
# `= false` property was NOT rejected and was counted as a constructor
# parameter. Every uninitialized property declared after it got a placeholder
# param_index one too high, while the artifact ABI (which tests `nil?`) lists
# it at the right index. The SDK splices constructorArgs[slot.paramIndex], so
# the deployed script got the wrong (or a missing) constructor argument.
#
# What this proves: for a `false`-initialized property declared before the
# sole uninitialized property `key`, both a stateless and a stateful contract
# emit `key`'s constructor slot at param_index 0, which is the index of `key`
# in the ABI constructor params, matching the TS reference compiler.
#
# What this does not prove: anything about initializer values other than
# `false` (`0` and `""` are truthy in Ruby, so the old check already handled
# them; they are covered here only as a control), and nothing about on-chain
# execution -- the SDK-splice / Spend.validate evidence is in the F-097 report.
# ---------------------------------------------------------------------------
class TestF097FalseInitializerCtorSlot < Minitest::Test
  def compile_ts(source)
    tf = Tempfile.new(["F097", ".runar.ts"])
    tf.write(source)
    tf.close
    RunarCompiler.compile_from_source(tf.path, disable_constant_folding: true)
  ensure
    tf&.unlink
  end

  def stateless_source(type, init)
    <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class F097 extends SmartContract {
        readonly flag: #{type} = #{init};
        readonly key: bigint;

        constructor(key: bigint) {
          super(key);
          this.key = key;
        }

        public unlock(x: bigint) {
          assert(x == this.key);
          assert(this.flag == #{init});
        }
      }
    TS
  end

  def assert_key_slot_matches_abi(art)
    abi_names = art.abi.constructor.params.map(&:name)
    assert_equal ["key"], abi_names
    slots = art.constructor_slots.map { |s| [s.param_index, s.byte_offset] }
    refute_empty slots
    slots.each do |idx, _offset|
      assert_equal 0, idx,
                   "key placeholder must use ABI constructor param index 0, got slots #{slots.inspect}"
    end
  end

  def test_stateless_false_initializer_is_not_a_ctor_param
    assert_key_slot_matches_abi(compile_ts(stateless_source("boolean", "false")))
  end

  def test_stateful_false_initializer_is_not_a_ctor_param
    art = compile_ts(<<~TS)
      import { StatefulSmartContract, assert } from 'runar-lang';

      class F097S extends StatefulSmartContract {
        enabled: boolean = false;
        readonly key: bigint;

        constructor(key: bigint) {
          super(key);
          this.key = key;
        }

        public unlock(x: bigint) {
          assert(x == this.key);
          this.enabled = true;
        }
      }
    TS
    assert_key_slot_matches_abi(art)
  end

  # Controls: these initializers are truthy in Ruby and must stay correct.
  def test_zero_initializer_is_not_a_ctor_param
    assert_key_slot_matches_abi(compile_ts(stateless_source("bigint", "0n")))
  end

  def test_true_initializer_is_not_a_ctor_param
    assert_key_slot_matches_abi(compile_ts(stateless_source("boolean", "true")))
  end
end
