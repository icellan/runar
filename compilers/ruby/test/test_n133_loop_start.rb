# frozen_string_literal: true

# N-133 — +loop.start+ on the +--ir+ trust boundary.
#
# +Loop.start+ is +integer | string+, and the string arm is the sanctioned
# +"<decimal>n"+ form — the suffix is REQUIRED, which is what Java's loader
# implements and what the schema's other two string-carrying integer fields
# (+load_const.value+, +ANFProperty.initialValue+) mean by a string.
#
# +_decode_loop_start+ ended in a bare +0+. Every shape it could not read —
# "abc", "", "5nn", a boolean, a null — became a zero-start loop that compiled
# and exited 0. It also read an unsuffixed "5" as 5, which Rust read as 0: two
# tiers, two different loops, neither of them complaining.
#
# 0 is what makes this invisible. It is a perfectly plausible loop start, and
# the commonest one, so the wrong program compiles and nothing looks wrong.
#
# The probe is a two-iteration loop summing its iterator, so the start lands in
# the emitted bytes and nothing else does.

require_relative 'test_helper'

class TestN133LoopStart < Minitest::Test
  def ir(start_json)
    <<~JSON
      {
        "contractName": "LoopProbe",
        "properties": [{"name": "target", "type": "bigint", "readonly": true}],
        "methods": [
          {"name": "constructor", "params": [], "isPublic": false,
           "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
          {"name": "run", "params": [], "isPublic": true,
           "body": [
             {"name": "acc", "value": {"kind": "load_const", "value": 0}},
             {"name": "t1", "value": {"kind": "loop", "count": 2, "iterVar": "i",
               "start": #{start_json}, "step": 1,
               "body": [{"name": "acc", "value": {"kind": "bin_op", "left": "acc", "op": "+", "right": "i"}}]}},
             {"name": "t2", "value": {"kind": "load_prop", "name": "target"}},
             {"name": "t3", "value": {"kind": "bin_op", "left": "acc", "op": "===", "right": "t2"}},
             {"name": "t4", "value": {"kind": "assert", "value": "t3"}}
           ]}
        ]
      }
    JSON
  end

  def script_hex(start_json)
    RunarCompiler.compile_from_ir_bytes(ir(start_json)).script
  end

  # Both cases non-zero: 0 is what every fallback path also produces.
  def test_decimal_bigint_string_start_means_the_integer
    [['"5n"', '5', '5b009c'], ['"-3n"', '-3', '0185009c']].each do |str, int, want|
      assert_equal script_hex(int), script_hex(str), "start #{str} must equal start #{int}"
      assert_equal want, script_hex(str)
    end
  end

  # Ruby Integer is arbitrary-precision, so this tier carries the value.
  def test_over_int64_start_is_not_truncated
    assert_equal '0dffffff7fd4dbe98ca039593e19009c',
                 script_hex('"999999999999999999999999999999n"')
  end

  def test_unreadable_start_is_refused
    ['"5"', '"abc"', '""', '"5nn"', '"n"', '"-n"', '"1.5n"', 'true', 'null'].each do |bad|
      assert_raises(StandardError, "loop.start #{bad} must be refused") do
        RunarCompiler.compile_from_ir_bytes(ir(bad))
      end
    end
  end

  # The bytes every fallback-to-zero lands on. If the probe could not tell
  # start 0 from start 5 apart, none of the rows above would mean anything.
  def test_zero_start_is_its_own_script
    assert_equal '008b009c', script_hex('0')
    refute_equal script_hex('5'), script_hex('0')
  end
end
