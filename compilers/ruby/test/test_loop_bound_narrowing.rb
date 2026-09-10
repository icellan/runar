# frozen_string_literal: true

# Regression tests for CL-BUG-088 / R-009: nothing bounded the magnitude of an
# unrolled loop's iteration count on the SOURCE path, in any tier.
#
# This tier does no narrowing at all — Ruby Integers are arbitrary precision, so
# `[0, count].max` faithfully preserves a bound of 10**20 and hands it to the
# unroller, which then tries to honour it. Reproduced at HEAD: bounds of 2^63
# and 2^64+10 both run past a 20-second wall clock with no diagnostic and no end
# in sight. The absence of a truncation bug is exactly what makes this tier hang
# instead of silently emitting the wrong script.
#
# The ceiling half of the contract: MAX_LOOP_COUNT (10000) lived in
# RunarCompiler::IR but was checked only against ANF IR arriving pre-built on
# the `--ir` path. A loop written in source could ask for any count; 10001
# compiled happily.
#
# What these tests pin: an over-ceiling loop bound is a compile-time diagnostic,
# and a valid loop still compiles to the exact bytes it produced before the
# guard existed.

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class TestLoopBoundNarrowing < Minitest::Test
  # Watchdog for a single compile, in seconds. The compile is CPU-bound and
  # synchronous; nothing inside this process can interrupt it, which is why the
  # out-of-range cases run as their own process (the Ruby analogue of the Go
  # tier's goroutine-behind-a-watchdog in bigint_narrowing_guard_test.go).
  WATCHDOG_SECONDS = 30

  LIB_DIR = File.expand_path('../lib', __dir__)

  def loop_bound_source(bound)
    <<~TS
      import { SmartContract, assert } from 'runar-lang';

      export class LoopBound extends SmartContract {
        constructor() { super(); }

        public unlock(x: bigint): void {
          let acc: bigint = 0n;
          for (let i = 0n; i < #{bound}n; i++) {
            acc = acc + i;
          }
          assert(acc === x);
        }
      }
    TS
  end

  CHILD_PROGRAM = <<~RUBY
    require 'json'
    require 'runar_compiler'
    begin
      artifact = RunarCompiler.compile_from_source(ARGV[0])
      print JSON.generate({ 'success' => true, 'script' => artifact.script, 'error' => nil })
    rescue StandardError => e
      print JSON.generate({ 'success' => false, 'script' => nil, 'error' => e.message.to_s })
    end
  RUBY

  # Compile the given bound in a child process behind a hard timeout.
  def compile_in_child(bound)
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'LoopBound.runar.ts')
      File.write(path, loop_bound_source(bound))

      Open3.popen3(RbConfig.ruby, '-I', LIB_DIR, '-e', CHILD_PROGRAM, path) do |stdin, stdout, stderr, wait_thr|
        stdin.close
        if wait_thr.join(WATCHDOG_SECONDS).nil?
          Process.kill('KILL', wait_thr.pid)
          wait_thr.join
          flunk "bound #{bound} did not produce a diagnostic within #{WATCHDOG_SECONDS}s — " \
                'the unbounded count is still driving loop unrolling'
        end
        out = stdout.read
        err = stderr.read
        assert_equal 0, wait_thr.value.exitstatus,
                     "bound #{bound}: the child compile exited non-zero instead of " \
                     "reporting a diagnostic.\nstderr: #{err[-2000..] || err}"
        JSON.parse(out)
      end
    end
  end

  def assert_rejected(outcome, label)
    refute outcome['success'],
           "bound #{label}: expected a compile diagnostic, got a successful compile " \
           "(script #{outcome['script']})"
    assert_includes outcome['error'].to_s.downcase, 'loop',
                    "bound #{label}: expected a diagnostic mentioning the loop bound, " \
                    "got: #{outcome['error']}"
  end

  # Control: a normal small bound must keep compiling, and to the exact bytes it
  # produced before the ceiling was added. If a guard moves these, the guard is
  # not byte-neutral and the change is a codegen regression, not a fix.
  def test_control_still_compiles_byte_identically
    { '3' => '537c9c', '10' => '012d7c9c' }.each do |bound, hex|
      [false, true].each do |disable_folding|
        Dir.mktmpdir do |dir|
          path = File.join(dir, 'LoopBound.runar.ts')
          File.write(path, loop_bound_source(bound))
          artifact = RunarCompiler.compile_from_source(path, disable_constant_folding: disable_folding)
          assert_equal hex, artifact.script,
                       "bound=#{bound} foldOff=#{disable_folding}: script hex changed"
        end
      end
    end
  end

  def test_bound_2_pow_63_is_rejected_without_hanging
    assert_rejected(compile_in_child('9223372036854775808'), '2^63')
  end

  def test_bound_2_pow_64_plus_10_is_rejected_without_hanging
    outcome = compile_in_child('18446744073709551626')
    assert_rejected(outcome, '2^64+10')
    # Belt and braces: whatever happens, it must not silently agree with the
    # `i < 10n` contract the way the modular-wrap tiers did.
    refute_equal '012d7c9c', outcome['script']
  end

  def test_bound_10_pow_20_is_rejected_without_hanging
    assert_rejected(compile_in_child('100000000000000000000'), '10^20')
  end

  # The ceiling half of the fix: MAX_LOOP_COUNT must apply to a loop written in
  # source, not only to ANF IR arriving pre-built.
  def test_bound_exceeding_max_loop_count_is_rejected_on_source_path
    outcome = compile_in_child('10001')
    assert_rejected(outcome, '10001')
    assert_includes outcome['error'].to_s, '10000',
                    "expected the diagnostic to name the maximum loop count, got: #{outcome['error']}"
  end
end
