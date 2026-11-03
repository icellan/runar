# frozen_string_literal: true

# N-202: the source path bounds the PRODUCT of nested loop counts, not just
# each loop's own count.
#
# _extract_loop_shape caps one for-loop at MAX_LOOP_COUNT (10,000). Two loops of
# 9,000, one inside the other, each passed that cap while the unrolled work was
# 81,000,000 iterations. F-283 refuses the same nest on the --ir path, so a
# source contract compiled while its own emitted IR was refused on replay.
#
# Proves: on the Ruby source path a 101 x 100 nest is refused with the shared
# product diagnostic, also when the inner loop sits in an if arm, and a nest of
# exactly 10,000 still compiles. Every compile runs in a child process behind a
# watchdog, so a regression fails instead of hanging.
# Does not prove: the other tiers (conformance/negatives/n202-nested-loop-
# product-parity.test.ts), or loops reached through a private method call that
# stack lowering inlines later -- the bound is per-method nesting in ANF, the
# same rule the --ir loader applies.

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class TestN202NestedLoopProduct < Minitest::Test
  WATCHDOG_SECONDS = 60

  LIB_DIR = File.expand_path('../lib', __dir__)

  PRODUCT_DIAG = 'For loop unrolls to 100 iterations nested inside an enclosing loop of total count 101, ' \
                 'producing 10100 total iterations, exceeding the maximum loop count of 10000.'

  CHILD_PROGRAM = <<~RUBY
    require 'json'
    require 'runar_compiler'
    begin
      artifact = RunarCompiler.compile_from_source(ARGV[0])
      print JSON.generate({ 'success' => true, 'error' => nil })
    rescue StandardError => e
      print JSON.generate({ 'success' => false, 'error' => e.message.to_s })
    end
  RUBY

  def nested_loop_source(outer, inner, in_if_arm: false)
    inner_loop = "for (let j = 0n; j < #{inner}n; j++) { acc = acc + x; }"
    inner_loop = "if (x > 0n) { #{inner_loop} }" if in_if_arm
    <<~TS
      import { SmartContract, assert } from 'runar-lang';

      export class NestedLoops extends SmartContract {
        constructor() { super(); }

        public unlock(x: bigint): void {
          let acc: bigint = 0n;
          for (let i = 0n; i < #{outer}n; i++) { #{inner_loop} }
          assert(acc > x);
        }
      }
    TS
  end

  def compile_in_child(source)
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'NestedLoops.runar.ts')
      File.write(path, source)

      Open3.popen3(RbConfig.ruby, '-I', LIB_DIR, '-e', CHILD_PROGRAM, path) do |stdin, stdout, stderr, wait_thr|
        stdin.close
        if wait_thr.join(WATCHDOG_SECONDS).nil?
          Process.kill('KILL', wait_thr.pid)
          wait_thr.join
          flunk "compile did not finish within #{WATCHDOG_SECONDS}s -- nested loops are being unrolled unbounded"
        end
        out = stdout.read
        err = stderr.read
        assert_equal 0, wait_thr.value.exitstatus,
                     "the child compile exited non-zero.\nstderr: #{err[-2000..] || err}"
        JSON.parse(out)
      end
    end
  end

  def test_nested_loop_product_over_max_is_rejected
    [false, true].each do |in_if_arm|
      outcome = compile_in_child(nested_loop_source(101, 100, in_if_arm: in_if_arm))
      refute outcome['success'], "in_if_arm=#{in_if_arm}: expected the 101 x 100 nest to be refused"
      assert_includes outcome['error'].to_s, PRODUCT_DIAG, "in_if_arm=#{in_if_arm}"
    end
  end

  def test_nested_loop_product_at_max_still_compiles
    outcome = compile_in_child(nested_loop_source(100, 100))
    assert outcome['success'], "expected the 100 x 100 nest to compile, got: #{outcome['error']}"
  end
end
