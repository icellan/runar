# frozen_string_literal: true

# N-265 -- the --ir path bypasses N-180's MAX_CALL_DEPTH bound, and (outside
# Go's F-071, which was cycle-only) the recursion check entirely.
#
# load_ir never ran frontend/validator.rb's recursion/call-depth check (that
# only runs on the source path); validate_ir had no equivalent of its own.
# Stack lowering (codegen/stack.rb's method_call inlining) inlines every
# method_call to a private method by lowering its body in place, with no
# cycle or depth guard, so a self/mutually-recursive method recurses the
# host call stack until a SystemStackError, and an acyclic chain past
# MAX_CALL_DEPTH recurses it just as deep.
#
# Proves: load_ir now refuses a chain one past MAX_CALL_DEPTH, naming the
# first offending method in declaration order with the shared diagnostic,
# accepts a chain right at the bound, refuses a 20000-link chain promptly
# (no SystemStackError, no multi-second hang), and refuses a direct/mutual
# cycle with the shared recursion wording.
#
# Does not prove: that the other six tiers' --ir loaders agree
# (conformance/negatives/n265-ir-call-depth-parity.test.ts does); call
# graphs other than a chain or a 2/3-node cycle; or that 128 is the right
# number (N-180 already measured that).

require_relative "test_helper"
require "json"
require "runar_compiler/ir/loader"
require "runar_compiler/frontend/input_limits"

class TestN265IRCallDepth < Minitest::Test
  MAX_CALL_DEPTH = RunarCompiler::Frontend::InputLimits::MAX_CALL_DEPTH

  # verify(a) calls m0(a); m_i calls m_{i+1} for i < n; m_{n-1} returns its
  # argument unchanged. Declaration order is m0..m(n-1) THEN verify, matching
  # N-180's own chain fixture: at n=MAX_CALL_DEPTH only `verify` exceeds the
  # bound, but at n=20000 `m0` is declared first and already exceeds it.
  def chain_ir(n)
    methods = (0...n).map do |i|
      body = if i == n - 1
               [{ "name" => "t0", "value" => { "kind" => "load_param", "name" => "x" } }]
             else
               [
                 { "name" => "t0", "value" => { "kind" => "load_const", "value" => "@this" } },
                 { "name" => "t1", "value" => { "kind" => "load_param", "name" => "x" } },
                 { "name" => "t2", "value" => { "kind" => "method_call", "object" => "t0", "method" => "m#{i + 1}", "args" => ["t1"] } },
               ]
             end
      { "name" => "m#{i}", "isPublic" => false, "params" => [{ "name" => "x", "type" => "bigint" }], "body" => body }
    end
    methods << {
      "name" => "verify",
      "isPublic" => true,
      "params" => [{ "name" => "a", "type" => "bigint" }],
      "body" => [
        { "name" => "t0", "value" => { "kind" => "load_const", "value" => "@this" } },
        { "name" => "t1", "value" => { "kind" => "load_param", "name" => "a" } },
        { "name" => "t2", "value" => { "kind" => "method_call", "object" => "t0", "method" => "m0", "args" => ["t1"] } },
        { "name" => "t3", "value" => { "kind" => "load_const", "value" => 0 } },
        { "name" => "t4", "value" => { "kind" => "bin_op", "op" => ">=", "left" => "t2", "right" => "t3" } },
        { "name" => "t5", "value" => { "kind" => "assert", "value" => "t4" } },
      ],
    }
    JSON.generate({ "contractName" => "Chain", "properties" => [], "methods" => methods })
  end

  # unlock(x) calls private p(x); each [name, callee] is either a terminal
  # (callee nil, returns x) or forwards to callee.
  def cycle_ir(private_methods)
    methods = [{
      "name" => "unlock",
      "isPublic" => true,
      "params" => [{ "name" => "x", "type" => "bigint" }],
      "body" => [
        { "name" => "t0", "value" => { "kind" => "load_const", "value" => "@this" } },
        { "name" => "t1", "value" => { "kind" => "load_param", "name" => "x" } },
        { "name" => "t2", "value" => { "kind" => "method_call", "object" => "t0", "method" => "p", "args" => ["t1"] } },
        { "name" => "t3", "value" => { "kind" => "load_const", "value" => 0 } },
        { "name" => "t4", "value" => { "kind" => "bin_op", "op" => ">=", "left" => "t2", "right" => "t3" } },
        { "name" => "t5", "value" => { "kind" => "assert", "value" => "t4" } },
      ],
    }]
    private_methods.each do |name, callee|
      body = if callee.nil?
               [{ "name" => "t0", "value" => { "kind" => "load_param", "name" => "x" } }]
             else
               [
                 { "name" => "t0", "value" => { "kind" => "load_const", "value" => "@this" } },
                 { "name" => "t1", "value" => { "kind" => "load_param", "name" => "x" } },
                 { "name" => "t2", "value" => { "kind" => "method_call", "object" => "t0", "method" => callee, "args" => ["t1"] } },
               ]
             end
      methods << { "name" => name, "isPublic" => false, "params" => [{ "name" => "x", "type" => "bigint" }], "body" => body }
    end
    JSON.generate({ "contractName" => "Rec", "properties" => [], "methods" => methods })
  end

  def test_chain_at_max_call_depth_loads
    RunarCompiler::IR.load_ir(chain_ir(MAX_CALL_DEPTH))
  end

  def test_chain_one_past_max_call_depth_refused
    err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(chain_ir(MAX_CALL_DEPTH + 1)) }
    assert_includes err.message, "call depth of method 'verify' exceeds MAX_CALL_DEPTH (limit=#{MAX_CALL_DEPTH})"
  end

  def test_20000_link_chain_refused_promptly
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(chain_ir(20000)) }
    assert_includes err.message, "call depth of method 'm0' exceeds MAX_CALL_DEPTH (limit=#{MAX_CALL_DEPTH})"
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
    assert_operator elapsed, :<, 10, "refusal took too long: #{elapsed}s"
  end

  def test_direct_self_recursion_refused
    err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(cycle_ir([["p", "p"]])) }
    assert_includes err.message, "recursion detected"
    assert_includes err.message, "calls itself directly or indirectly"
    assert_includes err.message, "method 'p'"
  end

  def test_mutual_recursion_refused
    err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(cycle_ir([["p", "q"], ["q", "p"]])) }
    assert_includes err.message, "recursion detected"
    assert(err.message.include?("method 'p'") || err.message.include?("method 'q'"))
  end

  def test_non_recursive_chain_still_loads
    RunarCompiler::IR.load_ir(cycle_ir([["p", "q"], ["q", "r"], ["r", nil]]))
  end
end
