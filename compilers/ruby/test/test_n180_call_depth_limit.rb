# frozen_string_literal: true

# N-180: the shared call-depth limit, MAX_CALL_DEPTH = 128.
#
# A chain of private helpers verify -> m0 -> m1 -> ... -> mN is flat source
# (MAX_SOURCE_NESTING never fires) but N+1 nested inlinings. Before N-180 this
# tier raised an uncaught SystemStackError from its recursion check at 2000
# links, and that check restarted its DFS from every method (quadratic).
#
# Proves, on the .ts, .sol (bare `m(x)` calls) and .rb surfaces: the chain at
# the limit (N=127, verify at depth 128) passes validation; one past (N=128) is
# refused with the shared diagnostic naming `verify`; N=20000 is refused naming
# `m0`, promptly, with no SystemStackError; and a cycle is still the recursion
# diagnostic, once per method that reaches it.
#
# Does not prove: that the other surfaces agree, or that the accepted chain
# compiles to the TS bytes (conformance/negatives/n180-call-depth-parity.test.ts
# drives every CLI on all nine surfaces), nor anything about the --ir JSON path.

require_relative 'test_helper'
require 'runar_compiler/frontend/input_limits'

class N180CallDepthLimitTest < Minitest::Test
  def diag(m)
    "call depth of method '#{m}' exceeds MAX_CALL_DEPTH (limit=128)"
  end

  def chain(ext, n)
    case ext
    when 'ts'
      "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n" +
        (0...n).map { |i| " private m#{i}(x: bigint): bigint { return this.m#{i + 1}(x); }\n" }.join +
        " private m#{n}(x: bigint): bigint { return x; }\n public verify(a: bigint) { assert(this.m0(a) == this.t); }\n}\n"
    when 'sol'
      "pragma runar ^0.1.0;\ncontract P is SmartContract {\n int immutable t;\n constructor(int _t) { t = _t; }\n" +
        (0...n).map { |i| " function m#{i}(int x) private returns (int) { return m#{i + 1}(x); }\n" }.join +
        " function m#{n}(int x) private returns (int) { return x; }\n function verify(int a) public { require(m0(a) == t); }\n}\n"
    when 'rb'
      "require 'runar'\n\nclass P < Runar::SmartContract\n  prop :t, Bigint\n\n  def initialize(t)\n    super(t)\n    @t = t\n  end\n\n" +
        (0...n).map { |i| "  params x: Bigint\n  def m#{i}(x)\n    m#{i + 1}(x)\n  end\n" }.join +
        "  params x: Bigint\n  def m#{n}(x)\n    x\n  end\n\n  runar_public a: Bigint\n  def verify(a)\n    assert m0(a) == @t\n  end\nend\n"
    end
  end

  def errors_of(src, file)
    parsed = RunarCompiler.send(:_parse_source, src, file)
    refute_nil parsed.contract, parsed.errors.map(&:message).inspect
    RunarCompiler.send(:_validate, parsed.contract).errors.map(&:message)
  end

  def test_max_call_depth_is_128
    assert_equal 128, RunarCompiler::Frontend::InputLimits::MAX_CALL_DEPTH
  end

  %w[ts sol rb].each do |ext|
    define_method("test_chain_boundary_#{ext}") do
      file = "P.runar.#{ext}"
      assert_equal [], errors_of(chain(ext, 127), file)
      assert_equal [diag('verify')], errors_of(chain(ext, 128), file)
    end

    define_method("test_chain_of_20000_is_refused_promptly_#{ext}") do
      src = chain(ext, 20_000)
      start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      errs = errors_of(src, "P.runar.#{ext}")
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
      assert_equal [diag('m0')], errs
      assert_operator elapsed, :<, 60, 'quadratic call-graph walk?'
    end
  end

  def test_cycle_is_still_reported_as_recursion
    src = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n" \
          " private a(x: bigint): bigint { return this.b(x); }\n" \
          " private b(x: bigint): bigint { return this.c(x); }\n" \
          " private c(x: bigint): bigint { return this.b(x); }\n" \
          " private d(x: bigint): bigint { return x; }\n" \
          " public verify(v: bigint) { assert(this.a(v) + this.d(v) == this.t); }\n}\n"
    want = %w[a b c verify].map { |m| "recursion detected: method '#{m}' calls itself directly or indirectly" }
    assert_equal want, errors_of(src, 'P.runar.ts')
  end
end
