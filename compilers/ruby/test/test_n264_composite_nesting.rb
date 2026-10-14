# frozen_string_literal: true

# N-264: call depth x nesting must not overflow the host stack.
#
# Private methods are inlined at every call site, so F-213's per-method nesting
# bound (128) and N-180's call-depth bound (128) compose multiplicatively: a
# chain of D helpers that each call the next under K nested ifs is D*K nested
# ifs after inlining. This tier raised SystemStackError at D=16 x 120 (stack
# lowering recursed once per nested if). User decision R106: lower
# iteratively, with an explicit work stack.
#
# The source is remediation-logs/N-180/compgen.py's shape. The pinned digests
# are sha256 of the script hex the UNMODIFIED Go compiler printed for the same
# source (at 5b75534ec, before any N-264 change): goroutine stacks grow, so Go
# compiled every depth, and its D=8 output was byte-identical to all six other
# tiers'.
#
# Proves: this tier compiles D=32 x 120 (3,840 nested ifs) and the deepest
# admissible chain D=127 x 120, byte-identical to Go.
# Does not prove: the other tiers (conformance/negatives/
# n264-composite-nesting-parity.test.ts drives all seven CLIs), nor that Go's
# deep output is right beyond agreeing with every tier at D=8.

require_relative 'test_helper'
require 'digest'
require 'tmpdir'

class N264CompositeNestingTest < Minitest::Test
  GO_DIGEST = {
    32 => 'edf53286692322f6787832929bb6aaf18d2b686e9bef2ad4683cbaf3e8a25fc2',
    127 => 'd1a30af5609fe4b5704c58f518cb9bdd1f31fce14df88c650dcf33fe25153c53'
  }.freeze

  # remediation-logs/N-180/compgen.py, verbatim.
  def comp(d, k)
    body = lambda do |i|
      s = +"  let r: bigint = x;\n"
      k.times { |j| s << "  if (x > #{j}n) {\n" }
      s << "  r = this.m#{i + 1}(x);\n" << ("  }\n" * k)
      s << "  return r;\n"
    end
    ms = (0...d).map { |i| " private m#{i}(x: bigint): bigint {\n#{body.call(i)} }\n" }.join
    "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n" \
      "#{ms} private m#{d}(x: bigint): bigint { return x; }\n public verify(a: bigint) { assert(this.m0(a) == this.t); }\n}\n"
  end

  def compile_digest(d)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "comp#{d}k120.runar.ts")
      File.write(path, comp(d, 120))
      Digest::SHA256.hexdigest(RunarCompiler.compile_from_source(path).script)
    end
  end

  def test_d32_x_120_compiles_byte_identical_to_go
    assert_equal GO_DIGEST[32], compile_digest(32)
  end

  def test_d127_x_120_compiles_byte_identical_to_go
    assert_equal GO_DIGEST[127], compile_digest(127)
  end
end
