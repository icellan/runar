# frozen_string_literal: true

# N-096: the IR loader refuses a syntheticArrayChain the expand-fixed-arrays
# pass could not have written, with the diagnostic shared by all 7 tiers
# (conformance/negatives/ir-synthetic-array-chain.test.ts holds the corpus).
#
# Before the rule this tier refused the F-105 probe only at the artifact
# regrouper's iteration cap, in words no other tier used.
#
# Proves: the probe is refused at load time with the shared words, and the
# FixedArray goldens still load. Does not prove the rest of the rule, which
# the conformance corpus covers in every tier.

require_relative "test_helper"
require "json"
require "runar_compiler/ir/loader"

class TestN096SyntheticArrayChainIR < Minitest::Test
  REPO_ROOT = File.expand_path("../../..", __dir__)

  def golden(fixture)
    JSON.parse(File.read(File.join(REPO_ROOT, "conformance", "tests", fixture, "expected-ir.json")))
  end

  def test_f105_probe_is_refused_with_the_shared_diagnostic
    ir = golden("basic-p2pkh")
    ir["properties"].insert(1, {
      "name" => "deep", "type" => "bigint", "readonly" => true,
      "syntheticArrayChain" => Array.new(1100) { { "base" => "deep", "index" => 0, "length" => 1 } }
    })
    err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(JSON.generate(ir)) }
    assert_equal "IR validation: malformed syntheticArrayChain on property 'deep': " \
                 "1100 levels exceed the limit of 1023", err.message
  end

  def test_fixed_array_goldens_still_load
    %w[fixed-array-index fixed-array-write].each do |f|
      RunarCompiler::IR.load_ir(JSON.generate(golden(f)))
    end
  end
end
