# frozen_string_literal: true

# N-101: load_ir refuses a StatefulSmartContract program (declared, or inferred
# per N-087) any of whose public methods lacks, reorders or alters the
# scaffolding ANF lowering injects (auto-injected parameters, the checkPreimage
# / sighash / deserialize_state prologue, the state continuation), with the
# diagnostics shared by all seven tiers
# (conformance/negatives/ir-stateful-scaffold-cases.json).
#
# Before: F-107's attack body relabelled StatefulSmartContract compiled to
# 76767b8777, which an attacker's key spends under strict @bsv/sdk Spend, and
# so did the parentClass-less variant carrying a dead add_data_output.
#
# Proves: every corpus case is refused with its exact diagnostic and the
# accepted programs (incl. unmodified stateful goldens) load. Does not prove
# cross-tier agreement (conformance/negatives/ir-stateful-scaffold.test.ts
# does) or anything about the free user code between prologue and continuation.

require_relative "test_helper"
require "json"
require "runar_compiler/ir/loader"

class TestN101IRStatefulScaffold < Minitest::Test
  CORPUS = JSON.parse(
    File.read(File.expand_path("../../../conformance/negatives/ir-stateful-scaffold-cases.json", __dir__))
  )

  def test_corpus_is_not_empty
    assert_operator CORPUS["cases"].length, :>=, 10
    assert_operator CORPUS["accept"].length, :>=, 3
  end

  CORPUS["accept"].each do |a|
    define_method("test_accepts_#{a['name'].tr('-', '_')}") do
      RunarCompiler::IR.load_ir(JSON.generate(a["ir"]))
    end
  end

  CORPUS["cases"].each do |c|
    define_method("test_refuses_#{c['name'].tr('-', '_')}") do
      err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(JSON.generate(c["ir"])) }
      assert_equal c["error"], err.message
    end
  end
end
