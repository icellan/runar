# frozen_string_literal: true

# N-087: load_ir enforces the source validator's parentClass rules and refuses
# a write to a readonly or undeclared property, with the diagnostics shared by
# all seven tiers (conformance/negatives/ir-parent-class-cases.json).
#
# Before: a SmartContract declaring `owner` with readonly:false (F-107's
# v2-mut-stateless) compiled to 76767b8777, which an attacker's key spends
# under strict @bsv/sdk Spend; a readonly write, stateful-only nodes in a
# non-stateful contract and raw_script outside UnsafeSmartContract compiled too.
#
# Proves: every corpus case is refused with its diagnostic and the accepted
# programs (incl. parentClass-less IR) load. Does not prove that a declared
# StatefulSmartContract body enforces its state continuation.

require_relative "test_helper"
require "json"
require "runar_compiler/ir/loader"

class TestN087IRParentClass < Minitest::Test
  CORPUS = JSON.parse(
    File.read(File.expand_path("../../../conformance/negatives/ir-parent-class-cases.json", __dir__))
  )

  def test_corpus_is_not_empty
    assert_operator CORPUS["cases"].length, :>=, 10
  end

  CORPUS["accept"].each do |a|
    define_method("test_accepts_#{a['name'].tr('-', '_')}") do
      RunarCompiler::IR.load_ir(JSON.generate(a["ir"]))
    end
  end

  CORPUS["cases"].each do |c|
    define_method("test_refuses_#{c['name'].tr('-', '_')}") do
      err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(JSON.generate(c["ir"])) }
      if c["match"] == "prefix"
        assert err.message.start_with?(c["error"]), err.message
      else
        assert_equal c["error"], err.message
      end
    end
  end
end
