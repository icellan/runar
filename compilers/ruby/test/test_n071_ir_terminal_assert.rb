# frozen_string_literal: true

# N-071: load_ir refuses a public method that does not END with an assert,
# with the diagnostic shared verbatim by all seven tiers.
#
# Before: `"body": []` compiled to an EMPTY (anyone-can-spend) locking script
# at exit 0, and an `if` whose else arm ended in `load_const true` compiled to
# a script an empty signature spends.
#
# Proves: every case in the shared corpus
# (conformance/negatives/ir-terminal-assert-cases.json) is refused with the
# exact diagnostic, and the accepted programs (a P2PK control, a both-arm
# `if`) load. Does not prove: that an accepted program is secure -- ending in
# an assert is necessary, not sufficient.

require_relative "test_helper"
require "json"
require "runar_compiler/ir/loader"

class TestN071IRTerminalAssert < Minitest::Test
  CORPUS = JSON.parse(
    File.read(File.expand_path("../../../conformance/negatives/ir-terminal-assert-cases.json", __dir__))
  )

  def test_corpus_is_not_empty
    assert_operator CORPUS["cases"].length, :>=, 5
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
