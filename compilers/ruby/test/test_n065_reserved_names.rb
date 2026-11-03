# frozen_string_literal: true

# N-065 / N-060: a user identifier spelled like a name a compiler pass mints
# is refused, with one diagnostic shared verbatim by all seven tiers.
#
# Before: `let t2: bigint = p; ... if (c) { t2 = p; } assert(t2 + 1n === 1n);`
# compiled to a script that accepts p = 1, c = false (the guard read the ANF
# temp t2, not the local), and --ir accepted parameters, properties, bindings
# and references named after stack lowering's own slots.
#
# Proves: every source case in the shared corpus
# (conformance/negatives/reserved-names-cases.json) is refused by the Ruby
# validator with the exact shared sentence while its renamed twin compiles;
# a stateless contract's own txPreimage parameter compiles; every --ir case is
# refused by load_ir and the accepted IR (ANF temps and __merge$ as binding
# names, txPreimage as a parameter) compiles to 00ac. Does not prove: other
# tiers or on-chain behaviour (conformance/negatives/reserved-names.test.ts).

require_relative "test_helper"
require "json"
require "tmpdir"
require "runar_compiler/compiler"
require "runar_compiler/ir/loader"

class TestN065ReservedNames < Minitest::Test
  CORPUS = JSON.parse(
    File.read(File.expand_path("../../../conformance/negatives/reserved-names-cases.json", __dir__))
  )

  def self.test_id(name)
    name.gsub(/[^A-Za-z0-9]/, "_")
  end

  def compile_src(file, src)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file)
      File.write(path, src)
      RunarCompiler.compile_from_source(path, disable_constant_folding: true).script
    end
  end

  def validator_errors(file, src)
    pr = RunarCompiler.send(:_parse_source, src, file)
    assert pr.contract, "parse failed: #{pr.errors.inspect}"
    RunarCompiler.send(:_validate, pr.contract).errors.map(&:message)
  end

  def test_corpus_is_not_empty
    assert_operator CORPUS["source"]["cases"].length, :>=, 30
    assert_operator CORPUS["ir"]["cases"].length, :>=, 10
  end

  CORPUS["source"]["cases"].each do |c|
    define_method("test_refuses_#{test_id(c['name'])}") do
      assert_includes validator_errors(c["file"], c["src"]), c["error"]
    end

    define_method("test_compiles_twin_of_#{test_id(c['name'])}") do
      refute_empty compile_src(c["file"], c["twin"])
    end
  end

  CORPUS["source"]["accept"].each do |a|
    define_method("test_accepts_#{test_id(a['name'])}") do
      refute_empty compile_src(a["file"], a["src"])
    end
  end

  CORPUS["ir"]["cases"].each do |c|
    define_method("test_ir_refuses_#{test_id(c['name'])}") do
      err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(JSON.generate(c["ir"])) }
      assert_includes err.message, c["error"]
    end
  end

  CORPUS["ir"]["accept"].each do |a|
    define_method("test_ir_accepts_#{test_id(a['name'])}") do
      assert_equal "00ac", RunarCompiler.compile_from_ir_bytes(JSON.generate(a["ir"])).script
    end
  end
end
