# frozen_string_literal: true

require_relative "test_helper"
require "json"
require "tmpdir"
require "runar_compiler/compiler"
require "runar_compiler/ir/loader"

# N-064 — constant folding must not fold with a constant a name no longer
# holds. Port of the reference tier's case in
# packages/runar-compiler/src/__tests__/optimizer.test.ts.
#
# The folder recorded a name's constant when a binding produced one and never
# dropped it. The probes that showed it bound a user local to the name of an
# earlier compiler temp, so with folding ON (the default) later uses folded
# with a stale value: Rebind's guard became OP_TRUE (7600a0695151515177777777,
# spendable with any p > 0), RebindEq's became OP_FALSE, and a rebinding
# inside an if arm or a loop body leaked the same way past the if / into later
# iterations.
#
# N-065 made that naming collision a refusal, so the probe SOURCES no longer
# compile. To keep this test's regression value, each probe's exact collision
# ANF (conformance/negatives/n064-collision-anf.json, generated from the probe
# with parse -> lowerToANF and no validator) is loaded through load_ir and
# driven through this tier's constant folder. On that ANF the pre-N-064 folder
# produced the `staleFoldOn` script byte for byte (verified on the reference
# tier); the fixed one must produce the fold-OFF script.
#
# Proves: the probe sources are refused with the N-065 diagnostic; this tier's
# folder, on each collision ANF, gives the same bytes as no folding, pinned to
# the fold-OFF bytes every tier emits. Does NOT prove on-chain behaviour — the
# Spend-engine proof is
# packages/runar-testing/src/__tests__/n064-rebind-fold-spend.test.ts.
class TestN064RebindFold < Minitest::Test
  PROBES = JSON.parse(
    File.read(File.expand_path("../../../conformance/negatives/n064-collision-anf.json", __dir__))
  )["probes"]

  COLLIDING_LOCAL = { "Rebind" => "t1", "RebindEq" => "t1", "IfStale" => "t2", "LoopStale" => "t2" }.freeze

  def ir_hex(probe, fold)
    program = RunarCompiler::IR.load_ir(JSON.generate(probe["ir"]))
    program = RunarCompiler.send(:_fold_constants, program) if fold
    RunarCompiler.compile_from_program(program, disable_constant_folding: true).script
  end

  def test_corpus_has_the_four_probes
    assert_equal %w[Rebind RebindEq IfStale LoopStale].sort, PROBES.map { |p| p["name"] }.sort
  end

  def test_probe_sources_are_refused
    PROBES.each do |p|
      Dir.mktmpdir do |dir|
        path = File.join(dir, "#{p['name']}.runar.ts")
        File.write(path, p["source"])
        err = assert_raises(StandardError) { RunarCompiler.compile_from_source(path) }
        want = "'#{COLLIDING_LOCAL.fetch(p['name'])}' is reserved for compiler-generated names " \
               "and cannot be used as an identifier"
        assert_includes err.message, want, p["name"]
      end
    end
  end

  def test_fold_on_does_not_use_a_stale_constant
    PROBES.each do |p|
      refute_equal p["staleFoldOn"], p["foldOff"]
      assert_equal p["foldOff"], ir_hex(p, false), "#{p['name']} unfolded"
      assert_equal p["foldOff"], ir_hex(p, true), "#{p['name']} folded"
    end
  end
end
