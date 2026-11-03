# frozen_string_literal: true

# N-112 -- the EC optimizer's fresh names must be a function of the program
# alone, and must be the names the TypeScript reference mints.
#
# The scalar-fusing rules (9, 10, 11) bind the folded scalar under a newly
# minted name. That name used to come from +ANFOptimize.fresh_counter+, a
# class-level counter that was never reset, so compiling the identical source
# twice in one Ruby process gave +__ec_opt_1+ the first time and +__ec_opt_2+
# the second: the optimized ANF (and +--emit-ir+ output) depended on whatever
# the process had compiled before, and never matched TS.
#
# TS (packages/runar-compiler/src/optimizer/anf-ec.ts) mints
# +freshName(`${binding.name}_k`, usedNames)+: +<binding>_k+, else the first
# unused +<binding>_k_<i>+ against the method's used names.
#
# Proves: compiling the same Rule-10 source three times in one process yields
# byte-identical serialized ANF in both fold modes; the minted name is
# +<binding>_k+; a collision picks +<binding>_k_1+.
# Does not prove: script-byte effects (names never reach the hex; N-028 / F-086
# pin the bytes), nor cross-tier equality of the whole ANF (that is
# packages/runar-compiler/src/__tests__/n112-ec-fusion-helper-name-parity.test.ts).

require_relative "test_helper"
require "json"
require "tmpdir"
require "runar_compiler/frontend/anf_optimize"

class TestN112ECFreshNameDeterminism < Minitest::Test
  OPT = RunarCompiler::Frontend::ANFOptimize

  EC_OPT_SOURCE = <<~TS
    import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';

    class EcOpt extends SmartContract {
        constructor() {
            super();
        }

        public spend(a: bigint) {
            assert(ecOnCurve(ecAdd(ecMulGen(2n), ecMulGen(3n))));
        }
    }
  TS

  def ir_json(path, disable_constant_folding)
    program = RunarCompiler.compile_source_to_ir(path, disable_constant_folding: disable_constant_folding)
    JSON.generate(RunarCompiler.send(:_serialize_anf_program, program))
  end

  def test_same_source_three_times_in_one_process_gives_identical_anf
    Dir.mktmpdir do |dir|
      path = File.join(dir, "EcOpt.runar.ts")
      File.write(path, EC_OPT_SOURCE)
      [true, false].each do |fold_off|
        first = ir_json(path, fold_off)
        second = ir_json(path, fold_off)
        third = ir_json(path, fold_off)
        assert_equal first, second, "ANF differs between identical compilations (fold_off=#{fold_off})"
        assert_equal first, third, "ANF differs between identical compilations (fold_off=#{fold_off})"
      end
    end
  end

  def rule10_program(extra_name)
    body = []
    body << { name: extra_name, value: { kind: "load_const", value: 999 } } if extra_name
    body += [
      { name: "t1", value: { kind: "load_const", value: 2 } },
      { name: "t2", value: { kind: "call", func: "ecMulGen", args: ["t1"] } },
      { name: "t3", value: { kind: "load_const", value: 3 } },
      { name: "t4", value: { kind: "call", func: "ecMulGen", args: ["t3"] } },
      { name: "s", value: { kind: "call", func: "ecAdd", args: %w[t2 t4] } },
      { name: "t5", value: { kind: "call", func: "ecOnCurve", args: ["s"] } },
      { name: "t6", value: { kind: "assert", value: "t5" } }
    ]
    JSON.generate(
      contractName: "EcOpt",
      properties: [],
      methods: [
        { name: "constructor", isPublic: false, params: [],
          body: [{ name: "t0", value: { kind: "call", func: "super", args: [] } }] },
        { name: "spend", isPublic: true, params: [], body: body }
      ]
    )
  end

  def fused_scalar_name(src)
    m = OPT.optimize_ec(RunarCompiler::IR.load_ir(src)).methods.find { |x| x.name == "spend" }
    s = m.body.find { |b| b.name == "s" }
    assert_equal "call", s.value.kind
    assert_equal "ecMulGen", s.value.func
    s.value.args[0]
  end

  def test_minted_name_follows_ts_fresh_name
    assert_equal "s_k", fused_scalar_name(rule10_program(nil))
    # Repeating it must not drift (the old counter gave the next N).
    assert_equal "s_k", fused_scalar_name(rule10_program(nil))
  end

  def test_minted_name_skips_a_used_name_like_ts
    assert_equal "s_k_1", fused_scalar_name(rule10_program("s_k"))
  end
end
