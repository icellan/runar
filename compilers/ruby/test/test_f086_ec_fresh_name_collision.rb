# frozen_string_literal: true

# F-086 -- a name minted by the EC optimizer must never collide with a name the
# method already uses.
#
# The scalar-fusing rules (9, 10, 11) bind the folded scalar under a generated
# name (+__ec_opt_N+ in this tier) just before the rewritten binding.
# +fresh_const_name+ never checked whether that name was taken. ANF is
# single-assignment and stack lowering resolves a name to its shallowest slot,
# so when +__ec_opt_N+ is already a body binding or a method param the two
# values alias. Reachable from +--ir+, where names are attacker-chosen.
# Pre-fix, +__ec_opt_1 = 999; s = ecAdd(ecMulGen(2), ecMulGen(3));
# assert(k == __ec_opt_1)+ compiled to a script that accepts k = 5 and rejects
# the honest k = 999 (@bsv/sdk Spend.validate, strict v1 -- F-086 remediation
# log).
#
# Proves: the minted name is fresh w.r.t. every binding (at any depth), param
# and property; colliding programs compile to exactly the script of their
# renamed twins; the no-collision name is unchanged.
# Does not prove: anything about names minted by stack lowering (+_codePart+,
# +__param_*+, +__merge$*+).

require_relative "test_helper"
require "json"
require "runar_compiler/frontend/anf_optimize"

class TestF086ECFreshNameCollision < Minitest::Test
  OPT = RunarCompiler::Frontend::ANFOptimize

  def setup
    # The counter is process-global; pin it so the first minted name is the
    # one the colliding programs below already use.
    OPT.fresh_counter = 0
  end

  def program_json(body_name, k_param)
    body = []
    body << { name: body_name, value: { kind: "load_const", value: 999 } } if body_name
    body += [
      { name: "t1", value: { kind: "load_const", value: 2 } },
      { name: "t2", value: { kind: "call", func: "ecMulGen", args: ["t1"] } },
      { name: "t3", value: { kind: "load_const", value: 3 } },
      { name: "t4", value: { kind: "call", func: "ecMulGen", args: ["t3"] } },
      { name: "s", value: { kind: "call", func: "ecAdd", args: %w[t2 t4] } },
      { name: "t5", value: { kind: "load_param", name: "p" } },
      { name: "t6", value: { kind: "bin_op", op: "===", left: "s", right: "t5" } },
      { name: "t7", value: { kind: "assert", value: "t6" } },
      { name: "t8", value: { kind: "load_param", name: k_param } }
    ]
    rhs = body_name
    unless body_name
      body << { name: "t9c", value: { kind: "load_const", value: 999 } }
      rhs = "t9c"
    end
    body << { name: "t9", value: { kind: "bin_op", op: "===", left: "t8", right: rhs } }
    body << { name: "t10", value: { kind: "assert", value: "t9" } }
    JSON.generate(
      contractName: "EcOptCollide",
      properties: [],
      methods: [
        { name: "constructor", isPublic: false, params: [],
          body: [{ name: "t0", value: { kind: "call", func: "super", args: [] } }] },
        { name: "unlock", isPublic: true,
          params: [{ name: "p", type: "Point" }, { name: k_param, type: "bigint" }],
          body: body }
      ]
    )
  end

  def optimized_unlock(src)
    program = OPT.optimize_ec(RunarCompiler::IR.load_ir(src))
    program.methods.find { |m| m.name == "unlock" }
  end

  def fused_scalar(method)
    i = method.body.index { |b| b.name == "s" }
    s = method.body[i].value
    assert_equal "call", s.kind
    assert_equal "ecMulGen", s.func
    arg = s.args[0]
    refute_includes method.params.map(&:name), arg, "fused scalar #{arg} is a param name"
    prior = method.body[0...i].select { |b| b.name == arg }
    assert_equal 1, prior.size, "fused scalar name #{arg} bound #{prior.size} times"
    prior[0].value.const_big_int
  end

  def assert_single_assignment(method)
    names = method.body.map(&:name)
    assert_equal names.uniq.size, names.size, names.inspect
    assert_empty method.params.map(&:name) & names, names.inspect
  end

  def test_no_collision_keeps_historical_name
    m = optimized_unlock(program_json(nil, "k"))
    assert(m.body.any? { |b| b.name == "__ec_opt_1" })
    assert_equal 5, fused_scalar(m)
  end

  def test_preexisting_body_binding_is_not_shadowed
    m = optimized_unlock(program_json("__ec_opt_1", "k"))
    assert_single_assignment(m)
    assert_equal 5, fused_scalar(m)
  end

  def test_param_is_not_shadowed
    m = optimized_unlock(program_json(nil, "__ec_opt_1"))
    assert_single_assignment(m)
    assert_equal 5, fused_scalar(m)
  end

  def test_colliding_programs_compile_like_their_renamed_twins
    hex = lambda do |src|
      OPT.fresh_counter = 0
      RunarCompiler.compile_from_ir_bytes(src).script
    end
    assert_equal hex.call(program_json("zz_unused", "k")), hex.call(program_json("__ec_opt_1", "k"))
    assert_equal hex.call(program_json(nil, "zz")), hex.call(program_json(nil, "__ec_opt_1"))
  end
end
