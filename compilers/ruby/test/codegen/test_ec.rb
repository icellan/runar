# frozen_string_literal: true

require_relative 'codegen_helper'
require 'runar_compiler/codegen/ec'

# Unit-vector tests for the Ruby EC (secp256k1) codegen module
# (compilers/ruby/lib/runar_compiler/codegen/ec.rb). Mirrors the spirit
# of the Go peer's codegen tests by compiling a contract that exercises
# `ecAdd` / `ecMul` and asserting the emitted script shape.

class TestEcCodegen < Minitest::Test
  include CodegenTestHelpers

  # ---------------------------------------------------------------------------
  # ecAdd: point addition on secp256k1
  # ---------------------------------------------------------------------------

  def test_ec_add_emits_modular_arithmetic
    source = <<~TS
      import { SmartContract, assert, ecAdd } from 'runar-lang';
      import type { Point } from 'runar-lang';

      class EcAddTest extends SmartContract {
        readonly expected: Point;

        constructor(expected: Point) {
          super(expected);
          this.expected = expected;
        }

        public verify(p: Point, q: Point) {
          const r = ecAdd(p, q);
          assert(r === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'EcAddTest.runar.ts')
    assert_equal 'EcAddTest', artifact.contract_name

    # secp256k1 point addition compiles to a multi-KB script.
    assert_operator artifact.script.length / 2, :>, 500,
                    'ecAdd should produce a sizable script'

    # The EC codegen relies on modular arithmetic — at minimum we expect
    # bigint addition / multiplication / subtraction / mod operators.
    asm = artifact.asm
    assert_includes asm, 'OP_ADD'
    assert_includes asm, 'OP_MUL'
    assert_includes asm, 'OP_SUB'
    assert_includes asm, 'OP_MOD'
  end

  # ---------------------------------------------------------------------------
  # ecMul: scalar multiplication
  # ---------------------------------------------------------------------------

  def test_ec_mul_emits_double_and_add_loop
    source = <<~TS
      import { SmartContract, assert, ecMul } from 'runar-lang';
      import type { Point } from 'runar-lang';

      class EcMulTest extends SmartContract {
        readonly expected: Point;

        constructor(expected: Point) {
          super(expected);
          this.expected = expected;
        }

        public verify(p: Point, k: bigint) {
          const r = ecMul(p, k);
          assert(r === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'EcMulTest.runar.ts')
    assert_equal 'EcMulTest', artifact.contract_name

    # Double-and-add over a 256-bit scalar produces a script that is
    # substantially larger than `ecAdd` alone.
    assert_operator artifact.script.length / 2, :>, 5_000,
                    'ecMul should produce a much larger script than ecAdd'

    asm = artifact.asm
    assert_includes asm, 'OP_ADD'
    assert_includes asm, 'OP_MUL'
  end

  # ---------------------------------------------------------------------------
  # T-11: Op-count goldens for every EC emitter.
  #
  # The ASM-substring tests above (`assert_includes asm, 'OP_ADD'`) catch a
  # gross regression but not byte-level codegen drift. These goldens —
  # copied from the Python peer (compilers/python/tests/codegen/test_ec.py)
  # and the Java reference EcTest at the same commit — lock the exact op
  # count for each Ruby emitter. Final hex is byte-identical across all 7
  # tiers (enforced by the conformance harness); the goldens here are an
  # in-process localized-regression gate.
  # ---------------------------------------------------------------------------

  EC_OP_COUNT_GOLDENS = {
    "ecAdd"              =>  8078,
    "ecMul"              => 63828,
    "ecMulGen"           => 63830,
    "ecNegate"           =>   945,
    "ecOnCurve"          =>   520,
    "ecModReduce"        =>     8,
    "ecEncodeCompressed" =>    14,
    "ecMakePoint"        =>   467,
    "ecPointX"           =>   233,
    "ecPointY"           =>   234,
  }.freeze

  EC_EMITTERS = {
    "ecAdd"              => RunarCompiler::Codegen::EC.method(:emit_ec_add),
    "ecMul"              => RunarCompiler::Codegen::EC.method(:emit_ec_mul),
    "ecMulGen"           => RunarCompiler::Codegen::EC.method(:emit_ec_mul_gen),
    "ecNegate"           => RunarCompiler::Codegen::EC.method(:emit_ec_negate),
    "ecOnCurve"          => RunarCompiler::Codegen::EC.method(:emit_ec_on_curve),
    "ecModReduce"        => RunarCompiler::Codegen::EC.method(:emit_ec_mod_reduce),
    "ecEncodeCompressed" => RunarCompiler::Codegen::EC.method(:emit_ec_encode_compressed),
    "ecMakePoint"        => RunarCompiler::Codegen::EC.method(:emit_ec_make_point),
    "ecPointX"           => RunarCompiler::Codegen::EC.method(:emit_ec_point_x),
    "ecPointY"           => RunarCompiler::Codegen::EC.method(:emit_ec_point_y),
  }.freeze

  def test_ec_emitter_op_count_goldens
    EC_EMITTERS.each do |name, emitter|
      ops = []
      emitter.call(->(op) { ops << op })
      expected = EC_OP_COUNT_GOLDENS.fetch(name)
      assert_equal expected, ops.length,
                   "#{name} op count drift: got #{ops.length}, want #{expected}"
    end
  end

  # Representative byte/shape assertion for the smallest emitter — ecModReduce
  # is exactly 8 ops in a known sequence. Mirrors the Python peer
  # `test_ec_mod_reduce_is_exact_eight_ops`.
  def test_ec_mod_reduce_exact_op_shape
    ops = []
    RunarCompiler::Codegen::EC.emit_ec_mod_reduce(->(op) { ops << op })
    assert_equal 8, ops.length

    # The Ruby StackOp is a Struct-ish; we render with #inspect and match
    # the load-bearing opcode tokens to avoid coupling to per-tier field
    # naming (Python uses `code`, Ruby uses a `code:` keyword).
    rendered = ops.map(&:inspect).join(' ')
    assert_includes rendered, 'OP_2DUP'
    assert_includes rendered, 'OP_ADD'
    # Two OP_MOD occurrences (positions 1 and 7 in the Python peer).
    mod_count = rendered.scan('OP_MOD').length
    assert_operator mod_count, :>=, 2,
                    "expected ≥2 OP_MOD tokens, got #{mod_count} in: #{rendered}"
  end
end
