# frozen_string_literal: true

require_relative 'codegen_helper'
require 'runar_compiler/codegen/p256_p384'

# Unit-vector tests for the Ruby P-256 / P-384 codegen module
# (compilers/ruby/lib/runar_compiler/codegen/p256_p384.rb).

class TestP256P384Codegen < Minitest::Test
  include CodegenTestHelpers

  # ---------------------------------------------------------------------------
  # P-256 point operations
  # ---------------------------------------------------------------------------

  def test_p256_add_emits_modular_arithmetic
    source = <<~TS
      import { SmartContract, assert, p256Add } from 'runar-lang';
      import type { P256Point } from 'runar-lang';

      class P256AddTest extends SmartContract {
        readonly expected: P256Point;

        constructor(expected: P256Point) {
          super(expected);
          this.expected = expected;
        }

        public verify(p: P256Point, q: P256Point) {
          const r = p256Add(p, q);
          assert(r === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'P256AddTest.runar.ts')
    assert_equal 'P256AddTest', artifact.contract_name

    assert_operator artifact.script.length / 2, :>, 500
    asm = artifact.asm
    assert_includes asm, 'OP_ADD'
    assert_includes asm, 'OP_MUL'
    assert_includes asm, 'OP_MOD'
  end

  def test_p256_mul_emits_double_and_add_loop
    source = <<~TS
      import { SmartContract, assert, p256Mul } from 'runar-lang';
      import type { P256Point } from 'runar-lang';

      class P256MulTest extends SmartContract {
        readonly expected: P256Point;

        constructor(expected: P256Point) {
          super(expected);
          this.expected = expected;
        }

        public verify(p: P256Point, k: bigint) {
          const r = p256Mul(p, k);
          assert(r === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'P256MulTest.runar.ts')
    assert_equal 'P256MulTest', artifact.contract_name

    # Scalar multiplication unrolls a 256-bit double-and-add loop, so the
    # script must be substantially larger than `p256Add`.
    assert_operator artifact.script.length / 2, :>, 5_000
  end

  # ---------------------------------------------------------------------------
  # P-384 point operations
  # ---------------------------------------------------------------------------

  def test_p384_add_emits_modular_arithmetic
    source = <<~TS
      import { SmartContract, assert, p384Add } from 'runar-lang';
      import type { P384Point } from 'runar-lang';

      class P384AddTest extends SmartContract {
        readonly expected: P384Point;

        constructor(expected: P384Point) {
          super(expected);
          this.expected = expected;
        }

        public verify(p: P384Point, q: P384Point) {
          const r = p384Add(p, q);
          assert(r === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'P384AddTest.runar.ts')
    assert_equal 'P384AddTest', artifact.contract_name

    assert_operator artifact.script.length / 2, :>, 500
    asm = artifact.asm
    assert_includes asm, 'OP_ADD'
    assert_includes asm, 'OP_MUL'
    assert_includes asm, 'OP_MOD'
  end

  def test_p384_mul_is_larger_than_p256_mul
    p256_source = <<~TS
      import { SmartContract, assert, p256Mul } from 'runar-lang';
      import type { P256Point } from 'runar-lang';

      class P256ScalarMul extends SmartContract {
        readonly expected: P256Point;
        constructor(expected: P256Point) { super(expected); this.expected = expected; }
        public verify(p: P256Point, k: bigint) {
          const r = p256Mul(p, k);
          assert(r === this.expected);
        }
      }
    TS

    p384_source = <<~TS
      import { SmartContract, assert, p384Mul } from 'runar-lang';
      import type { P384Point } from 'runar-lang';

      class P384ScalarMul extends SmartContract {
        readonly expected: P384Point;
        constructor(expected: P384Point) { super(expected); this.expected = expected; }
        public verify(p: P384Point, k: bigint) {
          const r = p384Mul(p, k);
          assert(r === this.expected);
        }
      }
    TS

    p256 = compile_ts_source(p256_source, 'P256ScalarMul.runar.ts')
    p384 = compile_ts_source(p384_source, 'P384ScalarMul.runar.ts')

    # P-384 has 384-bit scalars — the unrolled loop is meaningfully larger.
    assert_operator p384.script.length, :>, p256.script.length,
                    'P-384 scalar mul must produce a larger script than P-256'
  end

  # ---------------------------------------------------------------------------
  # T-11: Op-count goldens for every P-256 / P-384 emitter.
  #
  # The ASM-substring tests above catch a gross regression but not byte-level
  # codegen drift. Numbers mirror the Python peer
  # (compilers/python/tests/codegen/test_p256_p384.py) and the Java
  # reference at the same commit. Final hex is byte-identical across all
  # 7 tiers (enforced by the conformance harness); these goldens are an
  # in-process localized-regression gate.
  # ---------------------------------------------------------------------------

  P256_GOLDENS = {
    "p256Add"              =>   6505,
    "p256Mul"              =>  73306,
    "p256MulGen"           =>  73308,
    "p256Negate"           =>    945,
    "p256OnCurve"          =>    546,
    "p256EncodeCompressed" =>     14,
    "verifyECDSA_P256"     => 163589,
  }.freeze

  P256_EMITTERS = {
    "p256Add"              => RunarCompiler::Codegen::NISTEC.method(:emit_p256_add),
    "p256Mul"              => RunarCompiler::Codegen::NISTEC.method(:emit_p256_mul),
    "p256MulGen"           => RunarCompiler::Codegen::NISTEC.method(:emit_p256_mul_gen),
    "p256Negate"           => RunarCompiler::Codegen::NISTEC.method(:emit_p256_negate),
    "p256OnCurve"          => RunarCompiler::Codegen::NISTEC.method(:emit_p256_on_curve),
    "p256EncodeCompressed" => RunarCompiler::Codegen::NISTEC.method(:emit_p256_encode_compressed),
    "verifyECDSA_P256"     => RunarCompiler::Codegen::NISTEC.method(:emit_verify_ecdsa_p256),
  }.freeze

  P384_GOLDENS = {
    "p384Add"    =>  11311,
    "p384Mul"    => 111424,
    "p384MulGen" => 111426,
    "p384Negate" =>   1393,
  }.freeze

  P384_EMITTERS = {
    "p384Add"    => RunarCompiler::Codegen::NISTEC.method(:emit_p384_add),
    "p384Mul"    => RunarCompiler::Codegen::NISTEC.method(:emit_p384_mul),
    "p384MulGen" => RunarCompiler::Codegen::NISTEC.method(:emit_p384_mul_gen),
    "p384Negate" => RunarCompiler::Codegen::NISTEC.method(:emit_p384_negate),
  }.freeze

  def test_p256_emitter_op_count_goldens
    P256_EMITTERS.each do |name, emitter|
      ops = []
      emitter.call(->(op) { ops << op })
      expected = P256_GOLDENS.fetch(name)
      assert_equal expected, ops.length,
                   "#{name} op count drift: got #{ops.length}, want #{expected}"
    end
  end

  def test_p384_emitter_op_count_goldens
    P384_EMITTERS.each do |name, emitter|
      ops = []
      emitter.call(->(op) { ops << op })
      expected = P384_GOLDENS.fetch(name)
      assert_equal expected, ops.length,
                   "#{name} op count drift: got #{ops.length}, want #{expected}"
    end
  end
end
