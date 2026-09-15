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
  # T-11: Op-TREE-size goldens for every P-256 / P-384 emitter (`if` bodies
  # included, see count_op_tree).
  #
  # The ASM-substring tests above catch a gross regression but not byte-level
  # codegen drift. Numbers mirror the Python peer
  # (compilers/python/tests/codegen/test_p256_p384.py) and the Java
  # reference at the same commit. Final hex is byte-identical across all
  # 7 tiers (enforced by the conformance harness); these goldens are an
  # in-process localized-regression gate.
  #
  # `verifyECDSA_P256` moved 297273 -> 297331 (+58) when the verifier grew its
  # input-validation gates: the two length clamps on `_pk` / `_sig`, the
  # 1 <= r,s <= n-1 range gate, the SEC1 prefix test inside pubkey
  # decompression, and the BOOLAND chain that folds all three verdicts into
  # `_input_ok`. `verifyECDSA_P384` gains the same +58 but carries no golden
  # here. Both are input validation, not a formula change, so the ladder
  # emitters (`p256Mul` / `p384Mul`) are untouched.
  # ---------------------------------------------------------------------------

  # R-052 / CL-BUG-095, the Point WIDTH gate, moved these goldens again. A
  # P256Point/P384Point is exactly 2*coord_bytes by definition and nothing
  # checked it, so surplus bytes were split off and dropped. Deltas mirror the
  # secp256k1 module (see test/codegen/test_ec.rb): +3 per `c_decompose_point`
  # call site (`p256Add` decomposes twice -> +6), +15 for the on-curve
  # predicate's clamp-and-flag gate, +12 for `verifyECDSA_*` (four decompose
  # call sites), and +-0 for `*EncodeCompressed`, where the 3-op gate is paid
  # for by the fixed-offset parity read replacing a 6-op sequence with 3.
  P256_GOLDENS = {
    "p256Add"              =>   6719,
    "p256Mul"              => 140039,
    "p256MulGen"           => 140041,
    "p256Negate"           =>    948,
    "p256OnCurve"          =>    574,
    "p256EncodeCompressed" =>     16,
    "verifyECDSA_P256"     => 297393,
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
    "p384Add"    =>  11525,
    "p384Mul"    => 211181,
    "p384MulGen" => 211183,
    "p384Negate" =>   1396,
  }.freeze

  P384_EMITTERS = {
    "p384Add"    => RunarCompiler::Codegen::NISTEC.method(:emit_p384_add),
    "p384Mul"    => RunarCompiler::Codegen::NISTEC.method(:emit_p384_mul),
    "p384MulGen" => RunarCompiler::Codegen::NISTEC.method(:emit_p384_mul_gen),
    "p384Negate" => RunarCompiler::Codegen::NISTEC.method(:emit_p384_negate),
  }.freeze

  # Total StackOps in `ops`, INCLUDING the bodies of `if` ops.
  #
  # A flat `ops.length` cannot see inside a branch, so any emitter whose work
  # sits in an `if` body -- the scalar ladders emit 257 / 385 conditional
  # additions -- reports a count that barely moves no matter what the branch
  # contains. Adding +1.3 KB of script inside the ladder's last step left the
  # `p256Mul` / `p384Mul` goldens byte-identical. Recursing makes it a gate.
  def count_op_tree(ops)
    ops.sum do |op|
      if op[:op] == "if"
        1 + count_op_tree(op[:then] || []) + count_op_tree(op[:else_ops] || [])
      else
        1
      end
    end
  end

  def test_p256_emitter_op_count_goldens
    P256_EMITTERS.each do |name, emitter|
      ops = []
      emitter.call(->(op) { ops << op })
      expected = P256_GOLDENS.fetch(name)
      got = count_op_tree(ops)
      assert_equal expected, got,
                   "#{name} op count drift: got #{got}, want #{expected}"
    end
  end

  def test_p384_emitter_op_count_goldens
    P384_EMITTERS.each do |name, emitter|
      ops = []
      emitter.call(->(op) { ops << op })
      expected = P384_GOLDENS.fetch(name)
      got = count_op_tree(ops)
      assert_equal expected, got,
                   "#{name} op count drift: got #{got}, want #{expected}"
    end
  end
end
