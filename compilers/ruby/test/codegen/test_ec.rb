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
  # and the Java reference EcTest at the same commit — lock the exact size of
  # each Ruby emitter's op TREE (`if` bodies included, see count_op_tree). Final hex is byte-identical across all 7
  # tiers (enforced by the conformance harness); the goldens here are an
  # in-process localized-regression gate.
  # ---------------------------------------------------------------------------

  # R-052 / CL-BUG-095, the Point WIDTH gate, moved these goldens. A `Point` is
  # 64 bytes by definition and nothing checked it, so a surplus byte was split
  # off and silently dropped: `ecOnCurve(G || 0xff)` returned TRUE and
  # `ecEncodeCompressed` took its parity bit from the caller's extra byte. The
  # deltas are structural, which is why they match the six other tiers
  # byte-for-byte:
  #
  #   * +3 per `ec_decompose_point` call site -- OP_SIZE, push 64,
  #     OP_NUMEQUALVERIFY. `ecAdd` decomposes TWICE, hence +6; `ecMul` /
  #     `ecMulGen` / `ecNegate` once.
  #   * +15 `ecOnCurve` -- 9 for the clamp-and-flag gate (it must stay a
  #     PREDICATE and answer `false`, not abort, or `if (ecOnCurve(p))` stops
  #     being writable), +3 for the decompose gate, +1 for the extra OP_BOOLAND
  #     folding `_len_ok` in, +2 for rolling the two flags up.
  #   * +3 `ecPointX` / `ecPointY`.
  #
  # `ecEncodeCompressed` stays at 16 ops and that is NOT an oversight: the gate
  # adds 3 ops while the fixed-offset parity read (push 31, OP_SPLIT, OP_NIP)
  # replaces a 6-op OP_SIZE/OP_SUB/OP_SPLIT/OP_SWAP/OP_DROP sequence with 3.
  EC_OP_COUNT_GOLDENS = {
    # R-117, the COORDINATE-CANONICITY gate. ecAdd 8279 -> 8297 (+18), ecMul
    # 130518 -> 131073 (+8), ecMulGen +8, ecNegate 948 -> 956 (+8). emitCoordCanonVerify
    # is 8 ops per gated point -- copy x (pick), push p, OP_LESSTHAN, copy y (pick),
    # push p, OP_LESSTHAN, OP_BOOLAND, OP_VERIFY -- and ecAdd gates TWO points, so
    # +18 there rather than +16. The extra two are pick DEPTH, not extra work: this
    # tracker emits OP_DUP / OP_OVER for depth 0 / 1 and `push <n>, OP_PICK` for
    # anything deeper, and in ecAdd's FIRST gate the stack is [px, py, qx, qy], so
    # both of that gate's picks reach depth 3 and cost two ops each. Its second gate
    # sees [px, py, qx, qy] with qx / qy at depth 1, so both are a one-op OP_OVER.
    # 10 + 8 = 18, and ecMul / ecNegate gate a single point off a two-deep stack for
    # a flat 8. ecOnCurve / ecModReduce /
    # ecEncodeCompressed / ecMakePoint / ecPointX / ecPointY are all +0. The
    # predicates must stay TOTAL (they clamp and flag, they do not abort), and the
    # byte accessors have no selector to fool -- each returns a value derived
    # injectively from the bytes, so a non-canonical coordinate yields a DIFFERENT
    # number rather than a colliding one.
    "ecAdd"              =>  8297,
    # R-157, the ecMul ON-CURVE-OR-INFINITY gate: ecMul 130526 -> 131073 (+547),
    # ecMulGen +547. The gate is the whole ecOnCurve body plus a copy/compare against
    # the all-zero blob and an OP_BOOLOR/OP_VERIFY, run once before the ladder. ecAdd
    # / ecNegate / ecOnCurve / ecMakePoint / ecPointX / ecPointY are all +0 — this
    # gate is on the SCALAR LADDER only, because it is the +3n construction inside
    # ecMul whose soundness needs ord(P) | n. affineAdd has no n-dependent trick and
    # is correct on whatever curve its operand lies on, so gating it would cost bytes
    # and break ecAdd(P, O), which R-053 requires.
    # ecMulGen pays the gate too even though its operand is the compiler-pushed
    # generator: it is emitted as `push G; swap; ecMul`, and exempting it would mean a
    # second ecMul spelling whose only difference is a check that can never fail.
    "ecMul"              => 131073,
    "ecMulGen"           => 131075,
    "ecNegate"           =>   956,
    "ecOnCurve"          =>   548,
    "ecModReduce"        =>     8,
    "ecEncodeCompressed" =>     16,
    # R-156, the ecMakePoint FIELD-ELEMENT gate: 467 -> 477 (+10). Five ops per
    # coordinate -- OP_DUP, OP_0, push p, OP_WITHIN, OP_VERIFY -- and ecMakePoint has
    # two. Nothing else moves: this gate is on the two BIGINT arguments of the point
    # CONSTRUCTOR, which is a different surface from R-117's gate on the coordinates
    # of an existing Point. ecMakePoint is secp256k1-only; there is no p256MakePoint
    # or p384MakePoint to move.
    "ecMakePoint"        =>   477,
    "ecPointX"           =>   236,
    "ecPointY"           =>   237,
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

  # Total StackOps in `ops`, INCLUDING the bodies of `if` ops.
  #
  # A flat `ops.length` cannot see inside a branch, so any emitter whose work
  # sits in an `if` body -- the scalar ladders emit 257 / 385 conditional
  # additions, WOTS+ and SLH-DSA are almost entirely conditional -- reports a
  # count that barely moves no matter what the branch contains. Adding +1.3 KB
  # of script inside the ladder's last step left the `p256Mul` / `p384Mul`
  # goldens byte-identical. Recursing is what makes the golden a gate.
  def count_op_tree(ops)
    ops.sum do |op|
      if op[:op] == "if"
        1 + count_op_tree(op[:then] || []) + count_op_tree(op[:else_ops] || [])
      else
        1
      end
    end
  end

  def test_ec_emitter_op_count_goldens
    EC_EMITTERS.each do |name, emitter|
      ops = []
      emitter.call(->(op) { ops << op })
      expected = EC_OP_COUNT_GOLDENS.fetch(name)
      got = count_op_tree(ops)
      assert_equal expected, got,
                   "#{name} op count drift: got #{got}, want #{expected}"
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
