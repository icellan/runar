# frozen_string_literal: true

require_relative 'codegen_helper'

# Unit-vector tests for the Ruby math builtin codegen.
#
# These tests close audit gap T-1: Ruby was the only tier without a
# dedicated math-builtin unit test exercising every builtin in the language
# spec's E1–E16 group. The Python peer (test_math_builtins.py) drives the
# Stack-IR directly via +lower_to_stack+, but the Ruby tier follows the
# convention of its sibling codegen tests (test_blake3.rb, test_ec.rb,
# test_p256_p384.rb, ...) and inspects +artifact.asm+ produced by
# compiling a minimal TS source through the full Ruby pipeline.
#
# Pins, per builtin:
#   - The hallmark opcode the builtin must emit (e.g. +OP_ABS+).
#   - For open-coded sequences (safediv/safemod/divmod/...), the trailing
#     ordering of the tail ops.
#   - For unrolled iterative lowerings (pow/gcd/log2/sqrt), a lower
#     bound on the script size to detect a regression that collapsed the
#     loop.
#
# Goldens were captured from this Ruby implementation and double-checked
# against the conformance fixture +math-demo+, which now exercises all 16
# builtins across the 7 tiers.

class TestMathBuiltinsCodegen < Minitest::Test
  include CodegenTestHelpers

  # -- helpers --------------------------------------------------------------

  # Compile a one-method contract that calls +func_name+ with +arity+
  # bigint parameters, returning the resulting artifact. The method body
  # is +const r = <func>(p0, ...); assert(r ?? r === ...)+ — we use the
  # +bool+/+within+ shape directly to terminate with an assert, and the
  # value-returning builtins terminate with +assert(r > -2n)+ to make the
  # tail predictable. Every method takes +arity+ +bigint+ params so the
  # frontend's typechecker is happy.
  def compile_call_artifact(func_name, arity, returns_boolean: false)
    params = (0...arity).map { |i| "p#{i}: bigint" }.join(', ')
    args = (0...arity).map { |i| "p#{i}" }.join(', ')
    body =
      if returns_boolean
        "          const r = #{func_name}(#{args});\n" \
        '          assert(r);'
      else
        "          const r = #{func_name}(#{args});\n" \
        '          assert(r > -1000000000n);'
      end
    source = <<~TS
      import {
        SmartContract, assert,
        abs, min, max, within, bool,
        safediv, safemod, clamp, sign, pow, sqrt, gcd,
        mulDiv, percentOf, divmod, log2,
      } from 'runar-lang';

      class MathProbe extends SmartContract {
        readonly seed: bigint;
        constructor(seed: bigint) { super(seed); this.seed = seed; }
        public unlock(#{params}) {
          #{body}
        }
      }
    TS
    compile_ts_source(source, 'MathProbe.runar.ts')
  end

  # -- BUILTIN_OPCODES table-driven lowerings -------------------------------

  def test_abs_emits_op_abs
    artifact = compile_call_artifact('abs', 1)
    assert_includes artifact.asm, 'OP_ABS', 'abs must emit OP_ABS'
  end

  def test_min_emits_op_min
    artifact = compile_call_artifact('min', 2)
    assert_includes artifact.asm, 'OP_MIN', 'min must emit OP_MIN'
  end

  def test_max_emits_op_max
    artifact = compile_call_artifact('max', 2)
    assert_includes artifact.asm, 'OP_MAX', 'max must emit OP_MAX'
  end

  def test_within_emits_op_within
    artifact = compile_call_artifact('within', 3, returns_boolean: true)
    assert_includes artifact.asm, 'OP_WITHIN', 'within must emit OP_WITHIN'
  end

  def test_bool_emits_op_0notequal
    artifact = compile_call_artifact('bool', 1, returns_boolean: true)
    assert_includes artifact.asm, 'OP_0NOTEQUAL', 'bool must emit OP_0NOTEQUAL'
  end

  # -- safediv / safemod: open-coded with non-zero verify -------------------

  def test_safediv_verifies_non_zero_divisor_then_divides
    artifact = compile_call_artifact('safediv', 2)
    asm = artifact.asm
    # Order: ... OP_DUP OP_0NOTEQUAL OP_VERIFY OP_DIV ...
    assert_match(/OP_DUP\s+OP_0NOTEQUAL\s+OP_VERIFY\s+OP_DIV/, asm,
                 'safediv must emit DUP 0NOTEQUAL VERIFY DIV')
  end

  def test_safemod_verifies_non_zero_divisor_then_mods
    artifact = compile_call_artifact('safemod', 2)
    asm = artifact.asm
    assert_match(/OP_DUP\s+OP_0NOTEQUAL\s+OP_VERIFY\s+OP_MOD/, asm,
                 'safemod must emit DUP 0NOTEQUAL VERIFY MOD')
  end

  # -- clamp ----------------------------------------------------------------

  def test_clamp_emits_max_then_min
    artifact = compile_call_artifact('clamp', 3)
    asm = artifact.asm
    # ... OP_MAX <swap> OP_MIN ...
    assert_match(/OP_MAX\s+OP_SWAP\s+OP_MIN/, asm,
                 'clamp must emit MAX swap MIN tail')
  end

  # -- sign: IF-guarded |x| / x --------------------------------------------

  def test_sign_emits_dup_if_with_abs_and_div
    artifact = compile_call_artifact('sign', 1)
    asm = artifact.asm
    # sign(x) uses OP_DUP OP_IF { OP_DUP OP_ABS OP_SWAP OP_DIV } OP_ENDIF.
    assert_includes asm, 'OP_ABS', 'sign must inline OP_ABS'
    assert_includes asm, 'OP_DIV', 'sign must inline OP_DIV'
    assert_includes asm, 'OP_IF', 'sign must guard against zero with OP_IF'
  end

  # -- pow: 32-iteration unrolled MUL loop ----------------------------------

  def test_pow_unrolls_into_long_mul_sequence
    artifact = compile_call_artifact('pow', 2)
    asm = artifact.asm
    # 32-iter unroll => many OP_MUL ops (≥ 32 by the bounded loop count).
    op_mul_count = asm.scan('OP_MUL').length
    assert_operator op_mul_count, :>=, 32,
                    "pow must unroll ≥ 32 OP_MUL ops, got #{op_mul_count}"
  end

  # -- mulDiv: MUL then DIV -------------------------------------------------

  def test_mul_div_emits_mul_then_div
    artifact = compile_call_artifact('mulDiv', 3)
    asm = artifact.asm
    assert_match(/OP_MUL\s+OP_SWAP\s+OP_DIV/, asm,
                 'mulDiv must emit MUL swap DIV tail')
  end

  # -- percentOf: MUL by amount, DIV by 10000 -------------------------------

  def test_percent_of_divides_by_10000_basis_points
    artifact = compile_call_artifact('percentOf', 2)
    asm = artifact.asm
    # The push of 10000 is encoded as 0x271002 (canonical minimal push) —
    # appears as "1027" in 2-byte hex form. Easier to grep for the
    # OP_MUL ... OP_DIV pair with the 10000 push in between.
    assert_includes asm, 'OP_MUL', 'percentOf must emit OP_MUL'
    assert_includes asm, 'OP_DIV', 'percentOf must emit OP_DIV'
    assert_includes asm, '1027', 'percentOf must push 10000 (little-endian 0x2710 = "1027")'
  end

  # -- sqrt: 16-iter Newton's method under IF guard -------------------------

  def test_sqrt_emits_16_newton_iterations
    artifact = compile_call_artifact('sqrt', 1)
    asm = artifact.asm
    # 16 iter × (OVER OVER DIV ADD push(2) DIV) inside IF block.
    op_div_count = asm.scan('OP_DIV').length
    assert_operator op_div_count, :>=, 32,
                    "sqrt must unroll ≥ 32 DIVs for 16 Newton steps, got #{op_div_count}"
    assert_includes asm, 'OP_IF', 'sqrt must guard zero input with OP_IF'
  end

  # -- gcd: 256-iter unrolled Euclidean loop --------------------------------

  def test_gcd_unrolls_256_euclid_iterations
    artifact = compile_call_artifact('gcd', 2)
    asm = artifact.asm
    op_tuck_count = asm.scan('OP_TUCK').length
    op_mod_count = asm.scan('OP_MOD').length
    # 256 unrolled iterations: each emits TUCK + MOD inside an IF block.
    assert_operator op_tuck_count, :>=, 256,
                    "gcd must unroll ≥ 256 OP_TUCK ops, got #{op_tuck_count}"
    assert_operator op_mod_count, :>=, 256,
                    "gcd must unroll ≥ 256 OP_MOD ops, got #{op_mod_count}"
  end

  # -- divmod: returns quotient, drops remainder ----------------------------

  def test_divmod_emits_2dup_div_rot_rot_mod_drop_tail
    artifact = compile_call_artifact('divmod', 2)
    asm = artifact.asm
    # Tail: OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_DROP.
    assert_match(/OP_2DUP\s+OP_DIV\s+OP_ROT\s+OP_ROT\s+OP_MOD\s+OP_DROP/, asm,
                 'divmod must emit canonical 2DUP DIV ROT ROT MOD DROP tail')
  end

  # -- log2: 64-iter bit-scan under IF guard --------------------------------

  def test_log2_unrolls_64_bit_scan_iterations
    artifact = compile_call_artifact('log2', 1)
    asm = artifact.asm
    # 64 unrolled iterations: each guarded by an IF block.
    op_if_count = asm.scan(/\bOP_IF\b/).length
    assert_operator op_if_count, :>=, 64,
                    "log2 must unroll ≥ 64 IF blocks for the 64-bit scan, got #{op_if_count}"
    assert_includes asm, 'OP_1ADD',
                    'log2 must emit OP_1ADD inside the bit-scan loop'
  end

  # -- Determinism: same source must produce byte-identical script ---------

  def test_lowering_is_deterministic
    a = compile_call_artifact('clamp', 3)
    b = compile_call_artifact('clamp', 3)
    assert_equal a.script, b.script,
                 'clamp codegen must be deterministic'
  end

  # -- end-to-end: every builtin produces non-empty hex --------------------

  ALL_BUILTINS = [
    ['abs', 1, false],
    ['min', 2, false],
    ['max', 2, false],
    ['within', 3, true],
    ['bool', 1, true],
    ['safediv', 2, false],
    ['safemod', 2, false],
    ['clamp', 3, false],
    ['sign', 1, false],
    ['pow', 2, false],
    ['mulDiv', 3, false],
    ['percentOf', 2, false],
    ['sqrt', 1, false],
    ['gcd', 2, false],
    ['divmod', 2, false],
    ['log2', 1, false],
  ].freeze

  def test_every_builtin_emits_non_empty_script
    ALL_BUILTINS.each do |name, arity, returns_boolean|
      artifact = compile_call_artifact(name, arity, returns_boolean: returns_boolean)
      refute_empty artifact.script, "#{name} produced empty script bytes"
      assert artifact.script.length.positive?,
             "#{name} produced zero-length script"
    end
  end
end
