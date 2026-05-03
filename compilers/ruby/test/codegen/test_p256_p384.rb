# frozen_string_literal: true

require_relative 'codegen_helper'

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
end
