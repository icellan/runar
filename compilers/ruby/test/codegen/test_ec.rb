# frozen_string_literal: true

require_relative 'codegen_helper'

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
end
