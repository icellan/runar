# frozen_string_literal: true

require_relative 'codegen_helper'

# Additional opcode-shape unit tests for the Stack-IR lowering pipeline.
# Each test compiles a single-feature contract and asserts that the
# expected Bitcoin Script opcodes appear in the emitted ASM.

class TestStackOpcodes < Minitest::Test
  include CodegenTestHelpers

  # ---------------------------------------------------------------------------
  # Bitwise ops
  # ---------------------------------------------------------------------------

  def test_bitwise_and_emits_op_and
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class And extends SmartContract {
        readonly mask: bigint;
        constructor(mask: bigint) { super(mask); this.mask = mask; }
        public check(a: bigint): void {
          assert((a & this.mask) > 0n);
        }
      }
    TS

    artifact = compile_ts_source(source, 'And.runar.ts')
    assert_includes artifact.asm, 'OP_AND'
  end

  def test_bitwise_or_emits_op_or
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Or extends SmartContract {
        readonly mask: bigint;
        constructor(mask: bigint) { super(mask); this.mask = mask; }
        public check(a: bigint): void {
          assert((a | this.mask) > 0n);
        }
      }
    TS

    artifact = compile_ts_source(source, 'Or.runar.ts')
    assert_includes artifact.asm, 'OP_OR'
  end

  def test_bitwise_xor_emits_op_xor
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Xor extends SmartContract {
        readonly mask: bigint;
        constructor(mask: bigint) { super(mask); this.mask = mask; }
        public check(a: bigint): void {
          assert((a ^ this.mask) > 0n);
        }
      }
    TS

    artifact = compile_ts_source(source, 'Xor.runar.ts')
    assert_includes artifact.asm, 'OP_XOR'
  end

  # ---------------------------------------------------------------------------
  # Shifts
  # ---------------------------------------------------------------------------

  def test_left_shift_emits_op_lshift
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class L extends SmartContract {
        readonly target: bigint;
        constructor(target: bigint) { super(target); this.target = target; }
        public check(a: bigint, n: bigint): void {
          assert((a << n) == this.target);
        }
      }
    TS

    artifact = compile_ts_source(source, 'L.runar.ts')
    assert_includes artifact.asm, 'OP_LSHIFT'
  end

  def test_right_shift_emits_op_rshift
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class R extends SmartContract {
        readonly target: bigint;
        constructor(target: bigint) { super(target); this.target = target; }
        public check(a: bigint, n: bigint): void {
          assert((a >> n) == this.target);
        }
      }
    TS

    artifact = compile_ts_source(source, 'R.runar.ts')
    assert_includes artifact.asm, 'OP_RSHIFT'
  end

  # ---------------------------------------------------------------------------
  # Concatenation / size
  # ---------------------------------------------------------------------------

  def test_cat_emits_op_cat
    source = <<~TS
      import { SmartContract, assert, cat } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Cat extends SmartContract {
        readonly expected: ByteString;
        constructor(expected: ByteString) { super(expected); this.expected = expected; }
        public check(a: ByteString, b: ByteString): void {
          assert(cat(a, b) === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'Cat.runar.ts')
    assert_includes artifact.asm, 'OP_CAT'
  end

  def test_len_emits_op_size
    source = <<~TS
      import { SmartContract, assert, len } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class L extends SmartContract {
        readonly target: bigint;
        constructor(target: bigint) { super(target); this.target = target; }
        public check(a: ByteString): void {
          assert(len(a) == this.target);
        }
      }
    TS

    artifact = compile_ts_source(source, 'L.runar.ts')
    assert_includes artifact.asm, 'OP_SIZE'
  end

  # ---------------------------------------------------------------------------
  # Numeric comparison
  # ---------------------------------------------------------------------------

  def test_less_than_emits_op_lessthan
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class LT extends SmartContract {
        readonly limit: bigint;
        constructor(limit: bigint) { super(limit); this.limit = limit; }
        public check(a: bigint): void {
          assert(a < this.limit);
        }
      }
    TS

    artifact = compile_ts_source(source, 'LT.runar.ts')
    assert_includes artifact.asm, 'OP_LESSTHAN'
  end

  def test_greater_than_emits_op_greaterthan
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class GT extends SmartContract {
        readonly limit: bigint;
        constructor(limit: bigint) { super(limit); this.limit = limit; }
        public check(a: bigint): void {
          assert(a > this.limit);
        }
      }
    TS

    artifact = compile_ts_source(source, 'GT.runar.ts')
    assert_includes artifact.asm, 'OP_GREATERTHAN'
  end

  def test_lessthan_or_equal_emits_op_lessthanorequal
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class LE extends SmartContract {
        readonly limit: bigint;
        constructor(limit: bigint) { super(limit); this.limit = limit; }
        public check(a: bigint): void {
          assert(a <= this.limit);
        }
      }
    TS

    artifact = compile_ts_source(source, 'LE.runar.ts')
    assert_includes artifact.asm, 'OP_LESSTHANOREQUAL'
  end

  def test_greaterthan_or_equal_emits_op_greaterthanorequal
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class GE extends SmartContract {
        readonly limit: bigint;
        constructor(limit: bigint) { super(limit); this.limit = limit; }
        public check(a: bigint): void {
          assert(a >= this.limit);
        }
      }
    TS

    artifact = compile_ts_source(source, 'GE.runar.ts')
    assert_includes artifact.asm, 'OP_GREATERTHANOREQUAL'
  end

  # ---------------------------------------------------------------------------
  # Equality / inequality
  # ---------------------------------------------------------------------------

  def test_strict_equality_emits_op_numequal_or_op_equal
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class EQ extends SmartContract {
        readonly target: bigint;
        constructor(target: bigint) { super(target); this.target = target; }
        public check(a: bigint): void {
          assert(a === this.target);
        }
      }
    TS

    artifact = compile_ts_source(source, 'EQ.runar.ts')
    assert(artifact.asm.include?('OP_NUMEQUAL') ||
           artifact.asm.include?('OP_NUMEQUALVERIFY') ||
           artifact.asm.include?('OP_EQUAL') ||
           artifact.asm.include?('OP_EQUALVERIFY'),
           "expected an equality opcode, got: #{artifact.asm[0, 200]}")
  end

  def test_strict_inequality_path_emits_some_negation
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class NEQ extends SmartContract {
        readonly target: bigint;
        constructor(target: bigint) { super(target); this.target = target; }
        public check(a: bigint): void {
          assert(a !== this.target);
        }
      }
    TS

    artifact = compile_ts_source(source, 'NEQ.runar.ts')
    asm = artifact.asm
    # Either an explicit NUMNOTEQUAL or an OP_NOT after an equality.
    assert(asm.include?('OP_NUMNOTEQUAL') || asm.include?('OP_NOT'),
           "expected NUMNOTEQUAL or NOT, got: #{asm[0, 200]}")
  end

  # ---------------------------------------------------------------------------
  # Boolean ops
  # ---------------------------------------------------------------------------

  def test_boolean_and_emits_op_booland
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class B extends SmartContract {
        readonly x: bigint;
        constructor(x: bigint) { super(x); this.x = x; }
        public check(a: boolean, b: boolean): void {
          assert(a && b);
        }
      }
    TS

    artifact = compile_ts_source(source, 'B.runar.ts')
    assert_includes artifact.asm, 'OP_BOOLAND'
  end

  def test_boolean_or_emits_op_boolor
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class B extends SmartContract {
        readonly x: bigint;
        constructor(x: bigint) { super(x); this.x = x; }
        public check(a: boolean, b: boolean): void {
          assert(a || b);
        }
      }
    TS

    artifact = compile_ts_source(source, 'B.runar.ts')
    assert_includes artifact.asm, 'OP_BOOLOR'
  end

  # ---------------------------------------------------------------------------
  # Arithmetic
  # ---------------------------------------------------------------------------

  def test_add_emits_op_add
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class A extends SmartContract {
        readonly target: bigint;
        constructor(target: bigint) { super(target); this.target = target; }
        public check(a: bigint, b: bigint): void {
          assert(a + b == this.target);
        }
      }
    TS

    artifact = compile_ts_source(source, 'A.runar.ts')
    assert_includes artifact.asm, 'OP_ADD'
  end

  def test_sub_emits_op_sub
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class S extends SmartContract {
        readonly target: bigint;
        constructor(target: bigint) { super(target); this.target = target; }
        public check(a: bigint, b: bigint): void {
          assert(a - b == this.target);
        }
      }
    TS

    artifact = compile_ts_source(source, 'S.runar.ts')
    assert_includes artifact.asm, 'OP_SUB'
  end

  def test_mul_emits_op_mul
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class M extends SmartContract {
        readonly target: bigint;
        constructor(target: bigint) { super(target); this.target = target; }
        public check(a: bigint, b: bigint): void {
          assert(a * b == this.target);
        }
      }
    TS

    artifact = compile_ts_source(source, 'M.runar.ts')
    assert_includes artifact.asm, 'OP_MUL'
  end

  def test_div_emits_op_div
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class D extends SmartContract {
        readonly target: bigint;
        constructor(target: bigint) { super(target); this.target = target; }
        public check(a: bigint, b: bigint): void {
          assert(a / b == this.target);
        }
      }
    TS

    artifact = compile_ts_source(source, 'D.runar.ts')
    assert_includes artifact.asm, 'OP_DIV'
  end

  def test_mod_emits_op_mod
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class M extends SmartContract {
        readonly target: bigint;
        constructor(target: bigint) { super(target); this.target = target; }
        public check(a: bigint, b: bigint): void {
          assert(a % b == this.target);
        }
      }
    TS

    artifact = compile_ts_source(source, 'M.runar.ts')
    assert_includes artifact.asm, 'OP_MOD'
  end
end
