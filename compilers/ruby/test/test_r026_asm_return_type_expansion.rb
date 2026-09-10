# frozen_string_literal: true

require 'tempfile'
require_relative 'test_helper'
require 'runar_compiler/frontend/parser_ts'
require 'runar_compiler/frontend/expand_fixed_arrays'

# R-026 — `expand_fixed_arrays` must not drop `CallExpr#asm_return_type`.
#
# `rewrite_expression` and `clone_expr` both rebuilt every `CallExpr` by naming
# its fields, and neither named `asm_return_type`. That field carries the
# captured return type of an expression-form `asm<T>({...})`, which is what
# tells ANF lowering the value is byte-typed — and that is what makes `+` lower
# to OP_CAT instead of OP_ADD. Losing it emits a different opcode, so the
# script computes a numeric sum where the author wrote a concatenation.
#
# The pass only runs when the contract also declares a FixedArray property,
# which is why the control below (same body, no array) already emitted OP_CAT
# and discriminates the expansion path as the cause.
class TestR026AsmReturnTypeExpansion < Minitest::Test
  include RunarCompiler::Frontend

  ARRAY_PROP = "  readonly board: FixedArray<bigint, 3> = [1n, 2n, 3n];\n"

  def source(array_prop, tail)
    <<~TS
      class Boardy extends UnsafeSmartContract {
      #{array_prop}  readonly n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        public go(): void {
          const a: ByteString = asm<ByteString>({ body: '00', in_arity: 0, out_arity: 1 });
          const c: ByteString = a + a;
          assert(len(c) === 2n);
      #{tail}  }
      }
    TS
  end

  def with_array
    source(ARRAY_PROP, "    assert(this.board[0] === this.n);\n")
  end

  def without_array
    source('', "    assert(this.n === this.n);\n")
  end

  def compile_ok(src)
    tf = Tempfile.new(['Boardy', '.runar.ts'])
    tf.write(src)
    tf.close
    RunarCompiler.compile_from_source(tf.path, disable_constant_folding: true)
  end

  def test_asm_return_type_survives_fixed_array_expansion
    parsed = RunarCompiler.send(:_parse_source, with_array, 'Boardy.runar.ts')
    assert_empty parsed.errors.map(&:message)

    result = RunarCompiler::Frontend.expand_fixed_arrays(parsed.contract)
    assert_empty result.errors.map(&:message)

    go = result.contract.methods.find { |m| m.name == 'go' }
    decl = go.body[0]
    assert_equal 'a', decl.name
    assert_equal 'ByteString', decl.init.asm_return_type,
                 'expand_fixed_arrays dropped CallExpr#asm_return_type'
  end

  def test_byte_concat_emits_op_cat_not_op_add
    ops = compile_ok(with_array).asm.split
    assert_includes ops, 'OP_CAT',
                    "byte concat lowered to numeric OP_ADD after expansion: #{ops.join(' ')}"
    refute_includes ops, 'OP_ADD', ops.join(' ')
  end

  def test_control_without_fixed_array_is_unchanged
    ops = compile_ok(without_array).asm.split
    assert_includes ops, 'OP_CAT', ops.join(' ')
    refute_includes ops, 'OP_ADD', ops.join(' ')
  end
end
