# frozen_string_literal: true

# N-262 -- +lower_if+ phase 3 must refuse to pad a NON-EMPTY arm.
#
# Phase 3 balances the two arms of an OP_IF by pushing an OP_0 on the shallower
# one. Padding an arm with NO bindings is the legitimate #99 fallback; padding an
# arm that DID compute something writes a placeholder the post-ENDIF code reads
# as a value (the OP_0-in-the-taken-arm shape). Go has refused it since R-161;
# the other six tiers padded silently.
#
# The program is hand-built --ir input: an arm ending in a non-terminal +assert+
# is one slot shallower than a sibling arm that leaves a value.
#
# Proves: both padding directions fail with the shared internal-codegen sentence
# (same words as compilers/go/codegen/stack.go), and padding an EMPTY arm still
# compiles. Does not prove that no source program reaches the guard (golden
# conformance covers the corpus).

require_relative "test_helper"
require "json"

class TestN262NonEmptyArmPadding < Minitest::Test
  VALUE_ARM = [{ "name" => "a", "value" => { "kind" => "load_const", "value" => 1 } }].freeze
  ASSERT_ARM = [
    { "name" => "k", "value" => { "kind" => "load_const", "value" => 1 } },
    { "name" => "k2", "value" => { "kind" => "assert", "value" => "k" } }
  ].freeze

  def ir(then_arm, else_arm)
    JSON.generate(
      "contractName" => "P", "properties" => [],
      "methods" => [{
        "name" => "m", "isPublic" => true,
        "params" => [{ "name" => "x", "type" => "bigint" }],
        "body" => [
          { "name" => "t0", "value" => { "kind" => "load_param", "name" => "x" } },
          { "name" => "t1", "value" => { "kind" => "load_const", "value" => 0 } },
          { "name" => "t2", "value" => { "kind" => "bin_op", "op" => ">", "left" => "t0", "right" => "t1" } },
          { "name" => "t3", "value" => { "kind" => "if", "cond" => "t2", "then" => then_arm, "else" => else_arm } },
          { "name" => "t4", "value" => { "kind" => "assert", "value" => "t3" } }
        ]
      }]
    )
  end

  def test_non_empty_else_arm_is_never_padded
    err = assert_raises(StandardError) { RunarCompiler.compile_from_ir_bytes(ir(VALUE_ARM, ASSERT_ARM)) }
    assert_includes err.message,
                    "internal codegen error: conditional needs 1 placeholder push(es) to balance " \
                    "a NON-EMPTY else arm (then depth 1 != else depth 0)"
    assert_includes err.message, 'binding="t3"'
  end

  def test_non_empty_then_arm_is_never_padded
    err = assert_raises(StandardError) { RunarCompiler.compile_from_ir_bytes(ir(ASSERT_ARM, VALUE_ARM)) }
    assert_includes err.message,
                    "internal codegen error: conditional needs 1 placeholder push(es) to balance " \
                    "a NON-EMPTY then arm (else depth 1 != then depth 0)"
    assert_includes err.message, 'binding="t3"'
  end

  def test_empty_else_arm_is_still_padded
    refute_empty RunarCompiler.compile_from_ir_bytes(ir(VALUE_ARM, [])).script
  end
end
