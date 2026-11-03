# frozen_string_literal: true

require_relative "test_helper"
require "runar_compiler/codegen/stack"

# F-258 / CL-BUG-151 -- codegen's non-literal property-initializer fallback
# emitted a silent OP_0.
#
# The language only allows literal property initializers (BigIntLiteral /
# BoolLiteral / ByteStringLiteral -- see CLAUDE.md "Property initializers").
# The frontend enforces that, but `--ir` skips the frontend entirely (same
# shape as R-012 / R-122), so a hand-written IR file can give a property a
# non-literal (array/object) `initialValue`. `_push_property_value`'s default
# case used to silently push 0 for any value it did not recognize --
# compiling cleanly to a script that always reads the property as 0, with no
# diagnostic.
class TestF258HostileIR < Minitest::Test
  def test_non_literal_property_initializer_is_a_loud_error_not_op0
    program = {
      "contractName" => "HostilePropInit",
      "properties" => [
        { "name" => "secret", "type" => "bigint", "readonly" => true, "initialValue" => [1, 2, 3] }
      ],
      "methods" => [
        {
          "name" => "reveal",
          "isPublic" => true,
          "params" => [],
          "body" => [
            { "name" => "t0", "value" => { "kind" => "load_prop", "name" => "secret" } },
            { "name" => "t1", "value" => { "kind" => "assert", "value" => "t0" } }
          ]
        }
      ]
    }

    err = assert_raises(RuntimeError) do
      RunarCompiler.compile_from_ir_bytes(JSON.dump(program))
    end
    assert_match(/secret/, err.message)
    assert_match(/Refusing to emit a silent OP_0/, err.message)
  end

  def test_literal_property_initializer_still_compiles
    # Control: an ordinary literal initializer must still compile through
    # _push_property_value's non-default arms.
    program = {
      "contractName" => "LiteralPropInit",
      "properties" => [
        { "name" => "threshold", "type" => "bigint", "readonly" => true, "initialValue" => 42 }
      ],
      "methods" => [
        {
          "name" => "check",
          "isPublic" => true,
          "params" => [],
          "body" => [
            { "name" => "t0", "value" => { "kind" => "load_prop", "name" => "threshold" } },
            { "name" => "t1", "value" => { "kind" => "assert", "value" => "t0" } }
          ]
        }
      ]
    }

    artifact = RunarCompiler.compile_from_ir_bytes(JSON.dump(program))
    refute_nil artifact.script
    refute_empty artifact.script
  end
end
