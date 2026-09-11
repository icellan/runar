# frozen_string_literal: true

require_relative "../test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/parser_ts"

# N-092 -- a FixedArray may not be a CONSTRUCTOR PARAMETER.
#
# A property's deploy-time value reaches the locking script through a
# constructor SLOT: the SDK splices `constructorArgs[slot.paramIndex]` into the
# bytes that slot names. `frontend/expand_fixed_arrays.rb` splits a FixedArray
# PROPERTY into scalar siblings, but a constructor PARAMETER has no such
# expansion pass, so there is nothing for an argument to be spliced into.
#
# Five tiers refuse the shape outright for exactly that reason (Go alone
# respells the same rule in its lowercase house style):
#
#     ts / rust / python / java  "Constructor parameter 'xs' cannot be a
#                                 FixedArray. Use initialized properties or
#                                 pass each element as a separate parameter."
#     go                         same rule, lowercase + em-dash
#     zig (before)               ACCEPTS
#     ruby (before)              ACCEPTS
#
# This tier did not merely skip a diagnostic. It COMPILED the source, measured
# before the fix:
#
#     runar-compiler-ruby --source CtorFA.runar.ts --hex  -> 960 hex chars, exit 0
#     artifact constructorSlots: (absent)
#
# No slot on a stateful contract whose ONLY state property is the FixedArray
# means the deployer's argument has nowhere to go: a deployable script whose
# state can never be set from the constructor argument its own ABI advertises
# (the ABI even names `xs__0 / xs__1 / xs__2`, which nothing ever fills). The
# Zig tier emitted the byte-identical script, so the two agreed with each other
# and with nobody else.
#
# The validator carried a comment asserting the opposite -- "the SDK accepts
# FixedArray constructor args and flattens them on behalf of the caller" -- next
# to the method-parameter rule. The empty slot list is the measurement that
# refutes it; the comment is corrected alongside the fix.
class TestN092FixedArrayCtorParam < Minitest::Test
  # The cross-tier diagnostic, spelled exactly as TS / Rust / Python / Java emit
  # it. Asserting on the MESSAGE rather than on "some error occurred" is the
  # point: a rejection for an unrelated reason would otherwise pass here and
  # stop guarding anything.
  CTOR_FA = "Constructor parameter 'xs' cannot be a FixedArray. " \
            "Use initialized properties or pass each element as a separate parameter."

  # The defect: FixedArray constructor parameter on a stateful contract. The
  # body deliberately asserts on the METHOD parameter, not on `this.xs[0]` --
  # the originally filed probe did the latter, which trips an unrelated
  # typechecker path and would have made this file vacuous.
  BAD_STATEFUL = <<~TS
    class CtorFA extends StatefulSmartContract {
      xs: FixedArray<bigint, 3>;

      constructor(xs: FixedArray<bigint, 3>) {
        super(xs);
        this.xs = xs;
      }

      public go(i: bigint) {
        assert(i >= 0n);
      }
    }
  TS

  # The same shape on a STATELESS contract. The five tiers gate on the
  # parameter's type alone, not on the parent class, so scoping the port to
  # StatefulSmartContract would reopen half the hole.
  BAD_STATELESS = <<~TS
    class CtorFAStateless extends SmartContract {
      readonly xs: FixedArray<bigint, 3>;

      constructor(xs: FixedArray<bigint, 3>) {
        super(xs);
        this.xs = xs;
      }

      public go(i: bigint) {
        assert(i >= 0n);
      }
    }
  TS

  # Control 1 -- the SUPPORTED form. A FixedArray PROPERTY with a literal
  # initializer needs no constructor argument, so expansion has something to
  # work with. Must keep compiling, byte-for-byte.
  GOOD_INITIALIZED_PROPERTY = <<~TS
    class CtrlFA extends StatefulSmartContract {
      readonly owner: bigint;
      xs: FixedArray<bigint, 3> = [1n, 2n, 3n];

      constructor(owner: bigint) {
        super(owner);
        this.owner = owner;
      }

      public go(v: bigint) {
        assert(this.owner > 0n);
        this.xs[0] = v;
      }
    }
  TS

  # Control 2 -- a scalar constructor parameter. The rule must key on the
  # parameter's TYPE, not merely on the presence of a constructor parameter.
  GOOD_SCALAR_CTOR_PARAM = <<~TS
    class CtrlScalar extends StatefulSmartContract {
      owner: bigint;

      constructor(owner: bigint) {
        super(owner);
        this.owner = owner;
      }

      public go(i: bigint) {
        assert(i >= this.owner);
      }
    }
  TS

  # Hexes pinned from the pre-fix compiler, so a port that over-reaches and
  # starts refusing legal contracts fails here rather than at conformance time.
  # The Zig tier emits the same bytes for both.
  GOOD_INITIALIZED_PROPERTY_HEX = File.read(
    File.expand_path("fixtures/n092_ctrl_initialized_property.hex", __dir__)
  ).strip
  GOOD_SCALAR_CTOR_PARAM_HEX = File.read(
    File.expand_path("fixtures/n092_ctrl_scalar_ctor_param.hex", __dir__)
  ).strip

  # Parse + validate a `.runar.ts` source, returning the validation error
  # strings. A parse failure raises rather than being counted as a rejection.
  def validation_errors(source, file_name = "N092.runar.ts")
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract, "fixture did not parse"

    RunarCompiler.send(:_validate, parse_result.contract).errors.map(&:format_message)
  end

  # Compile a source end-to-end through the CLI's own path and return the hex.
  def compile_hex(source, file_name)
    require "tempfile"
    tmp = Tempfile.new([File.basename(file_name, ".runar.ts"), ".runar.ts"])
    tmp.write(source)
    tmp.close
    program = RunarCompiler.compile_source_to_ir(tmp.path, disable_constant_folding: true)
    RunarCompiler.compile_from_program(program, disable_constant_folding: true).script
  ensure
    tmp&.unlink
  end

  # -- the defect ----------------------------------------------------------

  def test_fixed_array_constructor_parameter_is_a_validation_error
    errors = validation_errors(BAD_STATEFUL)
    assert(
      errors.any? { |e| e.include?(CTOR_FA) },
      "expected the cross-tier diagnostic, got: #{errors.inspect}"
    )
  end

  def test_the_rule_is_not_scoped_to_stateful_contracts
    errors = validation_errors(BAD_STATELESS, "CtorFAStateless.runar.ts")
    assert(
      errors.any? { |e| e.include?(CTOR_FA) },
      "expected the cross-tier diagnostic, got: #{errors.inspect}"
    )
  end

  def test_the_whole_compile_refuses_it_so_no_locking_script_is_emitted
    err = assert_raises(RunarCompiler::CompilationError) do
      compile_hex(BAD_STATEFUL, "CtorFA.runar.ts")
    end
    assert_includes err.message, CTOR_FA
  end

  # -- cross-surface: a SEPARATE gap, deliberately not asserted here --------
  #
  # The Solidity surface can express this shape -- `constructor(bigint[3] xs)`
  # -- and Go / Rust / Python parse it and then reject it with this same rule.
  # THIS tier's Solidity parser cannot parse an array-typed parameter at all:
  #
  #   ruby: line 6: expected token kind 1, got 8 ("[")
  #   zig:  parse error: expected parameter name after type 'bigint'
  #
  # So a `.runar.sol` probe is refused here for the wrong reason, and asserting
  # on it would be the bare-catch anti-pattern in a new costume. That parser
  # hole is a frontend-parity finding of its own (CLAUDE.md invariant 1: all
  # seven tiers parse all nine surfaces) and is filed separately rather than
  # papered over with a green test.

  # -- controls: the supported forms must be byte-unchanged -----------------

  def test_control_fixed_array_property_with_initializer_still_compiles_unchanged
    assert_equal GOOD_INITIALIZED_PROPERTY_HEX,
                 compile_hex(GOOD_INITIALIZED_PROPERTY, "CtrlFA.runar.ts")
  end

  def test_control_scalar_constructor_parameter_still_compiles_unchanged
    assert_equal GOOD_SCALAR_CTOR_PARAM_HEX,
                 compile_hex(GOOD_SCALAR_CTOR_PARAM, "CtrlScalar.runar.ts")
  end
end
