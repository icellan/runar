# frozen_string_literal: true

require_relative "test_helper"

# R-021 (CL-BUG-155): the continuation-shape walkers must descend into
# variable-declaration initialisers.
#
# +_stmt_mutates_state+, +_stmt_has_add_output+ and +_stmt_has_add_data_output+
# in +anf_lower.rb+ handled only ExpressionStmt / IfStmt / ForStmt / ReturnStmt.
# A +VariableDeclStmt+ was invisible, so a side effect reachable only through a
# variable-declaration initialiser never reached +needs_change_output+ /
# +needs_new_amount+ / +is_terminal+.
#
# The four tiers that ship a dedicated +side_effect_summary+ module (TS, Go,
# Rust, Python) walk the initialiser, so this is a cross-tier divergence, and
# the divergence is unsafe in both of its two shapes:
#
#   1. Output intrinsic behind the initialiser -- the private helper IS
#      ANF-inlined (+should_inline_private?+ asks the HELPER, which does see its
#      own +addOutput+), so the body emits the add_output node and loads
#      +_changePKH+, but the method header never declared it. Stack lowering
#      then refuses with "method parameter '_changePKH' is not on the stack".
#      A hard failure -- loud, but a compile of valid Rúnar that four other
#      tiers accept.
#
#   2. State mutation behind the initialiser -- mutation-only helpers are NOT
#      inlined, so nothing trips. The method is silently classified TERMINAL:
#      no continuation params, no +get_state_script+, no covenant. The deployed
#      script binds NOTHING about where the value goes, and a spender can take
#      the whole UTXO anywhere. Silent, and a funds bug.
#
# Reference ABIs below are the TypeScript compiler's own output for the same
# sources.
class TestR021VarDeclSideEffectDescent < Minitest::Test
  # --------------------------------------------------------------------
  # Fixtures
  # --------------------------------------------------------------------

  # Shape 1: `this.addOutput` reachable only through a var-decl initialiser.
  VARDECL_OUTPUT = <<~TS
    class VarDeclOutput extends StatefulSmartContract {
      a: bigint;

      constructor(a: bigint) {
        super(a);
        this.a = a;
      }

      private emitAndReturn(amount: bigint): bigint {
        this.addOutput(1000n, this.a);
        return amount;
      }

      public settle(amount: bigint) {
        const paid: bigint = this.emitAndReturn(amount);
        assert(paid > 0n);
      }
    }
  TS

  # Shape 2: state mutation reachable only through a var-decl initialiser.
  VARDECL_MUTATION = <<~TS
    class VarDeclMutation extends StatefulSmartContract {
      a: bigint;

      constructor(a: bigint) {
        super(a);
        this.a = a;
      }

      private bump(x: bigint): bigint {
        this.a = this.a + 1n;
        return x;
      }

      public settle(amount: bigint) {
        const paid: bigint = this.bump(amount);
        assert(paid > 0n);
      }
    }
  TS

  # Control: the identical effect reached from a bare expression statement.
  # This shape already worked and must keep working.
  STMT_OUTPUT = <<~TS
    class StmtOutput extends StatefulSmartContract {
      a: bigint;

      constructor(a: bigint) {
        super(a);
        this.a = a;
      }

      private emitAndReturn(amount: bigint): bigint {
        this.addOutput(1000n, this.a);
        return amount;
      }

      public settle(amount: bigint) {
        this.emitAndReturn(amount);
        assert(amount > 0n);
      }
    }
  TS

  # --------------------------------------------------------------------
  # Helpers
  # --------------------------------------------------------------------

  def compile_ts(source, file_name)
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty parse_result.errors.map(&:to_s), "parse errors"
    refute_nil parse_result.contract

    val_result = RunarCompiler.send(:_validate, parse_result.contract)
    assert_empty val_result.errors.map(&:format_message), "validation errors"

    tc_result = RunarCompiler.send(:_type_check, parse_result.contract)
    assert_empty tc_result.errors.map(&:format_message), "type check errors"

    program = RunarCompiler.send(:_lower_to_anf, parse_result.contract)
    RunarCompiler.compile_from_program(program, disable_constant_folding: true)
  end

  def settle_params(source, file_name)
    artifact = compile_ts(source, file_name)
    method = artifact.abi.methods.find { |m| m.name == "settle" }
    refute_nil method, "settle missing from ABI"
    method.params.map(&:name)
  end

  # --------------------------------------------------------------------
  # Control -- already green; guards against over-correction.
  # --------------------------------------------------------------------

  def test_control_output_from_bare_statement_gets_continuation_params
    assert_equal %w[amount _changePKH _changeAmount txPreimage],
                 settle_params(STMT_OUTPUT, "StmtOutput.runar.ts"),
                 "control regressed: a bare-statement addOutput lost its continuation params"
  end

  # --------------------------------------------------------------------
  # Shape 1 -- output intrinsic behind a var-decl initialiser.
  # --------------------------------------------------------------------

  def test_vardecl_output_compiles_and_declares_change_params
    assert_equal %w[amount _changePKH _changeAmount txPreimage],
                 settle_params(VARDECL_OUTPUT, "VarDeclOutput.runar.ts"),
                 "an addOutput reached through a var-decl initialiser did not reach " \
                 "the continuation-shape decision (TS/Go/Rust/Python all declare " \
                 "_changePKH/_changeAmount here)"
  end

  # --------------------------------------------------------------------
  # Shape 2 -- state mutation behind a var-decl initialiser.
  # --------------------------------------------------------------------

  def test_vardecl_mutation_is_not_terminal
    assert_equal %w[amount _changePKH _changeAmount _newAmount txPreimage],
                 settle_params(VARDECL_MUTATION, "VarDeclMutation.runar.ts"),
                 "a state mutation reached through a var-decl initialiser was " \
                 "classified TERMINAL: the deployed script carries no continuation " \
                 "covenant and a spender can take the UTXO anywhere"
  end

  def test_vardecl_mutation_emits_a_state_continuation
    artifact = compile_ts(VARDECL_MUTATION, "VarDeclMutation.runar.ts")
    method = artifact.abi.methods.find { |m| m.name == "settle" }
    refute method.is_terminal,
           "settle was marked isTerminal despite mutating state through a var-decl initialiser"
  end
end
