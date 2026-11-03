# frozen_string_literal: true

# N-012 -- the validator's expression walker covers a `for` loop's header.
#
# Proves: walk_expressions_in_stmt (the walker behind the asm() gate) visits all
# three header slots of a `for` statement -- init, condition and update -- so an
# asm(...) call planted in any of them in a non-Unsafe contract is refused. The
# AST is hand-built (mutated after parsing) because the for-update and
# literal-init rules make these shapes unreachable from source today.
#
# Does NOT prove: that any source program can reach this; only that a future
# loosening of those rules cannot reopen the asm gate through the walker.

require_relative 'test_helper'
require 'runar_compiler/frontend/parser_ts'

class TestN012ForHeaderWalker < Minitest::Test
  include RunarCompiler::Frontend

  SOURCE = <<~TS
    class C extends SmartContract {
      readonly t: bigint;
      constructor(t: bigint) { super(t); this.t = t; }
      public verify(a: bigint) {
        let s: bigint = 0n;
        for (let i: bigint = 0n; i < 3n; i++) { s = s + a; }
        assert(s === this.t);
      }
    }
  TS

  DIAG = "'asm' is only available in contracts extending UnsafeSmartContract"

  def asm_call
    CallExpr.new(callee: Identifier.new(name: 'asm'), args: [])
  end

  %w[init condition update].each do |slot|
    define_method("test_asm_in_for_#{slot}_is_refused") do
      parsed = RunarCompiler::Frontend.parse_ts(SOURCE, 'C.runar.ts')
      assert_empty parsed.errors
      contract = parsed.contract
      loop_stmt = contract.methods[0].body.find { |s| s.is_a?(ForStmt) }
      refute_nil loop_stmt
      case slot
      when 'init' then loop_stmt.init.init = asm_call
      when 'condition' then loop_stmt.condition = asm_call
      else loop_stmt.update = ExpressionStmt.new(expr: asm_call, source_location: loop_stmt.source_location)
      end

      messages = RunarCompiler::Frontend.validate(contract).errors.map(&:message)
      assert(messages.any? { |m| m.include?(DIAG) },
             "asm() in for-loop #{slot} was not refused; got #{messages.inspect}")
    end
  end
end
