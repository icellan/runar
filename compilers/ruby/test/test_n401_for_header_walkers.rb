# frozen_string_literal: true

# N-401 -- the validator's statement walkers cover a `for` loop's header.
#
# Proves: collect_method_calls (behind the recursion check) and
# find_output_intrinsic (behind the no-addOutput-in-a-loop rule) visit all three
# header slots of a `for` statement -- init, condition and update. A
# `this.m()` call planted only in a header slot is seen by the call graph (so
# self-recursion through a header is refused), and an addOutput planted only in
# a NESTED loop's header is found from the enclosing loop. The AST is
# hand-built (mutated after parsing) because the for-update and literal-init
# rules make these shapes unreachable from source today.
#
# Does NOT prove: that any source program can reach these shapes today.

require_relative 'test_helper'
require 'runar_compiler/frontend/parser_ts'

class TestN401ForHeaderWalkers < Minitest::Test
  include RunarCompiler::Frontend

  PLAIN_SOURCE = <<~TS
    class C extends SmartContract {
      readonly t: bigint;
      constructor(t: bigint) { super(t); this.t = t; }
      public m(a: bigint) {
        let s: bigint = 0n;
        for (let i: bigint = 0n; i < 3n; i++) { s = s + a; }
        assert(s === this.t);
      }
    }
  TS

  NESTED_SOURCE = <<~TS
    class C extends StatefulSmartContract {
      count: bigint;
      constructor(count: bigint) { super(count); this.count = count; }
      public m(a: bigint) {
        let s: bigint = 0n;
        for (let i: bigint = 0n; i < 3n; i++) {
          for (let j: bigint = 0n; j < 3n; j++) { s = s + a; }
        }
        this.count = s;
      }
    }
  TS

  def this_call(name)
    CallExpr.new(callee: PropertyAccessExpr.new(property: name), args: [])
  end

  def plant(loop_stmt, slot, expr)
    case slot
    when 'init' then loop_stmt.init.init = expr
    when 'condition' then loop_stmt.condition = expr
    else loop_stmt.update = ExpressionStmt.new(expr: expr, source_location: loop_stmt.source_location)
    end
  end

  def parse(source)
    parsed = RunarCompiler::Frontend.parse_ts(source, 'C.runar.ts')
    assert_empty parsed.errors
    parsed.contract
  end

  %w[init condition update].each do |slot|
    define_method("test_recursion_through_for_#{slot}_is_seen") do
      contract = parse(PLAIN_SOURCE)
      loop_stmt = contract.methods[0].body.find { |s| s.is_a?(ForStmt) }
      refute_nil loop_stmt
      plant(loop_stmt, slot, this_call('m'))
      messages = RunarCompiler::Frontend.validate(contract).errors.map(&:message)
      assert(messages.any? { |m| m.downcase.include?('recursion detected') },
             "call in for-loop #{slot} was not collected; got #{messages.inspect}")
    end

    define_method("test_add_output_in_nested_for_#{slot}_is_found") do
      contract = parse(NESTED_SOURCE)
      outer = contract.methods[0].body.find { |s| s.is_a?(ForStmt) }
      refute_nil outer
      inner = outer.body.find { |s| s.is_a?(ForStmt) }
      refute_nil inner
      plant(inner, slot, this_call('addOutput'))
      messages = RunarCompiler::Frontend.validate(contract).errors.map(&:message)
      assert(messages.any? { |m| m.include?("Output intrinsic 'addOutput'") },
             "addOutput in nested for-loop #{slot} was not found; got #{messages.inspect}")
    end
  end
end
