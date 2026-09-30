# frozen_string_literal: true

# F-064 — the .runar.ts surface refuses every statement kind outside
# spec/grammar.md §9 with the TS reference's diagnostic,
# "Unsupported statement kind: <ts.SyntaxKind name>", and never drops one.
#
# Pre-fix this parser swallowed stray `;` (skip_semicolons) and fell through to
# the expression parser for every keyword it did not dispatch on: `throw x;`,
# `debugger;` and `break;` became identifier expressions a later pass happened
# to reject, and a nested `;` compiled.
#
# What this proves: the Ruby .runar.ts parser refuses each kind (top level,
# nested in if, in a for body) with the shared diagnostic.
# What it does NOT prove: the other Ruby-tier surfaces (.runar.rb/.sol/...).

require_relative 'test_helper'
require 'runar_compiler/frontend/parser_ts'

class TestF064TsUnsupportedStatement < Minitest::Test
  include RunarCompiler::Frontend

  CASES = [
    ['while (x > 0n) { assert(false); }', 'WhileStatement'],
    ['do { assert(false); } while (x > 0n);', 'DoStatement'],
    ['switch (x) { case 1n: assert(false); break; default: assert(false); }', 'SwitchStatement'],
    ['outer: for (let i = 0n; i < 2n; i++) { assert(false); }', 'LabeledStatement'],
    ['try { assert(false); } catch (e) { assert(false); }', 'TryStatement'],
    ['throw x;', 'ThrowStatement'],
    ['for (const k in this) { assert(false); }', 'ForInStatement'],
    ['for (const k of [x]) { assert(false); }', 'ForOfStatement'],
    ['{ assert(false); }', 'Block'],
    [';', 'EmptyStatement'],
    ['assert(x > 1n);;', 'EmptyStatement'],
    ['const y = x;;', 'EmptyStatement'],
    ['class Inner { }', 'ClassDeclaration'],
    ['function inner(): void { assert(false); }', 'FunctionDeclaration'],
    ['debugger;', 'DebuggerStatement'],
    ['with (x) { assert(false); }', 'WithStatement'],
    ['break;', 'BreakStatement'],
    ['continue;', 'ContinueStatement'],
  ].freeze

  CONTEXTS = [
    '%s',
    'if (x > 0n) { %s }',
    'for (let j = 0n; j < 2n; j++) { %s }',
  ].freeze

  def wrap(stmt)
    <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Probe extends SmartContract {
        readonly a: bigint;

        constructor(a: bigint) {
          super(a);
          this.a = a;
        }

        public unlock(x: bigint) {
          #{stmt}
          assert(x > this.a);
        }
      }
    TS
  end

  def test_every_unsupported_statement_kind_is_refused
    failures = []
    CASES.each do |stmt, kind|
      CONTEXTS.each do |ctx|
        body = format(ctx, stmt)
        messages = RunarCompiler::Frontend.parse_ts(wrap(body), 'Probe.runar.ts').errors.map(&:message)
        want = "Unsupported statement kind: #{kind}"
        failures << "#{body}: want #{want.inspect}, got #{messages.inspect}" unless messages.include?(want)
      end
    end
    assert_empty failures, failures.join("\n")
  end

  def test_well_formed_body_still_parses_clean
    res = RunarCompiler::Frontend.parse_ts(wrap("const y = x + 1n;\n    assert(y > 0n);"), 'Probe.runar.ts')
    assert_empty res.errors
  end
end
