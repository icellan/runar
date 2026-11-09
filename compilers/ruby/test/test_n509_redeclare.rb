# frozen_string_literal: true

# N-509: a local cannot be re-declared in the same scope (spec/grammar.md).
# One scope = one statement list; a method's parameters belong to its body's
# top-level list. Shadowing in a NESTED list is not a re-declaration.
# Mirrors packages/runar-compiler/src/__tests__/02-validate.test.ts (N-509).

require_relative "test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/parser_ts"

class TestN509Redeclare < Minitest::Test
  DEFAULT_CTOR = "super(k);\n    this.k = k;"

  def source(body, ctor = DEFAULT_CTOR)
    "\nclass R extends SmartContract {\n  readonly k: bigint;\n  constructor(k: bigint) {\n    #{ctor}\n  }\n" \
      "  public unlock(p: bigint, c: boolean) {\n    #{body}\n  }\n}\n"
  end

  def msg(name)
    "'#{name}' is already declared in this scope and cannot be re-declared"
  end

  def errors(src)
    result = RunarCompiler.send(:_parse_source, src, "R.runar.ts")
    assert_empty result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil result.contract
    RunarCompiler::Frontend.validate(result.contract).errors
  end

  REFUSED = [
    ["const a = 1n; const a = 2n; assert(a == p);", "a"],
    ["let x = 1n; let x = 2n; assert(x == p);", "x"],
    ["const a = 1n; let a = 2n; a = 3n; assert(a == p);", "a"],
    ["if (c) { let y = 1n; let y = 2n; assert(y == p); } assert(c);", "y"],
    ["if (c) { assert(c); } else { let y = 1n; let y = 2n; assert(y == p); }", "y"],
    ["let s = 0n; for (let i = 0n; i < 2n; i++) { let t = i; let t = i; s = s + t; } assert(s == p);", "t"],
    ["let p = 5n; assert(p == this.k && c);", "p"],
    ["assert(p == this.k && c);", "k", "super(k);\n    this.k = k;\n    const k = 2n;\n    assert(k > 0n);"],
  ].freeze

  def test_refuses_same_scope_redeclaration
    REFUSED.each do |body, name, ctor|
      hits = errors(source(body, ctor || DEFAULT_CTOR)).count { |d| d.message == msg(name) }
      assert_equal 1, hits, "want exactly one #{msg(name).inspect} for #{body}"
    end
  end

  def test_reports_the_second_declaration
    hit = errors(source("const a = 1n;\n    const a = 2n;\n    assert(a == p);")).find { |d| d.message == msg("a") }
    refute_nil hit, "no re-declaration error"
    assert_equal 10, hit.loc.line
  end

  ACCEPTED = [
    "let x = 1n; if (c) { let x = 2n; assert(x == 2n); } assert(x == p);",
    "if (c) { let p = 5n; assert(p == 5n); } assert(p == this.k);",
    "const k = 5n; assert(k == p + this.k && c);",
    "let s = 0n; for (let i = 0n; i < 2n; i++) { let i = 7n; s = s + i; } assert(s == p && c);",
    "if (c) { let y = 1n; assert(y == p); } else { let y = 2n; assert(y == p); }",
    "if (c) { let y = 1n; assert(y == p); } let y = 2n; assert(y == p);",
    "let s = 0n; for (let i = 0n; i < 2n; i++) { s = s + i; } for (let i = 0n; i < 3n; i++) { s = s + i; } assert(s == p && c);",
  ].freeze

  def test_accepts_shadowing_and_siblings
    ACCEPTED.each do |body|
      hits = errors(source(body)).select { |d| d.message.include?("already declared") }.map(&:message)
      assert_empty hits, "unexpected for #{body}"
    end
  end
end
