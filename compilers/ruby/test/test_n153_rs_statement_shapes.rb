# frozen_string_literal: true

# N-153 — the .runar.rs surface refuses a token that cannot start an
# expression with the TS reference's diagnostic,
# "Unexpected token in expression: '<token>'", and never drops a statement.
#
# Pre-fix the expression parser's fallback skipped the token and returned the
# literal 0 without a diagnostic. On a bare block `{ assert!(true); }` the
# block's `}` then closed the METHOD and every statement after it was skipped
# as impl-level junk: `{ assert!(true); } assert!(x == self.t);` compiled to
# 00517777, which any x unlocks (proved under @bsv/sdk Spend in
# conformance/negatives/n153-statement-shape-parity.test.ts). `;` became a
# stray literal 0.
#
# What this proves: the Ruby .runar.rs parser refuses a bare block and an
# empty statement with the shared diagnostic, and still parses `let _ = ...;`,
# a parenthesised call statement and a trailing `;` after a statement.
# What it does NOT prove: the other Ruby-tier surfaces (see N-053 / F-064).

require_relative 'test_helper'
require 'runar_compiler/frontend/input_limits'
require 'runar_compiler/compiler'
require 'runar_compiler/frontend/parser_rust'

class TestN153RsStatementShapes < Minitest::Test
  def wrap(body)
    <<~RS
      use runar::prelude::*;

      #[runar::contract]
      pub struct Disc {
          #[readonly]
          pub t: Bigint,
      }

      impl Disc {
          pub fn unlock(&self, x: Bigint) {
              #{body}
          }

          fn check(&self, x: Bigint) -> Bigint {
              assert!(x == self.t);
              x
          }
      }
    RS
  end

  def messages(body)
    RunarCompiler::Frontend.parse_rust(wrap(body), 'Disc.runar.rs').errors.map(&:message)
  end

  REFUSED = [
    ["{ assert!(true); }\n        assert!(x == self.t);", '{'],
    ["{ assert!(x == self.t); }\n        assert!(true);", '{'],
    ["let y = x + 1;\n        { assert!(y == self.t); }", '{'],
    [";\n        assert!(x == self.t);", ';'],
    ["assert!(x == self.t);;", ';'],
  ].freeze

  def test_bare_block_and_empty_statement_are_refused
    failures = []
    REFUSED.each do |body, tok|
      want = "Unexpected token in expression: '#{tok}'"
      got = messages(body)
      failures << "#{body.inspect}: want #{want.inspect}, got #{got.inspect}" unless got.include?(want)
    end
    assert_empty failures, failures.join("\n")
  end

  def test_well_formed_statements_still_parse_clean
    [
      "self.check(x);\n        assert!(true);",
      "let _ = self.check(x);\n        assert!(true);",
      "(self.check(x));\n        assert!(true);",
      "assert!(x == self.t);",
    ].each do |body|
      assert_empty messages(body), body
    end
  end
end
