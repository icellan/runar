# frozen_string_literal: true

# N-153 — a .runar.go statement that starts with `{` is refused with the TS
# reference's diagnostic, "Unexpected token in expression: '{'".
#
# Pre-fix this parser (like the TS reference) read it as a brace composite
# literal: `{ x, c.check(x) }`, which is not Go, compiled, while real Go blocks
# were refused for unrelated reasons. User decision on the N-153 escalation:
# refuse it in every tier.
#
# What this proves: the Ruby .runar.go parser refuses each statement-position
# `{` shape with the shared diagnostic and still parses a composite literal in
# expression position.
# What it does NOT prove: other tiers (conformance/negatives N191 / N192 and
# n153-statement-shape-parity.test.ts).

require_relative 'test_helper'
require 'runar_compiler/frontend/input_limits'
require 'runar_compiler/compiler'
require 'runar_compiler/frontend/parser_go'

class TestN153GoBraceStatement < Minitest::Test
  def wrap(stmt)
    <<~GO
      package contract

      import runar "github.com/icellan/runar/packages/runar-go"

      type Disc struct {
      \trunar.SmartContract
      \tT runar.Bigint `runar:"readonly"`
      }

      func (c *Disc) Unlock(x runar.Bigint) {
      \t#{stmt}
      \trunar.Assert(true)
      }

      func (c *Disc) check(x runar.Bigint) runar.Bigint {
      \trunar.Assert(x == c.T)
      \treturn x
      }
    GO
  end

  def messages(stmt)
    RunarCompiler::Frontend.parse_go(wrap(stmt), 'Disc.runar.go').errors.map(&:message)
  end

  WANT = "Unexpected token in expression: '{'"

  def test_statement_starting_with_a_brace_is_refused
    failures = []
    [
      '{ runar.Assert(x == c.T) }',
      '{ x, c.check(x) }',
      '{ }',
      "{\n\t\ty := x\n\t\trunar.Assert(y == c.T)\n\t}",
      "if x == c.T {\n\t\t{ runar.Assert(true) }\n\t}",
    ].each do |stmt|
      got = messages(stmt)
      failures << "#{stmt.inspect}: got #{got.inspect}" unless got.any? { |m| m.include?(WANT) }
    end
    assert_empty failures, failures.join("\n")
  end

  def test_expression_position_composite_literal_still_parses
    assert_empty messages("y := [2]runar.Bigint{x, c.T}\n\t_ = y")
  end
end
