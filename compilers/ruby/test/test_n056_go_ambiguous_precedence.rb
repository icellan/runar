# frozen_string_literal: true

require_relative 'test_helper'

# N-056 (CL-BUG-192) -- .runar.go operator precedence differed across tiers.
#
# The Go tier parses .runar.go with go/parser (Go precedence); this tier, the
# TS reference and the other four use the C ladder, so `a & b + 1` was
# `(a & b) + 1` in one tier and `a & (b + 1)` in the rest. R51: every tier
# refuses an unparenthesised mix whose grouping differs between the two
# schemes, with the shared diagnostic from 01-parse-go.ts.
#
# The oracle recomputes the 72 ambiguous ordered operator pairs from the two
# precedence tables rather than reusing the parser's constant.
#
# What this proves: this tier refuses every ambiguous pair with the shared
# text, accepts the 252 agreeing pairs and both parenthesisations, and treats
# `&^` as `&` and call results as operands.
# What it does not prove: emitted bytes or the other tiers (conformance
# negatives N175-N179 and the agreeing-pairs control cover cross-tier
# agreement).
class TestN056GoAmbiguousPrecedence < Minitest::Test
  require 'runar_compiler/frontend/parser_go'

  GO_PREC = {
    '*' => 5, '/' => 5, '%' => 5, '<<' => 5, '>>' => 5, '&' => 5,
    '+' => 4, '-' => 4, '|' => 4, '^' => 4,
    '==' => 3, '!=' => 3, '<' => 3, '<=' => 3, '>' => 3, '>=' => 3,
    '&&' => 2, '||' => 1
  }.freeze
  C_PREC = {
    '*' => 10, '/' => 10, '%' => 10, '+' => 9, '-' => 9, '<<' => 8, '>>' => 8,
    '<' => 7, '<=' => 7, '>' => 7, '>=' => 7, '==' => 6, '!=' => 6,
    '&' => 5, '^' => 4, '|' => 3, '&&' => 2, '||' => 1
  }.freeze

  def n056_message(x, y)
    "ambiguous operator precedence in .runar.go: `a #{x} b #{y} c` groups differently " \
      "under Go precedence than in Rúnar's other surfaces; add parentheses"
  end

  def errors_of(expr)
    src = <<~GO
      package contract

      import runar "github.com/icellan/runar/packages/runar-go"

      type Probe struct {
      	runar.SmartContract
      	T runar.Int `runar:"readonly"`
      }

      func (c *Probe) Unlock(a runar.Int, b runar.Int, d runar.Int) {
      	x := #{expr}
      	runar.Assert(x == c.T)
      }
    GO
    RunarCompiler.send(:_parse_source, src, 'Probe.runar.go').errors.map(&:message)
  end

  def test_every_pair
    conflicts = 0
    agree = 0
    failures = []
    GO_PREC.each_key do |x|
      GO_PREC.each_key do |y|
        expr = "a #{x} b #{y} d"
        if (GO_PREC[x] >= GO_PREC[y]) != (C_PREC[x] >= C_PREC[y])
          conflicts += 1
          failures << "#{expr} not refused" unless errors_of(expr).include?(n056_message(x, y))
          ["(a #{x} b) #{y} d", "a #{x} (b #{y} d)"].each do |ok|
            got = errors_of(ok)
            failures << "#{ok}: #{got}" unless got.empty?
          end
        else
          agree += 1
          got = errors_of(expr)
          failures << "#{expr}: #{got}" unless got.empty?
        end
      end
    end
    assert_equal [72, 252], [conflicts, agree]
    assert_empty failures, failures.join("\n")
  end

  PROBES = [
    ['a & b + 1', %w[& +]],
    ['a + b << 2', %w[+ <<]],
    ['a | b + d', %w[| +]],
    ['a & 255 == 15', %w[& ==]],
    ['a ^ b * d', nil],
    ['(a & b + 1) * d', %w[& +]],
    ['runar.Abs(a + b << 2)', %w[+ <<]],
    ['a * (d + (a | b + d))', %w[| +]],
    ['a + b * d - a', nil],
    ['a * b + d << 1', %w[+ <<]],
    ['a &^ b', nil],
    ['a &^ b + d', %w[& +]],
    ['(a &^ b) + d', nil],
    ['runar.BigintBigAdd(a, b) << 2', nil],
    ['runar.Abs(a + b) << 2', nil],
    ['-a + b << 2', %w[+ <<]],
    ['-(a + b) << 2', nil]
  ].freeze

  def test_probes
    failures = []
    PROBES.each do |expr, pair|
      got = errors_of(expr)
      if pair.nil?
        failures << "#{expr}: #{got}" unless got.empty?
      else
        failures << "#{expr} not refused: #{got}" unless got.include?(n056_message(*pair))
      end
    end
    assert_empty failures, failures.join("\n")
  end
end
