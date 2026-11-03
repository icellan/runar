# frozen_string_literal: true

# N-154 — a .runar.go `;` that separates statements on one line is accepted
# (user decision R56: it is valid Go), byte-identical to the newline form. An
# empty statement stays refused (N-153), with the TS reference's diagnostic.
#
# Pre-fix this parser's expression fallback read the `;` as an identifier
# named ";": `a := x + 1; b := a + 2` failed downstream, and a trailing
# `runar.Assert(x == c.T);` became a final statement that was not an assert.
#
# What this proves: the Ruby .runar.go parser compiles each same-line `;`
# form to the hex of its newline form, and refuses `;;`, `; ;`, `{;` and a
# `;` on the line after a bare `return` with
# "Unexpected token in expression: ';'".
# What it does NOT prove: other tiers
# (conformance/negatives/n154-go-semicolon-separator-parity.test.ts and N271).

require 'tmpdir'
require_relative 'test_helper'
require 'runar_compiler/frontend/input_limits'
require 'runar_compiler/compiler'
require 'runar_compiler/frontend/parser_go'

class TestN154GoSemicolonSeparator < Minitest::Test
  WANT = "Unexpected token in expression: ';'"

  def go(unlock, guard = "\trunar.Assert(x > 0)")
    <<~GO
      package contract

      import runar "github.com/icellan/runar/packages/runar-go"

      type Disc struct {
      \trunar.SmartContract
      \tT runar.Bigint `runar:"readonly"`
      }

      func (c *Disc) Unlock(x runar.Bigint) {
      #{unlock}
      }

      func (c *Disc) guard(x runar.Bigint) {
      #{guard}
      }
    GO
  end

  def hex(source)
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'Disc.runar.go')
      File.write(path, source)
      RunarCompiler.compile_from_source(path, disable_constant_folding: true).script
    end
  end

  def parse_errors(source)
    RunarCompiler::Frontend.parse_go(source, 'Disc.runar.go').errors.map(&:message)
  end

  def test_same_line_separator_matches_the_newline_form
    [
      [go("\ta := x + 1\n\tb := a + 2\n\trunar.Assert(b == c.T)"),
       go("\ta := x + 1; b := a + 2\n\trunar.Assert(b == c.T)")],
      [go("\trunar.Assert(x == c.T)"), go("\trunar.Assert(x == c.T);")],
      [go("\ty := x\n\tif y > 1 {\n\t\ty = y - 1\n\t} else {\n\t\ty = y + 1\n\t}\n\trunar.Assert(y == c.T)"),
       go("\ty := x; if y > 1 { y = y - 1; } else { y = y + 1; }; runar.Assert(y == c.T)")],
      [go("\ts := x\n\tfor i := 0; i < 3; i++ {\n\t\ts += i\n\t}\n\trunar.Assert(s == c.T)"),
       go("\ts := x; for i := 0; i < 3; i++ { s += i; }; runar.Assert(s == c.T)")],
      [go("\tc.guard(x)\n\trunar.Assert(x == c.T)", "\trunar.Assert(x > 0)\n\treturn"),
       go("\tc.guard(x); runar.Assert(x == c.T)", "\trunar.Assert(x > 0); return;")]
    ].each do |newline, semi|
      assert_equal hex(newline), hex(semi)
    end
  end

  def test_empty_statements_stay_refused
    failures = []
    [
      go("\trunar.Assert(x == c.T);;"),
      go("\ta := x; ;\n\trunar.Assert(a == c.T)"),
      go("\tif x == c.T {; runar.Assert(true) }\n\trunar.Assert(true)"),
      go("\tc.guard(x)\n\trunar.Assert(x == c.T)", "\trunar.Assert(x > 0)\n\treturn\n\t;")
    ].each do |src|
      got = parse_errors(src)
      failures << "#{src.inspect}: got #{got.inspect}" unless got.any? { |m| m.include?(WANT) }
    end
    assert_empty failures, failures.join("\n")
  end
end
