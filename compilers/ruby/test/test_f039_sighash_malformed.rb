# frozen_string_literal: true

require_relative 'test_helper'

# F-039 — a present-but-malformed `@sighash` marker is a compile error.
#
# Before F-039, `/** @sighash SINGLE|FORKID! */` (a one-character typo) did not
# match the extractor regex, so the method was read as having NO directive and
# compiled, silently, under the default ALL|FORKID. A second directive on one
# method was silently ignored.
#
# Proves: the Ruby TS-surface parser refuses each malformed / duplicated shape
# with the diagnostic shared by all seven tiers (N-039: including `@sighash`
# glued to the next token), and still honours a well-formed multi-line JSDoc
# directive.
# Does not prove: cross-tier agreement (conformance/negatives rejection-parity).
class TestF039SighashMalformed < Minitest::Test
  MALFORMED = "Method 'bump': @sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS " \
              'is a |-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)'
  MULTIPLE = "Method 'bump': @sighash: more than one @sighash directive on this method; declare exactly one"

  def src(directive)
    <<~TS
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        #{directive}
        public bump(): void { this.addOutput(1000n, this.n); }
      }
    TS
  end

  def parse(directive)
    RunarCompiler.send(:_parse_source, src(directive), 'X.runar.ts')
  end

  def errors(directive)
    parse(directive).errors.map(&:message)
  end

  def test_malformed_directive_rejected
    ['/** @sighash SINGLE|FORKID! */', '/** @sighash:SINGLE|FORKID */',
     '// @sighash=SINGLE|FORKID', '/** @sighash SINGLE,FORKID */'].each do |d|
      assert_equal [MALFORMED], errors(d), d
    end
  end

  def test_bare_marker_line_comment_rejected
    assert_equal ["Method 'bump': @sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)"],
                 errors('// @sighash')
  end

  def test_multiple_directives_rejected
    ["/** @sighash SINGLE|FORKID\n   * @sighash ALL|FORKID */",
     "/** @sighash SINGLE|FORKID */\n  /** @sighash ALL|FORKID */",
     "/** @sighash SINGLE|FORKID!\n   * @sighash NONE|FORKID */"].each do |d|
      assert_equal [MULTIPLE], errors(d), d
    end
  end

  # N-039 (user decision R85, "Refuse, all 7 tiers"): this used to pin the
  # word-boundary rule (`@sighashSINGLE` / `@sighashType` read as prose, so the
  # method silently got the default ALL|FORKID). A comment token that starts
  # with `@sighash` but is not exactly `@sighash <FLAGS>` is now refused with the
  # shared malformed diagnostic; the case list is unchanged plus `_` / digit.
  def test_n039_glued_marker_rejected
    ['/** @sighashSINGLE|FORKID */', '/** see the @sighashType docs */',
     '// @sighash_SINGLE|FORKID', '/** @sighash2 */'].each do |d|
      assert_equal [MALFORMED], errors(d), d
    end
  end

  def test_well_formed_multiline_jsdoc_honoured
    r = parse("/**\n   * Bump.\n   * @sighash SINGLE|FORKID\n   */")
    assert_empty r.errors.map(&:message)
    assert_equal 0x43, r.contract.methods.find { |m| m.name == 'bump' }.sighash_type
  end
end
