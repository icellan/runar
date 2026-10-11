# frozen_string_literal: true

# N-004 (CL-BUG-257) — stray class-level tokens in .runar.rb.
#
# The parser skipped any class-body token it did not recognise and ignored
# everything after the class's `end`. An INDENTED `=begin` is not a comment in
# Ruby: it lexes as `=` then `begin`, both were skipped, the "commented-out"
# `drain` became a method, the block's `end` closed the class, and the real
# guarded `unlock` was dropped with no diagnostic, leaving `drain`
# (assert true) as the only spend path.
#
# The rule is the TS reference's: a class-body token other than `prop`,
# `runar_public`, `params`, `def` or a bare `private` / `public` marker is
# refused with "Unexpected token in class body: '<tok>'", and the first token
# after the class's `end` with "Unexpected token after class end: '<tok>'".
#
# What this proves: the indented backdoor, stray class-body tokens and trailing
# code after the class are parse errors whose first diagnostic carries the
# shared text at the offending token's line; bare `private` / `public` markers
# and trailing blank lines and comments still parse cleanly.
# What it does not prove: emitted bytes, other tiers (see
# conformance/negatives/n004-rb-stray-token-parity.test.ts), characters the
# tokenizer drops, or a class with no closing `end`.

require_relative 'test_helper'
require 'runar_compiler/frontend/parser_ruby'

class TestN004RubyStrayTokens < Minitest::Test
  def p2pkh(body, tail)
    [
      "require 'runar'",
      '',
      'class P2PKH < Runar::SmartContract',
      '  prop :pub_key_hash, Addr',
      '',
      '  def initialize(pub_key_hash)',
      '    super(pub_key_hash)',
      '    @pub_key_hash = pub_key_hash',
      '  end',
      body,
      '  runar_public sig: Sig, pub_key: PubKey',
      '  def unlock(sig, pub_key)',
      '    assert hash160(pub_key) == @pub_key_hash',
      '    assert check_sig(sig, pub_key)',
      '  end',
      'end',
      tail,
    ].join("\n")
  end

  def indented
    p2pkh([
      '',
      '  =begin',
      '  Old debugging entry point, disabled:',
      '  runar_public sig: Sig, pk: PubKey',
      '  def drain(sig, pk)',
      '    assert true',
      '  end',
      'end',
      '  =end',
      '',
    ].join("\n"), '')
  end

  def parse(source)
    RunarCompiler.send(:_parse_source, source, 'P2PKH.runar.rb')
  end

  def body(tok)
    "Unexpected token in class body: '#{tok}'"
  end

  def after(tok)
    "Unexpected token after class end: '#{tok}'"
  end

  def test_stray_class_level_tokens_are_refused
    [
      ['indented =begin backdoor', indented, body('='), 11],
      ['stray 42 + ?', p2pkh("\n  42 + ?\n", ''), body('42'), 11],
      ['stray = end', p2pkh("\n  = end\n", ''), body('='), 11],
      ['bare identifier', p2pkh("\n  foo\n", ''), body('foo'), 11],
      ['identifier after class', p2pkh('', "foo\n"), after('foo'), 17],
      ['end after class', p2pkh('', "end\n"), after('end'), 17],
      ['method after class', p2pkh('', "def drain(sig)\n  assert true\nend\n"), after('def'), 17],
      ['class after class', p2pkh('', "class Other < Runar::SmartContract\nend\n"), after('class'), 17],
    ].each do |name, src, want, line|
      msgs = parse(src).errors.map(&:message)
      refute_empty msgs, "#{name}: parsed with no errors"
      assert msgs.first.end_with?(want), "#{name}: first error #{msgs.first.inspect}, want #{want.inspect}"
      assert_includes msgs.first, "P2PKH.runar.rb:#{line}:", "#{name}: location"
    end
  end

  def test_visibility_markers_and_trailing_blanks_are_accepted
    {
      'plain' => p2pkh('', ''),
      'private / public' => p2pkh("\n  private\n\n  public\n", ''),
      'trailing comment' => p2pkh('', "\n# trailing note\n\n"),
    }.each do |name, src|
      r = parse(src)
      assert_empty r.errors.map(&:message), name
      refute_nil r.contract, name
    end
  end
end
