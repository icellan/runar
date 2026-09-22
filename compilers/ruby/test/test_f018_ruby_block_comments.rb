# frozen_string_literal: true

# F-018 (CL-BUG-257) — Ruby `=begin` / `=end` block comments.
#
# The .runar.rb tokenizer only knew `#` line comments. A `=begin ... =end`
# embedded document — which Ruby itself treats as a comment — was tokenized as
# live code, so a method "commented out" inside one became a real spending
# entry point, and the `end` inside it closed the class early so the genuine
# guarded method vanished. The executed reproducer compiled a P2PKH contract
# down to the 6-byte, anyone-can-spend `OP_TRUE OP_NIP OP_NIP`.
#
# What these tests prove:
#   - the crafted attack (P2PKH guard + a commented-out `drain` backdoor inside
#     `=begin`/`=end`) compiles to an ABI whose ONLY public method is `unlock`,
#     and to a locking script byte-identical to the checked-in basic-p2pkh
#     golden (`conformance/tests/basic-p2pkh/expected-script.hex`, fold OFF),
#     i.e. the comment contributes nothing to the script;
#   - an unterminated `=begin` is a parse error (Ruby rejects it too), not a
#     silent truncation of the contract;
#   - at the tokenizer, `=begin` that is not at column 0 is NOT treated as a
#     comment opener (Ruby only recognises the column-0 form), and `=beginx`
#     is not one either.
#
# What they do not prove:
#   - on-chain spend behaviour; the script is pinned to the golden, whose own
#     provenance gate is responsible for its correctness;
#   - anything about the Go tier's (or any other tier's) Ruby-surface parser,
#     which is a separate item;
#   - `__END__` handling, which is a different lexical feature.

require_relative 'test_helper'
require 'tempfile'
require 'runar_compiler/frontend/parser_ruby'

class TestF018RubyBlockComments < Minitest::Test
  GOLDEN_P2PKH_HEX = File.read(
    File.expand_path('../../../conformance/tests/basic-p2pkh/expected-script.hex', __dir__)
  ).strip

  # Built by concatenation, not a squiggly heredoc: `=begin` / `=end` must sit
  # at column 0, exactly as an attacker would place them.
  ATTACK_SOURCE = [
    "require 'runar'",
    '',
    'class P2PKH < Runar::SmartContract',
    '  prop :pub_key_hash, Addr',
    '',
    '  def initialize(pub_key_hash)',
    '    super(pub_key_hash)',
    '    @pub_key_hash = pub_key_hash',
    '  end',
    '',
    '=begin',
    '  Old debugging entry point, disabled:',
    '  runar_public sig: Sig, pk: PubKey',
    '  def drain(sig, pk)',
    '    assert true',
    '  end',
    'end',
    '=end',
    '',
    '  runar_public sig: Sig, pub_key: PubKey',
    '  def unlock(sig, pub_key)',
    '    assert hash160(pub_key) == @pub_key_hash',
    '    assert check_sig(sig, pub_key)',
    '  end',
    'end',
    '',
  ].join("\n")

  def parse(source, file_name = 'P2PKH.runar.rb')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def compile(source)
    tmp = Tempfile.new(['P2PKH', '.runar.rb'])
    tmp.write(source)
    tmp.close
    RunarCompiler.compile_from_source(tmp.path, disable_constant_folding: true)
  ensure
    tmp&.unlink
  end

  def test_commented_out_backdoor_is_not_a_spend_path
    result = parse(ATTACK_SOURCE)
    assert_empty result.errors.map(&:format_message)
    refute_nil result.contract
    assert_equal ['unlock'], result.contract.methods.map(&:name),
                 'the =begin/=end block must be a comment: no `drain`, and `unlock` must survive'

    artifact = compile(ATTACK_SOURCE)
    public_methods = artifact.abi.methods.select(&:is_public).map(&:name)
    assert_equal ['unlock'], public_methods
    assert_equal GOLDEN_P2PKH_HEX, artifact.script.downcase,
                 'locking script must be byte-identical to the basic-p2pkh golden'
  end

  def test_unterminated_begin_is_a_parse_error
    source = ATTACK_SOURCE.sub("=end\n", '')
    result = parse(source)
    messages = result.errors.map(&:format_message)
    refute_empty messages, 'an unterminated =begin must be rejected, not silently swallow the contract'
    assert(messages.any? { |m| m.include?('=begin') }, "expected an =begin diagnostic, got #{messages.inspect}")
  end

  # The two tests below pin the fix's boundary at the tokenizer: only a
  # column-0, whole-word `=begin` opens a comment. They assert the lines after
  # the marker are still lexed (the `drain` identifier reaches the token
  # stream). They deliberately do not assert a parse error: the parser's
  # tolerance of stray tokens is a separate, pre-existing matter.
  def ident_values(source)
    RunarCompiler::Frontend::RubyTokens.tokenize(source)
                                       .select { |t| t.kind == RunarCompiler::Frontend::RubyTokens::TOK_IDENT }
                                       .map(&:value)
  end

  def test_block_comment_is_removed_from_token_stream
    refute_includes ident_values(ATTACK_SOURCE), 'drain'
  end

  def test_indented_begin_is_not_a_block_comment
    source = ATTACK_SOURCE.sub("\n=begin\n", "\n  =begin\n").sub("\n=end\n", "\n  =end\n")
    assert_includes ident_values(source), 'drain', 'Ruby only opens an embedded document at column 0'
  end

  def test_begin_prefix_word_is_not_a_block_comment
    source = ATTACK_SOURCE.sub("\n=begin\n", "\n=beginx\n")
    assert_includes ident_values(source), 'drain', '`=beginx` is not an embedded-document opener'
  end
end
