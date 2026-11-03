# frozen_string_literal: true

# F-203 (CL-BUG-208..213) — .runar.py byte literals decode escapes the way
# CPython bytes literals do.
#
# Pre-fix this tier hex-encoded `b'\n'`, `b'\t'`, `b'\\'` character by
# character (5c 6e, ...), and decoded nothing but `\xHH`, so the same source
# compiled to different bytes than CPython (pytest) runs, and than the Python
# tier (which decoded `\0` to 00). `b'\q'` compiled to 5c 71.
#
# The rule is the TS reference's (packages/runar-compiler/src/passes/
# 01-parse-python.ts, decodePyLiteral; user decision R59):
#   - b'..' / b".." decode \\ \' \" \a \b \f \n \r \t \v, octal \NNN (1-3
#     digits, at most 0o377) and \xHH (exactly two hex digits);
#   - any other escape (\q; \N, \u, \U in bytes), a short or non-hex \x, an
#     octal escape above 0o377 is refused with "invalid escape sequence '<esc>'";
#     a non-ASCII character in b'..' with
#     "bytes can only contain ASCII literal characters";
#   - plain '..' strings (hex text) decode the same escapes before the hex
#     check, and refuse \u, \U, \N;
#   - backslash-newline continuations and rb / br / B prefixes stay refused.
# Every expected byte string is CPython's own: python3 -c "print(b'..'.hex())".
#
# What this proves: this tier's CLI compiles each escape to CPython's bytes and
# refuses each undefined or unsupported form with the shared diagnostic.
# What it does NOT prove: anything about the other tiers (their own suites and
# conformance/negatives/py-bytes-escape-parity.test.ts cover that).

require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class F203PyBytesEscapeTest < Minitest::Test
  RUBY_CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)
  NON_ASCII = 'bytes can only contain ASCII literal characters'

  def invalid(esc)
    "invalid escape sequence '#{esc}'"
  end

  # [Python source body between b'..', CPython's b'..'.hex()].
  BYTES_CASES = [
    ['\\0', '00'],
    ['\\00', '00'],
    ['\\000', '00'],
    ['\\7', '07'],
    ['\\101', '41'],
    ['\\377', 'ff'],
    ['\\1234', '5334'],
    ['a\\0b', '610062'],
    ['\\08', '0038'],
    ['\\n', '0a'],
    ['\\t', '09'],
    ['\\r', '0d'],
    ['\\\\', '5c'],
    ["\\'", '27'],
    ['\\"', '22'],
    ['\\a', '07'],
    ['\\b', '08'],
    ['\\f', '0c'],
    ['\\v', '0b'],
    ['\\xde\\xAD', 'dead'],
    ['\\x00\\x6a', '006a'],
    ['ab', '6162'],
    ['\\\\n', '5c6e'],
    ['x\\ty\\nz', '7809790a7a'],
  ].freeze

  def contract(lit)
    <<~PY
      from runar import SmartContract, ByteString, public, assert_


      class Esc(SmartContract):
          def __init__(self):
              super().__init__()

          @public
          def unlock(self, x: ByteString):
              assert_(x == #{lit})
    PY
  end

  # Minimal push of `hex` as the emitter encodes byte strings, then OP_EQUAL.
  def guard_hex(hex)
    n = hex.length / 2
    v = hex.to_i(16)
    push = if n == 1 && v >= 1 && v <= 16 then format('%02x', 0x50 + v)
           elsif n == 1 && hex == '81' then '4f'
           else format('%02x', n) + hex
           end
    push + '87'
  end

  # [exit status success?, stdout+stderr] of `--source <file> --hex`.
  def run_cli(source)
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'Esc.runar.py')
      File.write(path, source)
      stdout, stderr, status = Open3.capture3(RbConfig.ruby, RUBY_CLI, '--source', path, '--hex')
      [status.success?, stdout.strip.force_encoding('UTF-8'), "#{stderr}\n#{stdout}".force_encoding('UTF-8')]
    end
  end

  def test_bytes_escapes_decode_to_cpython_bytes
    BYTES_CASES.each do |body, hex|
      ok, out, all = run_cli(contract("b'#{body}'"))
      assert ok, "b'#{body}': refused: #{all}"
      assert_equal guard_hex(hex), out, "b'#{body}'"
    end
  end

  def test_both_escaped_quotes_inside_double_quotes
    ok, out, all = run_cli(contract("b\"\\'\\\"\""))
    assert ok, all
    assert_equal guard_hex('2722'), out
  end

  def test_plain_string_decodes_escapes_before_the_hex_check
    ok, out, all = run_cli(contract('"\\x61\\x62"'))
    assert ok, all
    assert_equal guard_hex('ab'), out
  end

  def test_invalid_escapes_are_refused_with_the_shared_diagnostic
    [
      ["b'\\q'", '\\q'],
      ["b'\\x4'", '\\x'],
      ["b'\\xg0'", '\\x'],
      ["b'\\400'", '\\400'],
      ["b'\\N{DIGIT ONE}'", '\\N'],
      ["b'\\u0041'", '\\u'],
      ["b'\\U00000041'", '\\U'],
      ['"\\q"', '\\q'],
      ['"\\u0061"', '\\u'],
    ].each do |lit, esc|
      ok, _out, all = run_cli(contract(lit))
      refute ok, "#{lit} compiled"
      assert_includes all, invalid(esc), lit
    end
  end

  def test_non_ascii_in_bytes_is_refused
    ok, _out, all = run_cli(contract("b'é'"))
    refute ok
    assert_includes all, NON_ASCII
  end

  def test_prefix_forms_and_continuation_are_refused
    ["rb'\\n'", "br'\\n'", "B'\\n'", "r'ab'", "u'ab'", "f'ab'", "b'ab\\\ncd'"].each do |lit|
      ok, = run_cli(contract(lit))
      refute ok, "#{lit.inspect} compiled"
    end
  end
end
