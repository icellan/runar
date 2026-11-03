# frozen_string_literal: true

# F-011 (CL-BUG-196) — an unterminated string or byte-string literal is
# refused, never scanned onward into the lines that follow it.
#
# Pre-fix, this tier's run-to-next-quote tokenizers (.sol/.move/.zig/.java/
# .go/.ts) swallowed the next line into an unterminated literal, its line-based
# .py and .rb tokenizers ended one silently at the line break, and its Python
# tokenizer skipped every line after an unclosed docstring, which dropped the
# guard in N54 (the emitted script had no `y < 5` check).
#
# The rule is the TS reference's (packages/runar-compiler/src/errors.ts,
# UNTERMINATED_STRING_LITERAL): a quoted literal that reaches a line break or
# end of file before its closing quote is refused with exactly
# "unterminated string literal" at its opening quote; on .runar.rs, for Python
# triple-quoted strings, for .runar.go backtick raw strings and for .runar.ts
# template literals only end of file counts; a Java char literal is refused
# with "char literals are unsupported in Rúnar Java contracts".
#
# What this proves: every surface of this tier (all nine are hand-written)
# refuses the conformance negatives N52-N64 through the CLI with that exact
# text at the opening quote's line; the closed-literal controls, Python
# docstrings, a Rust string and a Go struct tag that span lines are not
# refused for it.
# What it does NOT prove: anything about the other tiers (their suites and
# conformance/negatives/rejection-parity.test.ts), or literal forms the
# tokenizers never scanned (Rust raw strings, heredocs, Java text blocks).

require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class F011UnterminatedLiteralTest < Minitest::Test
  RUBY_CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)
  NEGATIVES = File.expand_path('../../../conformance/negatives', __dir__)
  MSG = 'unterminated string literal'
  CHAR_MSG = 'char literals are unsupported in Rúnar Java contracts'

  FIXTURES = [
    ['N52-py-bytes-unterminated-swallow.runar.py', 22, "b\"cafe\n", "b\"cafe\"\n", MSG],
    ['N53-py-string-unterminated.runar.py', 13, "'cafe\n", "'cafe'\n", MSG],
    ['N54-py-docstring-unterminated.runar.py', 19, "follows.\n", "follows.\"\"\"\n", MSG],
    ['N55-sol-string-unterminated.runar.sol', 13, "\"cafe\n", "\"cafe\";\n", MSG],
    ['N56-move-string-unterminated.runar.move', 12, "\"cafe\n", "\"cafe\";\n", MSG],
    ['N57-zig-string-unterminated.runar.zig', 12, "\"cafe\n", "\"cafe\";\n", MSG],
    ['N58-rs-string-unterminated.runar.rs', 13, "\"cafe;\n", "\"cafe\";\n", MSG],
    ['N59-java-string-unterminated.runar.java', 22, "\"cafe\n", "\"cafe\");\n", MSG],
    ['N60-java-char-literal.runar.java', 21, '', '', CHAR_MSG],
    ['N61-rb-single-quote-unterminated.runar.rb', 10, "'cafe\n", "'cafe'\n", MSG],
    ['N62-rb-double-quote-unterminated.runar.rb', 9, "\"cafe\n", "\"cafe\"\n", MSG],
    ['N63-go-string-unterminated.runar.go', 18, "\"cafe\n", "\"cafe\"\n", MSG],
    ['N64-ts-string-unterminated.runar.ts', 14, "\"cafe;\n", "\"cafe\";\n", MSG],
  ].freeze

  # The CLI's --parse-only diagnostics for `source`.
  def diagnostics(source, file_name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      stdout, stderr, _status = Open3.capture3(RbConfig.ruby, RUBY_CLI, '--source', path, '--parse-only')
      "#{stderr}\n#{stdout}".force_encoding('UTF-8')
    end
  end

  def assert_at(source, file_name, msg, line)
    out = diagnostics(source, file_name)
    assert_match(/#{Regexp.escape(file_name)}:#{line}(:\d+)?: #{Regexp.escape(msg)}$/, out,
                 "#{file_name}: want #{msg.inspect} at line #{line}")
  end

  def refute_unterminated(source, file_name)
    out = diagnostics(source, file_name)
    refute_match(/: #{MSG}$/, out, "#{file_name}: refused as unterminated but it is not")
  end

  def test_conformance_negatives
    FIXTURES.each do |file, line, open, closed, msg|
      src = File.read(File.join(NEGATIVES, file))
      assert_at(src, file, msg, line)
      next if open.empty?

      ctl = src.sub(open, closed)
      refute_equal src, ctl, "#{file}: control replacement did not apply"
      refute_unterminated(ctl, file)
    end
  end

  PY_HEAD = "from runar import SmartContract, Bigint, ByteString, public, assert_\n\n\n" \
            "class G(SmartContract):\n    def __init__(self):\n        super().__init__()\n\n" \
            "    @public\n    def unlock(self, y: Bigint):\n"

  def test_python_shapes
    ["b\"ca", "b'ca", "\"ca", "'ca"].each do |lit|
      assert_at(PY_HEAD + "        t: ByteString = #{lit}\n        assert_(y < 5)\n", 'G.runar.py', MSG, 10)
      assert_at(PY_HEAD + "        assert_(y < 5)\n        t: ByteString = #{lit}", 'G.runar.py', MSG, 11)
    end
    assert_at(PY_HEAD + "        t: ByteString = b\"ca\\\n        assert_(y < 5)\n", 'G.runar.py', MSG, 10)
    assert_at(PY_HEAD + "        assert_(y < 5)\n        x = \"\"\"note\n", 'G.runar.py', MSG, 11)
    refute_unterminated(PY_HEAD + "        '''Method docstring\n        on two lines.'''\n        \"\"\"one line\"\"\"\n        assert_(y < 5)\n", 'G.runar.py')
  end

  def test_other_surface_shapes
    assert_at("pragma runar ^0.1.0;\ncontract G is SmartContract {\n  function f() public { 'ca", 'G.runar.sol', MSG, 3)
    assert_at("module G {\n    public fun f(y: Int) {\n        let t: ByteString = b\"ca\\\n", 'G.runar.move', MSG, 3)
    assert_at("const runar = @import(\"runar", 'G.runar.zig', MSG, 1)
    assert_at("class G extends SmartContract {\n  void f() { ByteString t = ByteString.fromHex(\"ca\\\"\n  }\n}\n", 'G.runar.java', MSG, 2)
    refute_unterminated("class G extends SmartContract {\n  void f() { ByteString t = ByteString.fromHex(\"ca\\\"fe\"); }\n}\n", 'G.runar.java')
    ["'c';", "'c", "'\\''"].each do |lit|
      assert_at("class G extends SmartContract {\n  void f() { #{lit}\n  }\n}\n", 'G.runar.java', CHAR_MSG, 2)
    end
    assert_at("require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\n  end\nend\n", 'G.runar.rb', MSG, 4)
    refute_unterminated("require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\"fe\"\n  end\nend\n", 'G.runar.rb')
    assert_at("package contract\n\nfunc (c *G) F() {\n\tt := \"ca\\\n}\n", 'G.runar.go', MSG, 4)
    assert_at("package contract\n\ntype G struct {\n\tK runar.Bigint `runar:\"readonly\"\n}\n", 'G.runar.go', MSG, 4)
    refute_unterminated("package contract\n\ntype G struct {\n\tK runar.Bigint `runar:\n\"readonly\"`\n}\n", 'G.runar.go')
    assert_at("import { SmartContract } from 'runar-lang\n", 'G.runar.ts', MSG, 1)
    assert_at("class G extends SmartContract {\n  f(): void { const t = \"ca\n  }\n}\n", 'G.runar.ts', MSG, 2)
    refute_unterminated("class G extends SmartContract {\n  f(): void { const t = \"ca\\\nfe\";\n  }\n}\n", 'G.runar.ts')
    rs = "use runar::prelude::*;\n\n#[runar::contract]\npub struct G {\n}\n\nimpl G {\n    pub fn unlock(&self, y: Bigint) {\n"
    assert_at(rs + "        let t: ByteString = \"ca\\\"\n        assert!(y < 5);\n    }\n}\n", 'G.runar.rs', MSG, 9)
    refute_unterminated(rs + "        let t: ByteString = \"ca\nfe\";\n        assert!(y < 5);\n    }\n}\n", 'G.runar.rs')
  end
end
