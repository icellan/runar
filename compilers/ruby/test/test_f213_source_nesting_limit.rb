# frozen_string_literal: true

# F-213 — a shared source-nesting limit, MAX_SOURCE_NESTING = 128.
#
# MAX_SOURCE_BYTES (4 MiB) never bounded recursion: a few KB of nested parens,
# nested ifs, `-(` unary chains or a long `a + a + ...` chain sent every
# hand-written parser of this tier (and the passes after them) into
# `stack level too deep (SystemStackError)`. The rule is the TS reference's
# (packages/runar-ir-schema/src/input-limits.ts and
# packages/runar-compiler/src/passes/source-limits.ts): a source is refused,
# with exactly
#   source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)
# when (A) the parse-nesting counter (statements, full-expression entries,
# prefix-unary operands, nested type arguments) or (B) the AST nesting
# (statement level + expression-tree depth) exceeds 128.
#
# What this proves: on all nine surfaces, through each exported
# Frontend.parse_<fmt> entry, the canonical boundary shapes land on the same
# side of the limit as the TS reference -- parens n=126 and nested-if n=126
# and chain k=127 and unary n=63 compile end to end, parens/nested-if n=127,
# unary n=64 and chain k=128 are refused with the shared diagnostic -- and that
# a 20000-deep source on every surface is refused through the CLI with that
# diagnostic and a normal non-zero exit, not a SystemStackError or a signal.
# What it does NOT prove: byte-equality of the accepted scripts with the TS
# tier (remediation-logs/F-213/check_tier.py does that against TS hexes), type
# nesting boundaries (crash-safety only; no shape pins them), or anything
# about the other six tiers.

require 'open3'
require 'tmpdir'
require_relative 'test_helper'
require 'runar_compiler/frontend/input_limits'
require 'runar_compiler/frontend/parser_python'
require 'runar_compiler/frontend/parser_ts'
require 'runar_compiler/frontend/parser_sol'
require 'runar_compiler/frontend/parser_move'
require 'runar_compiler/frontend/parser_go'
require 'runar_compiler/frontend/parser_rust'
require 'runar_compiler/frontend/parser_ruby'
require 'runar_compiler/frontend/parser_zig'
require 'runar_compiler/frontend/parser_java'

class F213SourceNestingLimitTest < Minitest::Test
  RUBY_CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)
  DIAG = 'source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)'
  L = 128

  # Surface templates (a port of remediation-logs/F-213/gen.py): the body of
  # `check` is `{BODY}`; the canonical statement is `result = <expr>`.
  BRACE_IF = ->(cond, close) { ->(n, inner) { "if #{cond} {\n" * n + inner + "\n" + "#{close}\n" * n } }
  SURFACES = {
    'ts' => {
      parse: :parse_ts,
      head: "import { SmartContract, assert } from 'runar-lang';\n\nclass P extends SmartContract {\n  readonly limit: bigint;\n  constructor(limit: bigint) { super(limit); this.limit = limit; }\n  public check(value: bigint, mode: boolean): void {\n    let result: bigint = 0n;\n{BODY}\n    assert(result > 0n);\n  }\n}\n",
      assign: ->(e) { "    result = #{e};" },
      if_wrap: BRACE_IF.call('(mode)', '}'),
    },
    'sol' => {
      parse: :parse_sol,
      head: "pragma runar ^0.1.0;\n\ncontract P is SmartContract {\n    int immutable limit;\n    constructor(int _limit) { limit = _limit; }\n    function check(int value, bool mode) public {\n        int result = 0;\n{BODY}\n        require(result > 0);\n    }\n}\n",
      assign: ->(e) { "        result = #{e};" },
      if_wrap: BRACE_IF.call('(mode)', '}'),
    },
    'move' => {
      parse: :parse_move,
      head: "module P {\n    use runar::types::{Int};\n    struct P { limit: Int, }\n    public fun check(contract: &P, value: Int, mode: bool) {\n        let result: Int = 0;\n{BODY}\n        assert!(result > 0, 0);\n    }\n}\n",
      assign: ->(e) { "        result = #{e};" },
      if_wrap: BRACE_IF.call('(mode)', '};'),
    },
    'go' => {
      parse: :parse_go,
      head: "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype P struct {\n\trunar.SmartContract\n\tLimit runar.Int `runar:\"readonly\"`\n}\n\nfunc (c *P) Check(value runar.Int, mode runar.Bool) {\n\tresult := runar.Int(0)\n{BODY}\n\trunar.Assert(result > 0)\n}\n",
      assign: ->(e) { "\tresult = #{e}" },
      if_wrap: BRACE_IF.call('mode', '}'),
    },
    'rs' => {
      parse: :parse_rust,
      head: "use runar::prelude::*;\n\n#[runar::contract]\nstruct P {\n    #[readonly]\n    limit: Int,\n}\n\nimpl P {\n    pub fn check(&self, value: Int, mode: bool) {\n        let mut result: Int = 0;\n{BODY}\n        assert!(result > 0);\n    }\n}\n",
      assign: ->(e) { "        result = #{e};" },
      if_wrap: BRACE_IF.call('mode', '}'),
    },
    'py' => {
      parse: :parse_python,
      head: "from runar import SmartContract, Bigint, public, assert_\n\nclass P(SmartContract):\n    limit: Bigint\n\n    def __init__(self, limit: Bigint):\n        super().__init__(limit)\n        self.limit = limit\n\n    @public\n    def check(self, value: Bigint, mode: bool):\n        result: Bigint = 0\n{BODY}\n        assert_(result > 0)\n",
      assign: ->(e) { "        result = #{e}" },
      if_wrap: lambda { |n, inner|
        lines = (0...n).map { |i| '        ' + (' ' * i) + 'if mode:' }
        lines << ('        ' + (' ' * n) + inner.strip)
        lines.join("\n")
      },
    },
    'zig' => {
      parse: :parse_zig,
      head: "const runar = @import(\"runar\");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    limit: i64,\n    pub fn init(limit: i64) P { return .{ .limit = limit }; }\n    pub fn check(self: *const P, value: i64, mode: bool) void {\n        var result: i64 = 0;\n{BODY}\n        runar.assert(result > 0);\n    }\n};\n",
      assign: ->(e) { "        result = #{e};" },
      if_wrap: BRACE_IF.call('(mode)', '}'),
    },
    'rb' => {
      parse: :parse_ruby,
      head: "require 'runar'\n\nclass P < Runar::SmartContract\n  prop :limit, Bigint\n\n  def initialize(limit)\n    super(limit)\n    @limit = limit\n  end\n\n  runar_public value: Bigint, mode: Boolean\n  def check(value, mode)\n    result = 0\n{BODY}\n    assert result > 0\n  end\nend\n",
      assign: ->(e) { "    result = #{e}" },
      if_wrap: ->(n, inner) { "if mode\n" * n + inner + "\n" + "end\n" * n },
    },
    'java' => {
      parse: :parse_java,
      head: "package p;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass P extends SmartContract {\n    @Readonly Bigint limit;\n    P(Bigint limit) { super(limit); this.limit = limit; }\n    @Public\n    void check(Bigint value, boolean mode) {\n        Bigint result = Bigint.ZERO;\n{BODY}\n        assertThat(result.gt(Bigint.ZERO));\n    }\n}\n",
      assign: ->(e) { "        result = #{e};" },
      if_wrap: BRACE_IF.call('(mode)', '}'),
    },
  }.freeze

  def self.source(ext, shape, n)
    s = SURFACES.fetch(ext)
    body = case shape
           when :parens then s[:assign].call(('(' * n) + 'value' + (')' * n))
           when :if then s[:if_wrap].call(n, s[:assign].call('value').strip)
           when :chain then s[:assign].call((['value'] * n).join(' + '))
           when :neg then s[:assign].call(('-(' * n) + 'value' + (')' * n))
           end
    s[:head].sub('{BODY}') { body }
  end

  def parse(ext, shape, n)
    RunarCompiler::Frontend.public_send(SURFACES.fetch(ext)[:parse], self.class.source(ext, shape, n), "P.runar.#{ext}")
  end

  def assert_refused(ext, shape, n)
    result = parse(ext, shape, n)
    msgs = result.errors.map(&:message)
    assert_includes msgs, DIAG, "#{ext} #{shape} n=#{n}: expected the shared nesting diagnostic, got #{msgs.inspect}"
    assert_nil result.contract, "#{ext} #{shape} n=#{n}: a refused source must not hand back an AST"
  end

  # The at-limit source compiles end to end (every pass after the parser
  # handles a depth-128 tree).
  def assert_accepted(ext, shape, n)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "P.runar.#{ext}")
      File.write(path, self.class.source(ext, shape, n))
      artifact = RunarCompiler.compile_from_source(path)
      refute_empty artifact.script, "#{ext} #{shape} n=#{n}: no script"
    end
  end

  def test_max_source_nesting_is_128
    assert_equal 128, RunarCompiler::Frontend::InputLimits::MAX_SOURCE_NESTING
    assert_equal DIAG, RunarCompiler::Frontend::InputLimits::SOURCE_NESTING_MESSAGE
  end

  SURFACES.each_key do |ext|
    define_method("test_#{ext}_parens_126_accepted") { assert_accepted(ext, :parens, L - 2) }
    define_method("test_#{ext}_parens_127_refused") { assert_refused(ext, :parens, L - 1) }
    define_method("test_#{ext}_nested_if_126_accepted") { assert_accepted(ext, :if, L - 2) }
    define_method("test_#{ext}_nested_if_127_refused") { assert_refused(ext, :if, L - 1) }
    define_method("test_#{ext}_unary_63_accepted") { assert_accepted(ext, :neg, (L - 2) / 2) }
    define_method("test_#{ext}_unary_64_refused") { assert_refused(ext, :neg, ((L - 2) / 2) + 1) }
    define_method("test_#{ext}_chain_127_accepted") { assert_accepted(ext, :chain, L - 1) }
    define_method("test_#{ext}_chain_128_refused") { assert_refused(ext, :chain, L) }

    # Deep sources run in a CLI subprocess: before the limit they ended in a
    # SystemStackError, which must not be able to take this suite down.
    define_method("test_#{ext}_parens_20000_refused_through_cli_without_crash") do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "P.runar.#{ext}")
        File.write(path, self.class.source(ext, :parens, 20_000))
        stdout, stderr, status = Open3.capture3(RbConfig.ruby, RUBY_CLI, '--source', path, '--hex')
        refute status.signaled?, "#{ext}: CLI died on a signal"
        refute status.success?, "#{ext}: a 20000-deep source compiled"
        assert_equal 1, status.exitstatus, "#{ext}: unexpected exit status"
        refute_match(/SystemStackError|stack level too deep/, stderr, "#{ext}: stack overflow escaped")
        assert_includes stdout + stderr, DIAG, "#{ext}: missing the shared diagnostic\n#{stderr[0, 600]}"
      end
    end
  end
end
