# frozen_string_literal: true

# F-026 (CL-BUG-198) — an integer literal means what its host language says it
# means, on every surface, or it is refused.
#
# Pre-fix, this tier's hand-written tokenizers scanned decimal digits (and
# sometimes `0x`) only. `0b1010` on .runar.py / .runar.zig lexed as `0` plus
# the identifier `b1010`, and with an identifier of that name in scope the
# stray token was absorbed (.zig call arguments needed no commas, .py took two
# statements on one line), so `amount > 0b1010` compiled to `amount > 0`.
#
# The rule is the TS reference's (packages/runar-compiler/src/passes/
# int-literal.ts, user decision R15): the number token runs over every glued
# [0-9A-Za-z_] character and must be an integer literal of the surface's host
# language, with that language's value (table:
# conformance/negatives/int-literal-cases.json, generated from the host
# toolchains); anything else is refused with
# "invalid <Language> integer literal '<text>'". Also: .zig call and array
# lists require commas; .py refuses a second statement on one line.
#
# What this proves: this tier's validator reproduces every table row; every
# tokenizer (all nine surfaces are hand-written here) accepts exactly the
# table's forms with its values and refuses the rest with the shared text;
# the attempt-1 exploit shapes read 10; the absorbing paths are closed.
# What it does NOT prove: the other tiers, or the Solidity / Move rows
# themselves (documentation-derived).

require_relative 'test_helper'

class F026IntLiteralTest < Minitest::Test
  IL = RunarCompiler::Frontend::IntLiteral
  ZIG_COMMA = "expected ',' between list elements"
  PY_LINE_BREAK = 'expected a line break between statements'
  CASES = JSON.parse(File.read(File.expand_path('../../../conformance/negatives/int-literal-cases.json', __dir__)))['cases']
  SURFACES = %w[ts sol move go rs py zig rb java].freeze

  TEMPLATE = {
    'ts' => ->(l) { "import { SmartContract, assert } from 'runar-lang';\n\nclass T extends SmartContract {\n  readonly target: bigint;\n\n  constructor(target: bigint) {\n    super(target);\n    this.target = target;\n  }\n\n  public verify(a: bigint): void {\n    assert(a > #{l});\n  }\n}\n" },
    'sol' => ->(l) { "pragma runar ^0.1.0;\n\ncontract T is SmartContract {\n    int immutable target;\n\n    constructor(int _target) {\n        target = _target;\n    }\n\n    function verify(int a) public {\n        require(a > #{l});\n    }\n}\n" },
    'move' => ->(l) { "module T {\n    use runar::types::{Int};\n\n    struct T {\n        target: Int,\n    }\n\n    public fun verify(contract: &T, a: Int) {\n        assert!(a > #{l});\n    }\n}\n" },
    'go' => ->(l) { "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype T struct {\n\trunar.SmartContract\n\tTarget runar.Int `runar:\"readonly\"`\n}\n\nfunc (c *T) Verify(a runar.Int) {\n\trunar.Assert(a > #{l})\n}\n" },
    'rs' => ->(l) { "use runar::prelude::*;\n\n#[runar::contract]\nstruct T {\n    #[readonly]\n    target: Int,\n}\n\nimpl T {\n    pub fn verify(&self, a: Int) {\n        assert!(a > #{l});\n    }\n}\n" },
    'py' => ->(l) { "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, a: Bigint):\n        assert_(a > #{l})\n" },
    'zig' => ->(l) { "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {\n        return .{ .target = target };\n    }\n\n    pub fn verify(self: *const T, a: i64) void {\n        _ = self;\n        runar.assert(a > #{l});\n    }\n};\n" },
    'rb' => ->(l) { "require 'runar'\n\nclass T < Runar::SmartContract\n  prop :target, Bigint\n\n  def initialize(target)\n    super(target)\n    @target = target\n  end\n\n  runar_public a: Bigint\n  def verify(a)\n    assert a > #{l}\n  end\nend\n" },
    'java' => ->(l) { "package t;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass T extends SmartContract {\n\n    @Readonly Bigint target;\n\n    T(Bigint target) {\n        super(target);\n        this.target = target;\n    }\n\n    @Public\n    void verify(Bigint a) {\n        assertThat(a.gt(Bigint.of(#{l})));\n    }\n}\n" }
  }.freeze

  def parse(src, file)
    RunarCompiler.send(:_parse_source, src, file)
  end

  def messages(result)
    (result.errors || []).map { |e| e.respond_to?(:message) ? e.message.to_s : e.to_s }
  end

  def collect(node, out)
    case node
    when RunarCompiler::Frontend::BigIntLiteral then out << node.value
    when Array then node.each { |x| collect(x, out) }
    when Struct then node.each_pair { |k, v| collect(v, out) unless k == :source_location }
    end
  end

  def literals(src, file)
    r = parse(src, file)
    vals = []
    r.contract&.methods&.each { |m| collect(m.body, vals) if m.name == 'verify' }
    [vals, messages(r)]
  end

  def has?(errs, want)
    errs.any? { |e| e.include?(want) }
  end

  def test_validator_reproduces_host_table
    assert_equal SURFACES.sort, CASES.keys.sort
    bad = []
    CASES.each do |surf, rows|
      rows.each do |lit, want|
        r = IL.parse(surf, lit)
        got = r && !r.neg_only ? r.value.to_s : nil
        bad << "#{surf} #{lit}: want #{want.inspect}, got #{got.inspect}" unless got == want
      end
    end
    assert_empty bad
  end

  def test_every_tokenizer_applies_the_table
    bad = []
    SURFACES.each do |surf|
      CASES[surf].each do |lit, want|
        vals, errs = literals(TEMPLATE[surf].call(lit), "T.runar.#{surf}")
        if want.nil?
          bad << "#{surf} #{lit}: not refused with the shared text (#{vals} #{errs})" unless has?(errs, IL.invalid_integer_literal(surf, lit))
        elsif !errs.empty? || vals != [want.to_i]
          bad << "#{surf} #{lit}: want [#{want}], got #{vals} #{errs}"
        end
      end
    end
    assert_empty bad
  end

  def test_unary_minus_only_literals
    [['java', '-2147483648', 2147483648], ['java', '- 9223372036854775808L', 9223372036854775808],
     ['rs', '-128i8', 128], ['rs', '-(128i8)', 128], ['rs', '-9223372036854775808i64', 9223372036854775808]].each do |surf, src, want|
      vals, errs = literals(TEMPLATE[surf].call(src), "T.runar.#{surf}")
      assert(errs.empty? && vals == [want], "#{surf} #{src}: #{vals} #{errs}")
    end
    [['java', '-(2147483648)', '2147483648'], ['java', '1 - 2147483648', '2147483648'], ['java', '2147483648', '2147483648'],
     ['java', '-9223372036854775808', '9223372036854775808'], ['rs', '128i8', '128i8'], ['rs', '1 - 128i8', '128i8'],
     ['rs', '-129i8', '129i8']].each do |surf, src, lit|
      _, errs = literals(TEMPLATE[surf].call(src), "T.runar.#{surf}")
      assert(has?(errs, IL.invalid_integer_literal(surf, lit)), "#{surf} #{src}: #{errs}")
    end
  end

  def zig(params, body)
    "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n" \
      "    target: i64,\n\n    pub fn init(target: i64) T {\n        return .{ .target = target };\n    }\n\n" \
      "    pub fn verify(self: *const T, amount: i64#{params}) void {\n        _ = self;\n#{body}\n    }\n};\n"
  end

  def py(params, body)
    "from runar import SmartContract, Bigint, ByteString, public, assert_\n\nclass T(SmartContract):\n" \
      "    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n" \
      "        self.target = target\n\n    @public\n    def verify(self, amount: Bigint#{params}):\n#{body}\n"
  end

  def test_exploit_shapes_read_the_literal
    vals, errs = literals(zig(', b1010: runar.ByteString', '        runar.assert(amount > 0b1010);'), 'T.runar.zig')
    assert(errs.empty? && vals == [10], "zig 0b1010 beside b1010: #{vals} #{errs}")
    _, errs = literals(zig(', B1010: i64', "        runar.assert(amount > 0B1010);\n        runar.assert(B1010 == B1010);"), 'T.runar.zig')
    assert(has?(errs, IL.invalid_integer_literal('zig', '0B1010')), errs.inspect)
    %w[0b1010 0o12 0xa].each do |lit|
      src = "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n" \
            "    target: i64 = #{lit},\n\n    pub fn verify(self: *const T, amount: i64) void {\n" \
            "        runar.assert(amount > self.target);\n    }\n};\n"
      r = parse(src, 'T.runar.zig')
      assert_empty messages(r), lit
      assert_equal 10, r.contract.properties[0].initializer.value, lit
    end
    vals, errs = literals(py(', b1010: Bigint', "        lim = 0b1010\n        assert_(amount > lim)"), 'T.runar.py')
    assert(errs.empty? && vals == [10], "py 0b1010 beside b1010: #{vals} #{errs}")
    %w[0o12 0b1010].each do |lit|
      src = "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n" \
            "    limit: Bigint = #{lit}\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n" \
            "        self.target = target\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.limit)\n"
      r = parse(src, 'T.runar.py')
      assert_empty messages(r), lit
      assert_equal 10, r.contract.properties[1].initializer.value, lit
    end
    %w[0b102 0o19].each do |lit|
      _, errs = literals(TEMPLATE['ts'].call(lit), 'T.runar.ts')
      assert(has?(errs, IL.invalid_integer_literal('ts', lit)), errs.inspect)
    end
  end

  def test_absorbing_paths
    _, errs = literals(zig(', b: i64', '        runar.assert(runar.within(amount b, 20));'), 'T.runar.zig')
    assert(has?(errs, ZIG_COMMA), errs.inspect)
    _, errs = literals(zig(', b: i64', '        runar.assert(runar.within(amount, b, 20,));'), 'T.runar.zig')
    refute(has?(errs, ZIG_COMMA), errs.inspect)
    _, errs = literals(zig('', "        const xs = [ 1 2, 3 ];\n        runar.assert(amount > xs[0]);"), 'T.runar.zig')
    assert(has?(errs, ZIG_COMMA), errs.inspect)
    _, errs = literals(zig('', "        const xs: [3]i64 = .{ 1, 2 3 };\n        runar.assert(amount > xs[0]);"), 'T.runar.zig')
    assert(has?(errs, ZIG_COMMA), errs.inspect)
    _, errs = literals(py(', b: Bigint', "        lim = 10 b\n        assert_(amount > lim)"), 'T.runar.py')
    assert(has?(errs, PY_LINE_BREAK), errs.inspect)
    _, errs = literals(py('', '        assert_(amount > 1) assert_(amount > 2)'), 'T.runar.py')
    assert(has?(errs, PY_LINE_BREAK), errs.inspect)
    cls = "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n" \
          "    target: Bigint = 10 extra\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.target)\n"
    assert(has?(messages(parse(cls, 'T.runar.py')), PY_LINE_BREAK))
    _, errs = literals(TEMPLATE['ts'].call('10').sub('assert(a > 10);', 'assert(a > 10;'), 'T.runar.ts')
    refute_empty errs, 'ts unclosed call accepted'
  end
end
