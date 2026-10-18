# frozen_string_literal: true

# N-321 -- typecheck diagnostics must not echo an unbounded type text.
#
# What this proves: a 1 MB flat type name yields typecheck diagnostics capped
# at 1024 characters plus the `...(N more bytes elided)` marker, and an
# ordinary type is echoed verbatim. What it does NOT prove: the other tiers
# (conformance/negatives/n321-diagnostic-type-echo-parity.test.ts) nor each
# echo site individually (the cap sits at the diagnostic sink).

require_relative 'test_helper'

require 'runar_compiler/frontend/ast_nodes'
require 'runar_compiler/frontend/diagnostic'
require 'runar_compiler/frontend/validator'
require 'runar_compiler/frontend/typecheck'
require 'runar_compiler/frontend/parser_ts'

class TestN321DiagnosticTypeEcho < Minitest::Test
  HEAD = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint) {\n let q: {T} = a;\n assert(q == this.t);\n }\n}\n"

  def messages(type_text)
    parsed = RunarCompiler.send(:_parse_source, HEAD.sub('{T}') { type_text }, 'P.runar.ts')
    out = parsed.errors.map(&:format_message)
    out += RunarCompiler::Frontend.type_check(parsed.contract).errors.map(&:message) if parsed.contract
    out
  end

  def test_huge_type_text_is_elided
    echoing = messages('T' * (1 << 20)).select { |m| m.include?('TTTT') }
    refute_empty echoing, 'no diagnostic echoed the type'
    echoing.each do |m|
      assert_operator m.length, :<, 1100
      assert_match(/\.\.\.\(\d+ more bytes elided\)\z/, m)
    end
  end

  def test_ordinary_type_text_is_unchanged
    assert_includes messages('ByteString').join("\n"), "'ByteString'"
  end
end
