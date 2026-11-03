# frozen_string_literal: true

require_relative 'test_helper'
require 'runar_compiler/frontend/parser_ts'
require 'runar_compiler/frontend/expand_fixed_arrays'

# N-048 (external "PrematurePeek"): pass 3b hoists a computed FixedArray index
# to `const __idx_K` in front of its whole statement. In
#
#   assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);
#
# that bound the index BEFORE the increment, so the gate read the
# pre-increment slot (an outsider spend at cursor 0 was accepted under the real
# @bsv/sdk Spend). The AST has no let-expression, so every hoist that would
# reorder evaluation is refused with the diagnostic shared by all seven tiers.
#
# Proves: the same refused / accepted shapes as the TS reference
# (packages/runar-compiler/src/__tests__/03b-expand-fixed-arrays.test.ts).
# Does not prove on-chain behaviour; the TS VM test and
# conformance/negatives/N120-N122 cover that across tiers.
class TestN048FixedArrayIndexOrder < Minitest::Test
  include RunarCompiler::Frontend

  DIAG = 'FixedArray index would be evaluated out of source order'

  REFUSED = {
    'the reported shape' => 'assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);',
    'index after an earlier ++' => 'assert(++this.cursor + this.enabled[this.cursor % 2n] > 0n);',
    'index after an output intrinsic' => 'assert(this.addRawOutput(1n, toByteString("00")) === this.enabled[this.cursor % 2n]);',
    'right operand of &&' => 'assert(k > 0n && this.enabled[k - 1n] === 1n);',
    'right operand of ||' => 'assert(k === 0n || this.enabled[k - 1n] === 1n);',
    'ternary arm' => 'assert((c ? this.enabled[k + 1n] : 0n) === 0n);',
    'own ++ ahead of an earlier read' => 'assert(this.cursor + this.enabled[++this.cursor % 2n] > 0n);',
    'value read after target-index effect' => 'this.slots[++this.cursor % 2n] = this.enabled[this.cursor % 2n]; assert(true);'
  }.freeze

  ACCEPTED = {
    'increment in its own statement' => '++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);',
    'left operand of &&' => 'assert(this.enabled[k - 1n] === 1n && k > 0n);',
    'ternary condition' => 'assert((this.enabled[k + 1n] === 1n ? 1n : 0n) === 1n);',
    'effect after the read' => 'assert(this.enabled[this.cursor % 2n] + ++this.cursor > 0n);',
    'statement-form read' => 'const v = this.enabled[k + 1n]; assert(v === 1n);',
    'computed write index, effectful value' => 'this.slots[this.cursor % 2n] = ++this.cursor; assert(true);'
  }.freeze

  def expand(body)
    src = <<~TS
      class Peek extends StatefulSmartContract {
        readonly enabled: FixedArray<bigint, 2> = [1n, 0n];
        slots: FixedArray<bigint, 2> = [0n, 0n];
        cursor: bigint;
        constructor(cursor: bigint) { super(cursor); this.cursor = cursor; }
        public release(k: bigint, c: boolean) {
          #{body}
        }
      }
    TS
    parsed = RunarCompiler.send(:_parse_source, src, 'Peek.runar.ts')
    assert_empty parsed.errors.map(&:message)
    RunarCompiler::Frontend.expand_fixed_arrays(parsed.contract)
  end

  def joined(result)
    result.errors.map(&:message).join("\n")
  end

  def test_refuses_reordering_hoist
    REFUSED.each do |what, body|
      assert_includes joined(expand(body)), DIAG, "#{what}: expected the hoist-order refusal"
    end
  end

  def test_accepts_order_preserving_hoist
    ACCEPTED.each do |what, body|
      refute_includes joined(expand(body)), DIAG, "#{what}: unexpected hoist-order refusal"
    end
  end

  def test_split_form_hoists_after_increment
    result = expand('++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);')
    assert_empty result.errors.map(&:message)
    body = result.contract.methods.find { |m| m.name == 'release' }.body
    assert_kind_of ExpressionStmt, body[0]
    assert_kind_of VariableDeclStmt, body[1]
    assert body[1].name.start_with?('__idx_'), body[1].name
  end
end
