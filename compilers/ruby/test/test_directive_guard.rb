# frozen_string_literal: true

require_relative 'test_helper'

# The @sighash (#123) and @embedAlways (#109) comment directives are honored
# ONLY on the `.runar.ts` surface. On the other 8 formats Ruby's parsers ignore
# comments, so the compiler must fail closed rather than silently drop them.
class TestDirectiveGuard < Minitest::Test
  def parse(source, file_name = 'Counter.runar.ts')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  # @sighash (#123) is implemented for .runar.ts — it must NOT be rejected
  # there. The other 8 formats still fail closed.
  def test_sighash_allowed_on_ts
    source = <<~TS
      class Counter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public bump() { this.addOutput(1000n, this.n); }
      }
    TS
    result = parse(source, 'Counter.runar.ts')
    refute(result.error_strings.any? { |m| m.include?('not supported') },
           "@sighash must compile on .runar.ts: #{result.error_strings}")
  end

  def test_sighash_directive_rejected_on_non_ts
    source = "# @sighash SINGLE|FORKID\nclass Counter < SmartContract\nend\n"
    result = parse(source, 'Counter.runar.rb')
    joined = result.error_strings.join("\n")
    assert result.errors.any?, 'expected fail-closed error for @sighash on .runar.rb'
    assert_includes joined, '@sighash'
    assert_includes joined, '#123'
  end

  # @embedAlways (#109) is implemented for .runar.ts — it must NOT be rejected
  # there. The other 8 formats still fail closed.
  def test_embed_always_allowed_on_ts
    source = <<~TS
      class Counter extends SmartContract {
        /** @embedAlways */
        readonly x: bigint;
        constructor(x: bigint) { super(x); this.x = x; }
        public unlock() { assert(true); }
      }
    TS
    result = parse(source, 'Counter.runar.ts')
    refute(result.error_strings.any? { |m| m.include?('@embedAlways') },
           "@embedAlways must compile on .runar.ts: #{result.error_strings}")
  end

  def test_embed_always_directive_rejected_on_non_ts
    source = <<~RB
      # @embedAlways
      class Counter < SmartContract
      end
    RB
    result = parse(source, 'Counter.runar.rb')
    joined = result.error_strings.join("\n")
    assert result.errors.any?, 'expected fail-closed error for @embedAlways on .runar.rb'
    assert_includes joined, '@embedAlways'
    assert_includes joined, '#109'
  end

  def test_non_directive_identifier_does_not_trip_guard
    # A field named `sighashType` (no `@`) must NOT trip the `@sighash` guard.
    source = <<~TS
      class Counter extends SmartContract {
        readonly sighashType: bigint;
        constructor(sighashType: bigint) { super(sighashType); this.sighashType = sighashType; }
        public unlock() {}
      }
    TS
    result = parse(source)
    refute(result.error_strings.any? { |m| m.include?('not yet supported') },
           "directive guard tripped on a non-directive identifier: #{result.error_strings}")
  end
end
