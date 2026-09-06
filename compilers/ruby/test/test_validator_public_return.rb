# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/parser_ts"

# NEW-012 -- `return` in a PUBLIC method.
#
# spec/grammar.md:161 makes public methods void, :162 makes their trailing
# assert the spending condition, and spec/semantics.md gives `return` no
# early-exit meaning at all (4.6 defines only "the value of this method is v";
# 4.7 sequences statements unconditionally).
#
# Lowering it as if it were the tail of an inlined helper produced two broken
# scripts: `return;` left the enclosing arm with no result, so it yielded OP_0
# and the whole script evaluated FALSE -- an unspendable UTXO from source that
# compiled clean; `return expr;` made the returned value the branch result and
# hence the script's final truthiness, so any truthy expr spent the contract
# WITHOUT reaching the guarding assert (fail-OPEN).
class TestValidatorPublicReturn < Minitest::Test
  include RunarCompiler::Frontend

  DIAG = "must not use `return`"

  def validate_ts(source)
    result = RunarCompiler.send(:_parse_source, source, "Guard.runar.ts")
    assert_empty result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil result.contract, "expected a contract from parsing"
    RunarCompiler::Frontend.validate(result.contract)
  end

  def count_diag(result, substr)
    result.errors.count { |e| e.message.include?(substr) }
  end

  def test_rejects_bare_return_in_public_method
    result = validate_ts(<<~TS)
      class Guard extends SmartContract {
        readonly secret: bigint;
        constructor(secret: bigint) { super(secret); this.secret = secret; }

        public unlock(x: bigint) {
          if (x > 0n) { return; }
          assert(x === this.secret);
        }
      }
    TS
    assert_equal 1, count_diag(result, DIAG), result.errors.map(&:message).inspect
  end

  def test_rejects_valued_return_in_public_method
    result = validate_ts(<<~TS)
      class Guard extends SmartContract {
        readonly secret: bigint;
        constructor(secret: bigint) { super(secret); this.secret = secret; }

        public unlock(x: bigint) {
          if (x > 0n) { return x; }
          assert(x === this.secret);
        }
      }
    TS
    assert_equal 1, count_diag(result, DIAG), result.errors.map(&:message).inspect
  end

  def test_rejects_return_nested_in_loop_in_public_method
    result = validate_ts(<<~TS)
      class Guard extends SmartContract {
        readonly secret: bigint;
        constructor(secret: bigint) { super(secret); this.secret = secret; }

        public unlock(x: bigint) {
          for (let i: bigint = 0n; i < 4n; i++) {
            if (x > i) { return; }
          }
          assert(x === this.secret);
        }
      }
    TS
    assert_equal 1, count_diag(result, DIAG), result.errors.map(&:message).inspect
  end

  # spec/grammar.md:168 -- "Private methods may return a value." The rejection
  # must not spill onto the inlined-helper form, which is how ~340 in-repo
  # contracts legitimately use `return`.
  def test_allows_return_in_private_helper
    result = validate_ts(<<~TS)
      class Guard extends SmartContract {
        readonly secret: bigint;
        constructor(secret: bigint) { super(secret); this.secret = secret; }

        private doubled(v: bigint): bigint { return v + v; }

        public unlock(x: bigint) {
          assert(this.doubled(x) === this.secret);
        }
      }
    TS
    assert_empty result.errors.map(&:message)
  end
end
