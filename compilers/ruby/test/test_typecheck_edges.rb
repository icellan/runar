# frozen_string_literal: true

require_relative 'test_helper'

require 'runar_compiler/frontend/ast_nodes'
require 'runar_compiler/frontend/diagnostic'
require 'runar_compiler/frontend/validator'
require 'runar_compiler/frontend/typecheck'
require 'runar_compiler/frontend/parser_ts'

# Additional negative coverage for the type checker. Focuses on rejection of
# non-Rúnar host-language methods that a developer might reach for out of
# habit (Ruby/Python/TS standard-library calls), and on builtin-family
# signature mismatches that are particularly easy to make.

class TestTypecheckEdges < Minitest::Test
  include RunarCompiler::Frontend

  def typecheck_source(source, file_name = 'Test.runar.ts')
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty parse_result.errors.map(&:format_message), 'unexpected parse errors'
    refute_nil parse_result.contract, 'expected a contract from parsing'
    RunarCompiler::Frontend.type_check(parse_result.contract)
  end

  def assert_typecheck_error(source, pattern = nil, file_name = 'Test.runar.ts')
    result = typecheck_source(source, file_name)
    assert result.errors.length > 0, 'expected at least one type check error'
    if pattern
      assert result.errors.any? { |e| e.message.downcase.include?(pattern.downcase) },
             "expected error matching '#{pattern}', got: #{result.error_strings}"
    end
  end

  # ---------------------------------------------------------------------------
  # Host-language stdlib methods must be rejected as unknown functions.
  # ---------------------------------------------------------------------------

  def test_rejects_array_isarray
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          const r = Array.isArray(this.x);
          assert(this.x > 0n);
        }
      }
    TS

    assert_typecheck_error(source, 'unknown function')
  end

  def test_rejects_json_stringify
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          const s = JSON.stringify(this.x);
          assert(this.x > 0n);
        }
      }
    TS

    assert_typecheck_error(source, 'unknown function')
  end

  def test_rejects_parse_int
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          const n = parseInt("42");
          assert(this.x > 0n);
        }
      }
    TS

    assert_typecheck_error(source, 'unknown function')
  end

  def test_rejects_math_max
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          // Math.max is JS stdlib, not Rúnar's `max` builtin
          const m = Math.max(a, b);
          assert(this.x > 0n);
        }
      }
    TS

    assert_typecheck_error(source, 'unknown function')
  end

  def test_accepts_rúnar_builtin_max
    source = <<~TS
      import { SmartContract, assert, max } from 'runar-lang';

      class Ok extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          const m = max(a, b);
          assert(m >= this.x);
        }
      }
    TS

    result = typecheck_source(source)
    assert_empty result.errors.map(&:format_message),
                 "rúnar builtin max should typecheck cleanly"
  end

  def test_accepts_rúnar_builtin_min
    source = <<~TS
      import { SmartContract, assert, min } from 'runar-lang';

      class Ok extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          const m = min(a, b);
          assert(m <= this.x);
        }
      }
    TS

    result = typecheck_source(source)
    assert_empty result.errors.map(&:format_message)
  end

  def test_accepts_rúnar_builtin_abs
    source = <<~TS
      import { SmartContract, assert, abs } from 'runar-lang';

      class Ok extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          assert(abs(a) >= 0n);
        }
      }
    TS

    result = typecheck_source(source)
    assert_empty result.errors.map(&:format_message)
  end

  # ---------------------------------------------------------------------------
  # Builtin signature errors
  # ---------------------------------------------------------------------------

  def test_hash160_wrong_arity
    source = <<~TS
      import { SmartContract, assert, hash160 } from 'runar-lang';

      class Bad extends SmartContract {
        readonly h: Addr;

        constructor(h: Addr) {
          super(h);
          this.h = h;
        }

        public check(a: ByteString, b: ByteString): void {
          assert(hash160(a, b) === this.h);
        }
      }
    TS

    assert_typecheck_error(source, 'expects')
  end

  def test_checksig_wrong_arity
    source = <<~TS
      import { SmartContract, assert, checkSig } from 'runar-lang';

      class Bad extends SmartContract {
        readonly pk: PubKey;

        constructor(pk: PubKey) {
          super(pk);
          this.pk = pk;
        }

        public check(sig: Sig): void {
          assert(checkSig(sig));
        }
      }
    TS

    assert_typecheck_error(source, 'expects')
  end

  def test_ripemd160_valid
    source = <<~TS
      import { SmartContract, assert, ripemd160 } from 'runar-lang';

      class Ok extends SmartContract {
        readonly h: Ripemd160;

        constructor(h: Ripemd160) {
          super(h);
          this.h = h;
        }

        public check(data: ByteString): void {
          assert(ripemd160(data) === this.h);
        }
      }
    TS

    result = typecheck_source(source)
    assert_empty result.errors.map(&:format_message)
  end

  # ---------------------------------------------------------------------------
  # Calling undeclared method on `this`
  # ---------------------------------------------------------------------------

  def test_rejects_unknown_this_method
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          const r = this.notARealMethod();
          assert(this.x > 0n);
        }
      }
    TS

    result = typecheck_source(source)
    assert result.errors.any?, "expected error for unknown this.method()"
  end

  # ---------------------------------------------------------------------------
  # Arithmetic on ByteString (without bitwise context) fails
  # ---------------------------------------------------------------------------

  def test_arithmetic_on_bytestring_fails
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Bad extends SmartContract {
        readonly tag: ByteString;

        constructor(tag: ByteString) {
          super(tag);
          this.tag = tag;
        }

        public check(): void {
          const r = this.tag + 1n;
          assert(this.tag === this.tag);
        }
      }
    TS

    # ByteString + bigint should fail typecheck.
    result = typecheck_source(source)
    assert result.errors.any?, "expected error for ByteString + bigint"
  end
end
