# frozen_string_literal: true

require_relative "test_helper"

# Pull in frontend modules for direct validation + type checking.
require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/parser_ts"

class TestTypecheck < Minitest::Test
  include RunarCompiler::Frontend

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Parse TS source, validate, and type-check. Returns the TypeCheckResult.
  def typecheck_source(source, file_name = "Test.runar.ts")
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract, "expected a contract from parsing"

    val_result = RunarCompiler::Frontend.validate(parse_result.contract)
    # We allow validation errors in some tests (we're testing typecheck specifically)

    RunarCompiler::Frontend.type_check(parse_result.contract)
  end

  # Parse, validate, type-check -- expect zero errors from all passes.
  def assert_typecheck_clean(source, file_name = "Test.runar.ts", msg = nil)
    result = typecheck_source(source, file_name)
    assert_empty result.errors.map(&:format_message),
                 msg || "expected zero type check errors"
  end

  # Parse, validate, type-check -- expect at least one type check error.
  def assert_typecheck_error(source, pattern = nil, file_name = "Test.runar.ts")
    result = typecheck_source(source, file_name)
    assert result.errors.length > 0, "expected at least one type check error"
    if pattern
      assert result.errors.any? { |e| e.message.downcase.include?(pattern.downcase) },
             "expected error matching '#{pattern}', got: #{result.error_strings}"
    end
  end

  # ---------------------------------------------------------------------------
  # 1. Valid P2PKH passes type check
  # ---------------------------------------------------------------------------

  def test_valid_p2pkh
    source = <<~TS
      import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

      class P2PKH extends SmartContract {
        readonly pubKeyHash: Addr;

        constructor(pubKeyHash: Addr) {
          super(pubKeyHash);
          this.pubKeyHash = pubKeyHash;
        }

        public unlock(sig: Sig, pubKey: PubKey): void {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS

    assert_typecheck_clean(source, "P2PKH.runar.ts")
  end

  # ---------------------------------------------------------------------------
  # 2. Unknown function call fails (Math.floor)
  # ---------------------------------------------------------------------------

  def test_unknown_function_math_floor
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          const y = Math.floor(3n);
          assert(this.x > 0n);
        }
      }
    TS

    assert_typecheck_error(source, "unknown function")
  end

  # ---------------------------------------------------------------------------
  # 3. Unknown function call fails (console.log)
  # ---------------------------------------------------------------------------

  def test_unknown_function_console_log
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          console.log(this.x);
          assert(this.x > 0n);
        }
      }
    TS

    assert_typecheck_error(source, "unknown function")
  end

  # ---------------------------------------------------------------------------
  # 4. Type mismatch: boolean used in arithmetic
  # ---------------------------------------------------------------------------

  def test_type_mismatch_boolean_in_arithmetic
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class TypeMismatch extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(flag: boolean): void {
          const y = flag + 1n;
          assert(y > 0n);
        }
      }
    TS

    assert_typecheck_error(source, "bigint")
  end

  # ---------------------------------------------------------------------------
  # 5. Valid boolean logic passes
  # ---------------------------------------------------------------------------

  def test_valid_boolean_logic
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class BoolLogic extends SmartContract {
        readonly x: bigint;
        readonly y: bigint;

        constructor(x: bigint, y: bigint) {
          super(x, y);
          this.x = x;
          this.y = y;
        }

        public check(a: bigint, b: bigint): void {
          const p = a > 0n;
          const q = b > 0n;
          assert(p && q);
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 6. Valid builtin calls pass (sha256, hash160)
  # ---------------------------------------------------------------------------

  def test_valid_builtin_sha256
    source = <<~TS
      import { SmartContract, assert, sha256 } from 'runar-lang';

      class HashTest extends SmartContract {
        readonly h: Sha256;

        constructor(h: Sha256) {
          super(h);
          this.h = h;
        }

        public check(data: ByteString): void {
          assert(sha256(data) === this.h);
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 7. Wrong argument count for builtins fails
  # ---------------------------------------------------------------------------

  def test_wrong_arg_count_sha256
    source = <<~TS
      import { SmartContract, assert, sha256 } from 'runar-lang';

      class Bad extends SmartContract {
        readonly h: Sha256;

        constructor(h: Sha256) {
          super(h);
          this.h = h;
        }

        public check(a: ByteString, b: ByteString): void {
          assert(sha256(a, b) === this.h);
        }
      }
    TS

    assert_typecheck_error(source, "expects")
  end

  # ---------------------------------------------------------------------------
  # 8. checkSig with correct types passes
  # ---------------------------------------------------------------------------

  def test_valid_checksig
    source = <<~TS
      import { SmartContract, assert, checkSig } from 'runar-lang';

      class SigTest extends SmartContract {
        readonly pk: PubKey;

        constructor(pk: PubKey) {
          super(pk);
          this.pk = pk;
        }

        public check(sig: Sig): void {
          assert(checkSig(sig, this.pk));
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 9. Subtype compatibility: PubKey -> ByteString
  # ---------------------------------------------------------------------------

  def test_subtype_pubkey_to_bytestring
    source = <<~TS
      import { SmartContract, assert, hash160 } from 'runar-lang';

      class SubtypeTest extends SmartContract {
        readonly pubKeyHash: Addr;

        constructor(pubKeyHash: Addr) {
          super(pubKeyHash);
          this.pubKeyHash = pubKeyHash;
        }

        public unlock(pubKey: PubKey): void {
          const h: ByteString = pubKey;
          assert(hash160(h) === this.pubKeyHash);
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 10. Comparison operators require bigint
  # ---------------------------------------------------------------------------

  def test_comparison_requires_bigint
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: boolean, b: boolean): void {
          assert(a > b);
        }
      }
    TS

    assert_typecheck_error(source, "bigint")
  end

  # ---------------------------------------------------------------------------
  # 11. Logical AND/OR require boolean operands
  # ---------------------------------------------------------------------------

  def test_logical_and_requires_boolean
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          assert(a && b);
        }
      }
    TS

    assert_typecheck_error(source, "boolean")
  end

  # ---------------------------------------------------------------------------
  # 12. Unary NOT requires boolean
  # ---------------------------------------------------------------------------

  def test_unary_not_requires_boolean
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          assert(!a);
        }
      }
    TS

    assert_typecheck_error(source, "boolean")
  end

  # ---------------------------------------------------------------------------
  # 13. Unary negate requires bigint
  # ---------------------------------------------------------------------------

  def test_unary_negate_requires_bigint
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: boolean): void {
          const y = -a;
          assert(y > 0n);
        }
      }
    TS

    assert_typecheck_error(source, "bigint")
  end

  # ---------------------------------------------------------------------------
  # 14. If condition must be boolean
  # ---------------------------------------------------------------------------

  def test_if_condition_must_be_boolean
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          if (a) {
            assert(true);
          } else {
            assert(false);
          }
        }
      }
    TS

    assert_typecheck_error(source, "boolean")
  end

  # ---------------------------------------------------------------------------
  # 15. Valid arithmetic operations pass
  # ---------------------------------------------------------------------------

  def test_valid_arithmetic
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Arith extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          const sum = a + b;
          const diff = a - b;
          const prod = a * b;
          assert(sum > diff);
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 16. Valid hash functions all pass
  # ---------------------------------------------------------------------------

  def test_valid_hash_builtins
    source = <<~TS
      import { SmartContract, assert, sha256, ripemd160, hash160, hash256 } from 'runar-lang';

      class Hashes extends SmartContract {
        readonly h: Sha256;

        constructor(h: Sha256) {
          super(h);
          this.h = h;
        }

        public check(data: ByteString): void {
          const s = sha256(data);
          const r = ripemd160(data);
          const h1 = hash160(data);
          const h2 = hash256(data);
          assert(s === this.h);
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 17. Valid math builtins pass (abs, min, max, within)
  # ---------------------------------------------------------------------------

  def test_valid_math_builtins
    source = <<~TS
      import { SmartContract, assert, abs, min, max, within } from 'runar-lang';

      class MathTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          const absVal = abs(a);
          const minVal = min(a, b);
          const maxVal = max(a, b);
          const inRange = within(a, 0n, 100n);
          assert(absVal >= 0n);
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 18. Unknown standalone function fails
  # ---------------------------------------------------------------------------

  def test_unknown_standalone_function
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          const y = unknownFunc(42n);
          assert(y > 0n);
        }
      }
    TS

    assert_typecheck_error(source, "unknown function")
  end

  # ---------------------------------------------------------------------------
  # 19. Unknown method on this fails
  # ---------------------------------------------------------------------------

  def test_unknown_method_on_this
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          const y = this.nonexistent(42n);
          assert(y > 0n);
        }
      }
    TS

    assert_typecheck_error(source, "unknown")
  end

  # ---------------------------------------------------------------------------
  # 20. Valid cat() passes
  # ---------------------------------------------------------------------------

  def test_valid_cat_builtin
    source = <<~TS
      import { SmartContract, assert, cat } from 'runar-lang';

      class CatTest extends SmartContract {
        readonly h: ByteString;

        constructor(h: ByteString) {
          super(h);
          this.h = h;
        }

        public check(a: ByteString, b: ByteString): void {
          const result = cat(a, b);
          assert(result === this.h);
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 21. assert() requires boolean condition
  # ---------------------------------------------------------------------------

  def test_assert_requires_boolean
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          assert(42n);
        }
      }
    TS

    assert_typecheck_error(source, "boolean")
  end

  # ---------------------------------------------------------------------------
  # 22. Shift operators require bigint
  # ---------------------------------------------------------------------------

  def test_shift_operators_require_bigint
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class ShiftTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          const left = a << b;
          const right = a >> b;
          assert(left > 0n);
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 23. Bitwise operators on bigint pass
  # ---------------------------------------------------------------------------

  def test_bitwise_operators_bigint
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class BitwiseTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          const andResult = a & b;
          const orResult = a | b;
          const xorResult = a ^ b;
          assert(andResult >= 0n);
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 24. Valid contract method call on this passes
  # ---------------------------------------------------------------------------

  def test_valid_method_call_on_this
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class MethodCall extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        private helper(a: bigint): bigint {
          return a + 1n;
        }

        public check(a: bigint): void {
          const r = this.helper(a);
          assert(r > 0n);
        }
      }
    TS

    assert_typecheck_clean(source)
  end

  # ---------------------------------------------------------------------------
  # 25. assert() with too many args fails
  # ---------------------------------------------------------------------------

  def test_assert_too_many_args
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          assert(true, "msg", 42n);
        }
      }
    TS

    assert_typecheck_error(source, "assert")
  end

  # ---------------------------------------------------------------------------
  # F-063: infer_expr_type walks array-literal elements
  # ---------------------------------------------------------------------------
  #
  # infer_expr_type had no ArrayLiteralExpr arm, so every array literal typed
  # as "<unknown>" (accepted by subtype? against anything) and its elements
  # were never visited: checkMultiSig's argument check was vacuous and a call
  # nested in an element never reached the unknown-function rule. Pre-fix the
  # mismatch shapes compiled to a locking script.
  #
  # Proves: type_check refuses each shape (TS reference wording for the
  # element mismatch). Does not prove: CLI exit status or cross-tier parity.

  F063_TC_HEADER = <<~TS
    class C extends SmartContract {
      readonly pk: PubKey;
      constructor(pk: PubKey) { super(pk); this.pk = pk; }
  TS

  def f063_type_errors(body)
    typecheck_source(F063_TC_HEADER + body + "\n}\n").errors.map(&:message)
  end

  def test_f063_unknown_function_inside_array_literal_rejected
    errs = f063_type_errors("public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, totallyBogusFunction(1n)])); }")
    assert errs.any? { |m| m.include?("unknown function 'totallyBogusFunction'") }, errs.inspect
  end

  def test_f063_array_element_type_mismatch_rejected
    errs = f063_type_errors("public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, 1n])); }")
    assert errs.any? { |m| m.include?("Array element type mismatch: expected 'PubKey', got 'bigint'") }, errs.inspect
  end

  def test_f063_check_multisig_wrong_array_types_rejected
    errs = f063_type_errors("public unlock(s: Sig) { assert(checkMultiSig([1n], [2n, 3n])); }")
    assert errs.any? { |m| m.include?("expected 'Sig[]', got 'bigint[]'") }, errs.inspect
    assert errs.any? { |m| m.include?("expected 'PubKey[]', got 'bigint[]'") }, errs.inspect
  end

  def test_f063_well_typed_check_multisig_accepted
    errs = f063_type_errors("public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, this.pk])); }")
    assert_empty errs
  end

  # F-110: a bounded loop is unrolled `count` times, so an affine value bound
  # outside a loop that runs two or more times and consumed in its body is
  # consumed once per iteration and must get the same diagnostic as a
  # sequential double use. Single-iteration loops stay legal. Proves the type
  # checker's verdict only; consumption inside private helpers is out of scope
  # (the affine check is intra-method).
  F110_CASES = [
    ["sig: Sig", "for (let i = 0n; i < 2n; i++) { assert(checkSig(sig, this.pk)); }", "affine value 'sig' has already been consumed"],
    ["preimage: SigHashPreimage", "for (let i = 3n; i > 0n; i--) { assert(checkPreimage(preimage)); }", "affine value 'preimage' has already been consumed"],
    ["sig: Sig", "for (let i = 0n; i <= 1n; i++) { const s: Sig = sig; assert(checkSig(s, this.pk)); }", "affine value 's' has already been consumed"],
    ["sig: Sig", "for (let i = 0n; i < 2n; i++) { for (let j = 0n; j < 1n; j++) { assert(checkSig(sig, this.pk)); } }", "affine value 'sig' has already been consumed"],
    ["sig: Sig", "assert(checkSig(sig, this.pk)); for (let i = 0n; i < 1n; i++) { assert(checkSig(sig, this.pk)); }", "affine value 'sig' has already been consumed"],
    ["sig: Sig", "for (let i = 0n; i < 1n; i++) { assert(checkSig(sig, this.pk)); }", nil],
    ["sig: Sig", "for (let i = 5n; i >= 5n; i--) { for (let j = 0n; j <= 0n; j++) { assert(checkSig(sig, this.pk)); } }", nil],
  ].freeze

  def test_f110_affine_consumption_in_repeating_loop
    F110_CASES.each do |params, body, want|
      source = "class C extends SmartContract {\n  readonly pk: PubKey;\n" \
               "  constructor(pk: PubKey) { super(pk); this.pk = pk; }\n" \
               "  public m(#{params}) {\n    #{body}\n    assert(true);\n  }\n}\n"
      errs = typecheck_source(source).errors.map(&:message)
      if want.nil?
        assert_empty errs, body
      else
        assert errs.any? { |m| m.include?(want) }, "#{body}: #{errs.inspect}"
      end
    end
  end

  # F-222: the then and else arms of an if are mutually exclusive, so a Sig
  # consumed once in each arm is consumed once on every path and must
  # typecheck. Every shape where some path consumes twice (an arm plus after
  # the if, before plus an arm, twice in one arm, once per arm inside a
  # 2-iteration loop) must still be refused. Proves the type checker's verdict
  # only; the ternary form is not an if statement and is untouched.
  F222_DOUBLE = "affine value 'sig' has already been consumed"
  F222_CASES = [
    ["if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); }", nil],
    ["if (flag) { const a: Sig = sig; assert(checkSig(a, this.pk)); } else { assert(checkSig(sig, this.pk)); }", nil],
    ["if (flag) { assert(checkSig(sig, this.pk)); } else { if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } }", nil],
    ["if (flag) { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));", F222_DOUBLE],
    ["if (flag) { assert(true); } else { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));", F222_DOUBLE],
    ["if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));", F222_DOUBLE],
    ["if (flag) { if (flag) { assert(checkSig(sig, this.pk)); } } else { assert(true); } assert(checkSig(sig, this.pk));", F222_DOUBLE],
    ["const a: Sig = sig; if (flag) { assert(checkSig(a, this.pk)); } else { assert(true); } assert(checkSig(sig, this.pk));", F222_DOUBLE],
    ["assert(checkSig(sig, this.pk)); if (flag) { assert(checkSig(sig, this.pk)); }", F222_DOUBLE],
    ["if (flag) { assert(checkSig(sig, this.pk)); assert(checkSig(sig, this.pk)); } else { assert(true); }", F222_DOUBLE],
    ["if (flag) { assert(true); } else { assert(checkSig(sig, this.pk)); assert(checkSig(sig, this.pk)); }", F222_DOUBLE],
    ["for (let i = 0n; i < 2n; i++) { if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } }", F222_DOUBLE],
  ].freeze

  def test_f222_affine_consumption_across_if_else_arms
    F222_CASES.each do |body, want|
      source = "class C extends SmartContract {\n  readonly pk: PubKey;\n" \
               "  constructor(pk: PubKey) { super(pk); this.pk = pk; }\n" \
               "  public m(sig: Sig, flag: boolean) {\n    #{body}\n    assert(true);\n  }\n}\n"
      errs = typecheck_source(source).errors.map(&:message)
      if want.nil?
        assert_empty errs, body
      else
        assert errs.any? { |m| m.include?(want) }, "#{body}: #{errs.inspect}"
      end
    end
  end

  # N-109: private helpers are inlined, so a call consumes the arguments at the
  # parameter positions the helper consumes (directly, through an alias, or
  # transitively through another helper). `this.h(sig)` twice, or once in a
  # 2-iteration loop, must get the same diagnostic as a sequential double use;
  # a single call, one call per if/else arm, and a helper that takes a Sig
  # without consuming it stay legal. Proves the type checker's verdict only; a
  # helper consuming a PROPERTY is not covered.
  N109_H = "private h(s: Sig): void { assert(checkSig(s, this.pk)); }"
  N109_DOUBLE = "affine value 'sig' has already been consumed"
  N109_CASES = [
    [N109_H, "sig: Sig", "this.h(sig); this.h(sig);", N109_DOUBLE],
    [N109_H, "sig: Sig", "for (let i = 0n; i < 2n; i++) { this.h(sig); }", N109_DOUBLE],
    [N109_H, "sig: Sig", "assert(checkSig(sig, this.pk)); this.h(sig);", N109_DOUBLE],
    ["#{N109_H} private g(t: bigint, s2: Sig): void { assert(t > 0n); this.h(s2); }", "sig: Sig", "this.g(1n, sig); this.g(2n, sig);", N109_DOUBLE],
    ["private h(s: Sig): void { const a: Sig = s; assert(checkSig(a, this.pk)); }", "sig: Sig", "this.h(sig); this.h(sig);", N109_DOUBLE],
    ["private p(x: SigHashPreimage): void { assert(checkPreimage(x)); }", "preimage: SigHashPreimage", "this.p(preimage); this.p(preimage);", "affine value 'preimage' has already been consumed"],
    [N109_H, "sig: Sig", "this.h(sig);", nil],
    [N109_H, "sig: Sig, flag: boolean", "if (flag) { this.h(sig); } else { this.h(sig); }", nil],
    [N109_H, "sig1: Sig, sig2: Sig", "this.h(sig1); this.h(sig2);", nil],
    ["private n(s: Sig): bigint { return len(s); }", "sig: Sig", "assert(this.n(sig) > 0n); assert(this.n(sig) > 0n); assert(checkSig(sig, this.pk));", nil],
  ].freeze

  def test_n109_affine_consumption_through_helpers
    N109_CASES.each do |helpers, params, body, want|
      source = "class C extends SmartContract {\n  readonly pk: PubKey;\n" \
               "  constructor(pk: PubKey) { super(pk); this.pk = pk; }\n" \
               "  #{helpers}\n" \
               "  public m(#{params}) {\n    #{body}\n    assert(true);\n  }\n}\n"
      errs = typecheck_source(source).errors.map(&:message)
      if want.nil?
        assert_empty errs, body
      else
        assert errs.any? { |m| m.include?(want) }, "#{body}: #{errs.inspect}"
      end
    end
  end

  # N-288: the N-109 summary covered parameters only. A helper that consumes a
  # PROPERTY (`checkSig(this.sig, ..)`, `checkPreimage(this.txPreimage)`) is
  # inlined at every call site, so calling it twice must get the diagnostic a
  # direct double use of the property gets, also per loop iteration, after a
  # direct consume, through an alias and transitively; a single call, one call
  # per if/else arm, and a helper that only reads the property stay legal.
  # Proves the type checker's verdict only, not the emitted script.
  N288_H = "private h(): void { assert(checkSig(this.sig, this.pk)); }"
  N288_DOUBLE = "affine value 'this.sig' has already been consumed"
  N288_STATELESS = "class C extends SmartContract {\n  readonly pk: PubKey;\n  readonly sig: Sig;\n" \
                   "  constructor(pk: PubKey, sig: Sig) { super(pk, sig); this.pk = pk; this.sig = sig; }\n"
  N288_STATEFUL = "class C extends StatefulSmartContract {\n  count: bigint;\n" \
                  "  constructor(count: bigint) { super(count); this.count = count; }\n"
  N288_CASES = [
    [N288_STATELESS, N288_H, "", "this.h(); this.h();", N288_DOUBLE],
    [N288_STATELESS, N288_H, "", "for (let i = 0n; i < 2n; i++) { this.h(); }", N288_DOUBLE],
    [N288_STATELESS, N288_H, "", "assert(checkSig(this.sig, this.pk)); this.h();", N288_DOUBLE],
    [N288_STATELESS, "#{N288_H} private g(t: bigint): void { assert(t > 0n); this.h(); }", "", "this.g(1n); this.g(2n);", N288_DOUBLE],
    [N288_STATELESS, "private h(): void { const a: Sig = this.sig; assert(checkSig(a, this.pk)); }", "", "this.h(); this.h();", N288_DOUBLE],
    [N288_STATEFUL, "private h(): void { assert(checkPreimage(this.txPreimage)); }", "", "this.h(); this.h(); this.count = this.count + 1n;", "affine value 'this.txPreimage' has already been consumed"],
    [N288_STATELESS, N288_H, "", "this.h();", nil],
    [N288_STATELESS, N288_H, "flag: boolean", "if (flag) { this.h(); } else { this.h(); }", nil],
    [N288_STATELESS, "private n(): bigint { return len(this.sig); }", "", "assert(this.n() > 0n); assert(this.n() > 0n); assert(checkSig(this.sig, this.pk));", nil],
  ].freeze

  def test_n288_affine_property_consumption_through_helpers
    N288_CASES.each do |header, helpers, params, body, want|
      source = "#{header}  #{helpers}\n" \
               "  public m(#{params}) {\n    #{body}\n    assert(true);\n  }\n}\n"
      errs = typecheck_source(source).errors.map(&:message)
      if want.nil?
        assert_empty errs, body
      else
        assert errs.any? { |m| m.include?(want) }, "#{body}: #{errs.inspect}"
      end
    end
  end

  # ---------------------------------------------------------------------------
  # F-265: substr() literal negative start is a compile-time error
  #
  # substr(witness, start, len) lowers to a raw OP_SPLIT argument. No pass
  # enforced start >= 0: a literal negative start (`substr(a, -5n, 3n)`)
  # type-checked as plain 'bigint' (the standard subtype loop never inspects
  # a literal's VALUE) and compiled to a script that aborts at runtime --
  # `-5n` minimal-encodes to `<85>`, which OP_SPLIT rejects as out of range.
  #
  # Mirrors the existing extractPrevOutputScript/requireOutputP2PKH
  # "must be >= 0" literal-bound pattern above.
  #
  # Proves: a literal (bare or unary-negated BigIntLiteral) negative start is
  # now a typecheck-time diagnostic. Does not prove: anything about a
  # NON-literal negative start (a variable or computed expression) -- that
  # remains a runtime abort, unchanged, because the stack model has no
  # static value range for a non-literal.
  # ---------------------------------------------------------------------------

  def test_f265_substr_literal_negative_start_rejected
    source = <<~TS
      class C extends SmartContract {
        readonly a: ByteString;
        constructor(a: ByteString) { super(a); this.a = a; }
        public unlock() {
          assert(substr(this.a, -5n, 3n) === this.a);
        }
      }
    TS
    errs = typecheck_source(source).errors.map(&:message)
    assert errs.any? { |m| m.include?("substr() argument 2 (start) must be >= 0; got -5") },
           "expected a substr() start-bound error, got: #{errs.inspect}"
  end

  def test_f265_substr_literal_non_negative_start_accepted
    source = <<~TS
      class C extends SmartContract {
        readonly a: ByteString;
        constructor(a: ByteString) { super(a); this.a = a; }
        public unlock() {
          assert(substr(this.a, 0n, 3n) === this.a);
        }
      }
    TS
    assert_typecheck_clean source
  end

  def test_f265_substr_non_literal_start_unchanged
    source = <<~TS
      class C extends SmartContract {
        readonly a: ByteString;
        constructor(a: ByteString) { super(a); this.a = a; }
        public unlock(n: bigint) {
          assert(substr(this.a, n, 3n) === this.a);
        }
      }
    TS
    assert_typecheck_clean source
  end

  # ---------------------------------------------------------------------------
  # N-234: a property initializer of the wrong literal family compiled
  # without complaint. Proves only the Ruby tier's check_property_initializers;
  # the 7-tier cross-compiler shape is conformance/negatives/N233-*.
  # ---------------------------------------------------------------------------

  def test_n234_rejects_bytestring_initializer_for_bigint_property
    source = <<~TS
      class BadScalarInit extends SmartContract {
        readonly x: bigint = 'ab';
        constructor() { super(); }
        public check() { assert(this.x === 1n); }
      }
    TS
    assert_typecheck_error source, "type 'ByteString' is not assignable to type 'bigint'"
  end

  def test_n234_rejects_to_bytestring_call_initializer_for_bigint_property
    source = <<~TS
      class BadScalarInit extends SmartContract {
        readonly x: bigint = toByteString('ab');
        constructor() { super(); }
        public check() { assert(this.x === 1n); }
      }
    TS
    assert_typecheck_error source, "type 'ByteString' is not assignable to type 'bigint'"
  end

  def test_n234_still_accepts_well_typed_scalar_initializer
    source = <<~TS
      class GoodScalarInit extends SmartContract {
        readonly x: bigint = 1n;
        constructor() { super(); }
        public check() { assert(this.x === 1n); }
      }
    TS
    assert_typecheck_clean source
  end
end
