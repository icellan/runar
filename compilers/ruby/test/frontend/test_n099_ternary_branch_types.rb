# frozen_string_literal: true

require_relative "../test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/parser_ts"

# Port of the TypeScript reference test
# `packages/runar-compiler/src/__tests__/n099-ternary-branch-types.test.ts`.
#
# N-099 -- a ternary whose two arms have incompatible types.
#
#     const y: ByteString = f ? this.blob : x;   # blob: ByteString, x: bigint
#
# Measured across the seven tiers before the fix:
#
#     ts / rust / java          REJECT
#     go / python / zig / ruby  ACCEPT, 12 hexchars
#
# This tier silently took the CONSEQUENT's type as the expression's type. A
# ByteString and a bigint do not share a stack representation -- one is a byte
# string, the other a script number -- so the arm that was silently retyped
# leaves the wrong kind of value on the stack and everything downstream reads a
# type the author never wrote. Same class as the operand-position `<unknown>`
# escapes R-092 closed: a 33-byte push into an arithmetic opcode succeeds
# post-Genesis and computes something meaningless rather than failing.
#
# The fall-through this rule needs was already here -- `subtype?(alt, cons)`
# then `subtype?(cons, alt)` -- it returned `cons_type` from it instead of
# raising. Ported from the TypeScript reference (Rust carries it verbatim),
# wording included. The neighbouring "ternary condition must be boolean" message
# is lowercase in this tier's house style while TS capitalises it; that
# pre-existing casing divergence is left alone, and the NEW message matches TS
# exactly so the seven tiers agree on it.
class TestN099TernaryBranchTypes < Minitest::Test
  HEAD = <<~TS
    import { SmartContract, ByteString, Ripemd160, assert, hash160 } from 'runar-lang';

    class C extends SmartContract {
      readonly pkh: Ripemd160;
      readonly blob: ByteString;

      constructor(pkh: Ripemd160, blob: ByteString) {
        super(pkh, blob);
        this.pkh = pkh;
        this.blob = blob;
      }

      private anySats(): bigint { return 1n; }

  TS

  def self.contract(body)
    "#{HEAD}#{body}}\n"
  end

  # -- REJECT --------------------------------------------------------------

  MIXED_ARMS = contract(<<~TS)
      public go(x: bigint, f: boolean) {
        const y: ByteString = f ? this.blob : x;
        assert(y == this.blob);
      }
  TS

  # The mirror image. A rule that only looked one way would let this through.
  MIXED_ARMS_SWAPPED = contract(<<~TS)
      public go(x: bigint, f: boolean) {
        const y: bigint = f ? x : this.blob;
        assert(y > 0n);
      }
  TS

  # -- ACCEPT (over-rejection guards) --------------------------------------

  SAME_TYPE_ARMS = contract(<<~TS)
      public go(x: bigint, f: boolean) {
        const a: bigint = f ? x : 2n;
        assert(a > 0n);
      }
  TS

  # `Ripemd160` is a declared subtype of `ByteString`; subtype? relates them and
  # the rule must not fire.
  SUBTYPE_ARMS = contract(<<~TS)
      public go(x: bigint, f: boolean) {
        const b: ByteString = f ? this.blob : this.pkh;
        assert(hash160(b) != this.pkh || x > 0n);
      }
  TS

  # A private helper's declared return type is discarded at parse time in EVERY
  # tier, so this arm infers as `<unknown>` -- top of the subtype lattice, hence
  # related to everything. Must stay ACCEPTED.
  UNKNOWN_ARM = contract(<<~TS)
      public go(x: bigint, f: boolean) {
        const c: bigint = f ? this.anySats() : x;
        assert(c > 0n);
      }
  TS

  # Parse + typecheck a `.runar.ts` source, returning the type-check error
  # strings. A parse failure raises rather than being counted as a rejection.
  def typecheck_errors(source)
    parse_result = RunarCompiler.send(:_parse_source, source, "C.runar.ts")
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract, "fixture did not parse"

    RunarCompiler.send(:_type_check, parse_result.contract).errors.map(&:format_message)
  end

  def compile_hex(source)
    require "tempfile"
    tmp = Tempfile.new(["C", ".runar.ts"])
    tmp.write(source)
    tmp.close
    program = RunarCompiler.compile_source_to_ir(tmp.path)
    RunarCompiler.compile_from_program(program).script
  ensure
    tmp&.unlink
  end

  def assert_diagnostic(source, want)
    errs = typecheck_errors(source)
    assert errs.any? { |e| e.include?(want) },
           "expected a diagnostic containing #{want.inspect}; got #{errs.inspect}"
  end

  def test_rejects_incompatible_ternary_arms
    assert_diagnostic(
      MIXED_ARMS,
      "Ternary branches have incompatible types: 'ByteString' and 'bigint'"
    )
  end

  def test_rejects_the_swapped_shape_too
    assert_diagnostic(
      MIXED_ARMS_SWAPPED,
      "Ternary branches have incompatible types: 'bigint' and 'ByteString'"
    )
  end

  def test_accepted_ternary_arms
    {
      "identical arm types" => SAME_TYPE_ARMS,
      "a declared subtype pair (ByteString / Ripemd160)" => SUBTYPE_ARMS,
      "an arm inferred as <unknown>" => UNKNOWN_ARM
    }.each do |label, source|
      assert_empty typecheck_errors(source), "#{label} was rejected"
      refute_empty compile_hex(source), "#{label} compiled to an empty script"
    end
  end
end
