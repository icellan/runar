# frozen_string_literal: true

require_relative "../test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/parser_ts"

# Port of the TypeScript reference test
# `packages/runar-compiler/src/__tests__/n105-output-shape.test.ts`.
#
# N-105 (2/2) -- the rest of TypeScript's output-intrinsic CONTRACT: the
# StatefulSmartContract gate, the arity of all three intrinsics, and the types
# of addOutput's state values.
#
# N-098 ported the satoshis check and N-105 (1/2) the scriptBytes check. These
# three are the remainder, and each was a hole with an executed consequence:
#
#   this.addOutput(1000n)                  1352 hexchars -- the state value is
#     with one mutable property            simply MISSING from the
#                                          continuation; the correct call emits
#                                          1362.
#   this.addOutput(1000n, this.count, 5n)  1368 hexchars -- the surplus value is
#                                          appended to a state serialization the
#                                          next spend deserializes by fixed
#                                          offsets.
#   this.addOutput(1000n, this.blob)       1362 hexchars, DIFFERENT bytes -- the
#     with count: bigint                   ByteString is serialized where an
#                                          8-byte LE number belongs.
#   this.addRawOutput(...) in a            152 hexchars -- a "continuation" in a
#     stateless SmartContract              contract that has no state.
#
# All four are the same class as N-098: the compiler does not refuse, it emits a
# covenant that commits to the wrong thing.
#
# Ported from the TypeScript reference, wording included.
class TestN105OutputShape < Minitest::Test
  HEAD = <<~TS
    import { StatefulSmartContract, ByteString, PubKey, assert } from 'runar-lang';

    class C extends StatefulSmartContract {
      count: bigint;
      owner: PubKey;
      readonly base: bigint;
      readonly blob: ByteString;

      constructor(count: bigint, owner: PubKey, base: bigint, blob: ByteString) {
        super(count, owner, base, blob);
        this.count = count;
        this.owner = owner;
        this.base = base;
        this.blob = blob;
      }

      private anything(): bigint { return this.base; }

  TS

  STATELESS_HEAD = <<~TS
    import { SmartContract, ByteString, assert } from 'runar-lang';

    class C extends SmartContract {
      readonly base: bigint;
      readonly blob: ByteString;

      constructor(base: bigint, blob: ByteString) {
        super(base, blob);
        this.base = base;
        this.blob = blob;
      }

  TS

  def self.stateful(body)
    "#{HEAD}#{body}}\n"
  end

  def self.stateless(body)
    "#{STATELESS_HEAD}#{body}}\n"
  end

  # -- REJECT: arity -------------------------------------------------------

  ARITY_TOO_FEW = stateful(<<~TS)
      public m(n: bigint, who: PubKey) {
        assert(n > 0n);
        this.count = this.count + n;
        this.owner = who;
        this.addOutput(1000n, this.count);
      }
  TS

  ARITY_TOO_MANY = stateful(<<~TS)
      public m(n: bigint, who: PubKey) {
        assert(n > 0n);
        this.count = this.count + n;
        this.owner = who;
        this.addOutput(1000n, this.count, this.owner, 5n);
      }
  TS

  RAW_ARITY_ONE = stateful(<<~TS)
      public m(n: bigint, who: PubKey) {
        assert(n > 0n);
        this.count = this.count + n;
        this.owner = who;
        this.addOutput(1000n, this.count, this.owner);
        this.addRawOutput(500n);
      }
  TS

  RAW_ARITY_THREE = stateful(<<~TS)
      public m(n: bigint, who: PubKey) {
        assert(n > 0n);
        this.count = this.count + n;
        this.owner = who;
        this.addOutput(1000n, this.count, this.owner);
        this.addRawOutput(500n, this.blob, 7n);
      }
  TS

  DATA_ARITY_THREE = stateful(<<~TS)
      public m(n: bigint, who: PubKey) {
        assert(n > 0n);
        this.count = this.count + n;
        this.owner = who;
        this.addOutput(1000n, this.count, this.owner);
        this.addDataOutput(500n, this.blob, 7n);
      }
  TS

  # -- REJECT: state-value types -------------------------------------------

  STATE_VALUE_WRONG_TYPE = stateful(<<~TS)
      public m(n: bigint, who: PubKey) {
        assert(n > 0n);
        this.count = this.count + n;
        this.owner = who;
        this.addOutput(1000n, this.blob, this.owner);
      }
  TS

  # -- REJECT: the StatefulSmartContract gate ------------------------------

  STATELESS_ADD_OUTPUT = stateless(<<~TS)
      public m(n: bigint) {
        this.addOutput(1000n, n);
        assert(n > 0n);
      }
  TS

  STATELESS_ADD_RAW_OUTPUT = stateless(<<~TS)
      public m(n: bigint) {
        this.addRawOutput(1000n, this.blob);
        assert(n > 0n);
      }
  TS

  STATELESS_ADD_DATA_OUTPUT = stateless(<<~TS)
      public m(n: bigint) {
        this.addDataOutput(1000n, this.blob);
        assert(n > 0n);
      }
  TS

  # -- ACCEPT (over-rejection guards) --------------------------------------

  SHAPE_EXACT = stateful(<<~TS)
      public m(n: bigint, who: PubKey) {
        assert(n > 0n);
        this.count = this.count + n;
        this.owner = who;
        this.addOutput(1000n, this.count, this.owner);
      }
  TS

  # A ByteString value in a PubKey state slot. TS's isSubtype treats the
  # ByteString family as bidirectionally compatible, so TS ACCEPTS this and
  # every tier must keep accepting it -- measured before this change, all seven
  # tiers compiled it to the same script.
  SHAPE_FAMILY_WIDENING = stateful(<<~TS)
      public m(n: bigint, b: ByteString) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count, b);
      }
  TS

  # A private helper's declared return type is discarded at parse time in every
  # tier, so this infers as `<unknown>`. TS escapes it; every port must too.
  SHAPE_UNKNOWN_STATE_VALUE = stateful(<<~TS)
      public m(n: bigint, who: PubKey) {
        assert(n > 0n);
        this.count = this.count + n;
        this.owner = who;
        this.addOutput(1000n, this.anything(), this.owner);
      }
  TS

  # The one-mutable-property shape: the arity rule must be derived from the
  # contract, not hardcoded.
  ONE_PROP = <<~TS
    import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

    class C extends StatefulSmartContract {
      count: bigint;
      readonly blob: ByteString;

      constructor(count: bigint, blob: ByteString) {
        super(count, blob);
        this.count = count;
        this.blob = blob;
      }

      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addRawOutput(500n, this.blob);
      }
    }
  TS

  # A FixedArray state property. `expand_fixed_arrays` runs AFTER the
  # typechecker in this tier and splits `board` into three scalar siblings, so
  # the only call shape that lowers is the EXPANDED one below -- which the arity
  # rule, counting the two DECLARED mutable properties, would reject. This is
  # the contract from
  # compilers/python/tests/test_r025_expand_fixed_arrays_field_preservation.py,
  # checked into this repo and compiled by all six non-TS tiers; the TypeScript
  # reference rejects it ("expects 3 argument(s) ... got 5"), which is a defect
  # in the reference rule, not in this source.
  FIXED_ARRAY_STATE = <<~TS
    import { StatefulSmartContract, assert } from 'runar-lang';
    import type { FixedArray } from 'runar-lang';

    class Boardy extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      public bump(): void { this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n); }
    }
  TS

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

  # -- the defect ----------------------------------------------------------

  def test_add_output_arity
    assert_diagnostic(
      ARITY_TOO_FEW,
      "addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 2"
    )
    assert_diagnostic(
      ARITY_TOO_MANY,
      "addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 4"
    )
  end

  def test_raw_and_data_output_arity
    assert_diagnostic(
      RAW_ARITY_ONE,
      "addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 1"
    )
    assert_diagnostic(
      RAW_ARITY_THREE,
      "addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 3"
    )
    assert_diagnostic(
      DATA_ARITY_THREE,
      "addDataOutput() expects 2 arguments (satoshis, scriptBytes), got 3"
    )
  end

  def test_add_output_state_value_types
    assert_diagnostic(
      STATE_VALUE_WRONG_TYPE,
      "addOutput() argument 2 (count) must be 'bigint', got 'ByteString'"
    )
  end

  def test_output_intrinsics_are_stateful_only
    assert_diagnostic(
      STATELESS_ADD_OUTPUT,
      "addOutput() is only available in StatefulSmartContract"
    )
    assert_diagnostic(
      STATELESS_ADD_RAW_OUTPUT,
      "addRawOutput() is only available in StatefulSmartContract"
    )
    assert_diagnostic(
      STATELESS_ADD_DATA_OUTPUT,
      "addDataOutput() is only available in StatefulSmartContract"
    )
  end

  # -- controls ------------------------------------------------------------

  def test_accepted_output_shapes
    {
      "exact arity and exact types" => SHAPE_EXACT,
      "ByteString value in a PubKey state slot" => SHAPE_FAMILY_WIDENING,
      "private helper call, inferred as <unknown>" => SHAPE_UNKNOWN_STATE_VALUE
    }.each do |label, source|
      assert_empty typecheck_errors(source), "#{label} was rejected"
      refute_empty compile_hex(source), "#{label} compiled to an empty script"
    end
  end

  # Non-vacuity: the arity rule must be derived from the contract's mutable
  # properties, not hardcoded.
  def test_arity_is_derived_from_mutable_properties
    refute_empty compile_hex(ONE_PROP)
    refute_empty compile_hex(SHAPE_EXACT)
  end

  # The carve-out, pinned: a FixedArray-state contract must stay compilable.
  def test_fixed_array_state_is_out_of_scope
    refute_empty compile_hex(FIXED_ARRAY_STATE)
  end
end
