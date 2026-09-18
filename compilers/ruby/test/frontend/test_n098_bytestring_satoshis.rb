# frozen_string_literal: true

require_relative "../test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/parser_ts"

# Port of the TypeScript reference test
# `packages/runar-compiler/src/__tests__/n098-bytestring-satoshis.test.ts`.
#
# N-098 -- a ByteString in the SATOSHIS position of an output intrinsic.
#
# This tier ACCEPTED all three shapes. It was not a missing diagnostic: the
# ByteString was lowered into the satoshis slot with NO conversion, and the
# emitted script was byte-identical to the same contract written with
# `blob: bigint` -- 1358 hexchars, same digest, in all six accepting tiers.
#
# `lower_add_output` prepends the satoshis operand as `OP_8 OP_NUM2BIN`, so the
# covenant commits to whatever those bytes decode to as a script number.
# Executed on the real @bsv/sdk Spend engine with `blob = 0x2a`, a 42-satoshi
# continuation VALIDATES and the 1000-satoshi one the author funded is
# REJECTED. Bigger blobs fail shut rather than safe: 0xcafebabefeed0001 demands
# 7.2e16 satoshis and a 20-byte hash aborts the script at OP_NUM2BIN, leaving
# the UTXO permanently unspendable.
#
# The rule ported here is the TypeScript reference's, wording included. Only the
# FIRST argument is checked. TS additionally checks arity, the state-value types
# and the scriptBytes argument; none of those are ported here and none of them
# are this finding.
#
# The ACCEPT block carries the real risk in a change like this. `<unknown>` must
# stay accepted: a private helper's declared return type is discarded at parse
# time in every tier, so `this.sats()` infers as `<unknown>`, and TS has always
# escaped it here.
class TestN098ByteStringSatoshis < Minitest::Test
  HEAD = <<~TS
    import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

    class C extends StatefulSmartContract {
      count: bigint;
      readonly base: bigint;
      readonly blob: ByteString;

      constructor(count: bigint, base: bigint, blob: ByteString) {
        super(count, base, blob);
        this.count = count;
        this.base = base;
        this.blob = blob;
      }

      private sats(): bigint { return this.base; }

  TS

  def self.contract(body)
    "#{HEAD}#{body}}\n"
  end

  # -- REJECT --------------------------------------------------------------

  ADD_OUTPUT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(this.blob, this.count);
      }
  TS

  ADD_RAW_OUTPUT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addRawOutput(this.blob, this.blob);
      }
  TS

  ADD_DATA_OUTPUT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addDataOutput(this.blob, this.blob);
      }
  TS

  # -- ACCEPT (over-rejection guards) --------------------------------------

  LITERAL_SATS = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
      }
  TS

  PARAM_SATS = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(n, this.count);
      }
  TS

  PROPERTY_SATS = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(this.base, this.count);
      }
  TS

  # A private helper's declared return type is discarded at parse time in EVERY
  # tier, so this infers as `<unknown>`. It must stay ACCEPTED.
  HELPER_SATS = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(this.sats(), this.count);
      }
  TS

  # Parse + typecheck a `.runar.ts` source, returning the type-check error
  # strings. A parse failure raises rather than being counted as a rejection --
  # a fixture refused for the wrong reason would make this file vacuous.
  def typecheck_errors(source)
    parse_result = RunarCompiler.send(:_parse_source, source, "C.runar.ts")
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract, "fixture did not parse"

    RunarCompiler.send(:_type_check, parse_result.contract).errors.map(&:format_message)
  end

  # Compile a source end-to-end through the CLI's own path and return the hex.
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

  def test_add_output_rejects_bytestring_satoshis
    assert_diagnostic(
      ADD_OUTPUT,
      "addOutput() first argument (satoshis) must be bigint, got 'ByteString'"
    )
  end

  def test_add_raw_output_rejects_bytestring_satoshis
    assert_diagnostic(
      ADD_RAW_OUTPUT,
      "addRawOutput() first argument (satoshis) must be bigint, got 'ByteString'"
    )
  end

  def test_add_data_output_rejects_bytestring_satoshis
    assert_diagnostic(
      ADD_DATA_OUTPUT,
      "addDataOutput() first argument (satoshis) must be bigint, got 'ByteString'"
    )
  end

  # -- controls ------------------------------------------------------------

  def test_accepted_satoshis_positions
    {
      "bigint literal" => LITERAL_SATS,
      "bigint method parameter" => PARAM_SATS,
      "bigint contract property" => PROPERTY_SATS,
      "private helper call, inferred as <unknown>" => HELPER_SATS
    }.each do |label, source|
      assert_empty typecheck_errors(source), "#{label} was rejected"
      refute_empty compile_hex(source), "#{label} compiled to an empty script"
    end
  end

  # Non-vacuity: "it compiled" would also hold for a tier that discarded the
  # satoshis operand entirely. A literal and a runtime parameter must lower to
  # DIFFERENT scripts. Every tier's own N-098 test makes this same assertion.
  def test_satoshis_operand_reaches_codegen
    lit = compile_hex(LITERAL_SATS)
    param = compile_hex(PARAM_SATS)
    refute_equal lit, param,
                 "literal and parameter satoshis produced the same script -- the operand is being dropped"
    assert_includes lit, "02e803" # PUSH(2) 0xe8 0x03 == 1000
  end
end
