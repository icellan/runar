# frozen_string_literal: true

require_relative "../test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/parser_ts"

# Port of the TypeScript reference test
# `packages/runar-compiler/src/__tests__/n105-scriptbytes.test.ts`.
#
# N-105 (1/2) -- a NUMBER in the scriptBytes position of addRawOutput /
# addDataOutput.
#
# Same shape as N-098, one argument slot over, and the slot is the created
# output's LOCKING SCRIPT.
#
# This tier ACCEPTED `this.addRawOutput(1000n, n)` with `n: bigint`, and the
# emitted script was byte-identical to the same contract written with
# `n: ByteString` -- measured, same digest, in all six accepting tiers. The
# operand is not converted: whatever sits in that slot is spliced into the
# output serialization as the output's script.
#
# `lower_add_raw_output` takes OP_SIZE of the operand, varint-prefixes it and
# concatenates it after the 8-byte amount. A script NUMBER on the stack is its
# minimal little-endian encoding, so the covenant commits to an output whose
# locking script IS those bytes. Executed on the real @bsv/sdk Spend engine
# against the exact 55-opcode window all six tiers emit:
#
#   n=0     -> scriptLen 0   locking script (empty)     -- anyone-can-spend
#   n=81    -> scriptLen 1   0x51 = OP_1                -- anyone-can-spend
#   n=118   -> scriptLen 1   0x76 = OP_DUP              -- anyone-can-spend
#   n=1000  -> scriptLen 2   0xe8 0x03, 0xe8 invalid    -- unspendable
#
# N-098's failure mode was a wrong amount or a frozen UTXO. This one can hand
# the whole output to anybody who sees it, which is why it is a gate.
#
# Ported from the TypeScript reference, wording included. `<unknown>` stays
# ACCEPTED exactly as TS has it -- a private helper's declared return type is
# discarded at parse time in every tier.
class TestN105ScriptBytes < Minitest::Test
  HEAD = <<~TS
    import { StatefulSmartContract, ByteString, Ripemd160, assert } from 'runar-lang';

    class C extends StatefulSmartContract {
      count: bigint;
      readonly base: bigint;
      readonly flag: boolean;
      readonly blob: ByteString;
      readonly pkh: Ripemd160;

      constructor(count: bigint, base: bigint, flag: boolean, blob: ByteString, pkh: Ripemd160) {
        super(count, base, flag, blob, pkh);
        this.count = count;
        this.base = base;
        this.flag = flag;
        this.blob = blob;
        this.pkh = pkh;
      }

      private bytes(): ByteString { return this.blob; }

  TS

  def self.contract(body)
    "#{HEAD}#{body}}\n"
  end

  # -- REJECT --------------------------------------------------------------

  RAW_BIGINT_SCRIPT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addRawOutput(500n, this.base);
      }
  TS

  DATA_BIGINT_SCRIPT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addDataOutput(500n, this.base);
      }
  TS

  RAW_BOOLEAN_SCRIPT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addRawOutput(500n, this.flag);
      }
  TS

  # -- ACCEPT (over-rejection guards) --------------------------------------

  RAW_BYTESTRING_SCRIPT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addRawOutput(500n, this.blob);
      }
  TS

  RAW_STATE_SCRIPT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addRawOutput(500n, this.getStateScript());
      }
  TS

  # A ByteString SUBTYPE. TS's rule is `subtype?(script_type, "ByteString")`,
  # not equality, so Ripemd160 must keep compiling.
  RAW_SUBTYPE_SCRIPT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addRawOutput(500n, this.pkh);
      }
  TS

  # A private helper's declared return type is discarded at parse time in every
  # tier, so this infers as `<unknown>`. TS escapes it; every port must too.
  RAW_HELPER_SCRIPT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addRawOutput(500n, this.bytes());
      }
  TS

  DATA_BYTESTRING_SCRIPT = contract(<<~TS)
      public m(n: bigint) {
        assert(n > 0n);
        this.count = this.count + n;
        this.addOutput(1000n, this.count);
        this.addDataOutput(500n, this.blob);
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

  # -- the defect ----------------------------------------------------------

  def test_add_raw_output_rejects_bigint_script_bytes
    assert_diagnostic(
      RAW_BIGINT_SCRIPT,
      "addRawOutput() second argument (scriptBytes) must be ByteString, got 'bigint'"
    )
  end

  def test_add_data_output_rejects_bigint_script_bytes
    assert_diagnostic(
      DATA_BIGINT_SCRIPT,
      "addDataOutput() second argument (scriptBytes) must be ByteString, got 'bigint'"
    )
  end

  def test_add_raw_output_rejects_boolean_script_bytes
    assert_diagnostic(
      RAW_BOOLEAN_SCRIPT,
      "addRawOutput() second argument (scriptBytes) must be ByteString, got 'boolean'"
    )
  end

  # -- controls ------------------------------------------------------------

  def test_accepted_script_bytes_positions
    {
      "ByteString property" => RAW_BYTESTRING_SCRIPT,
      "getStateScript()" => RAW_STATE_SCRIPT,
      "ByteString subtype (Ripemd160)" => RAW_SUBTYPE_SCRIPT,
      "private helper call, inferred as <unknown>" => RAW_HELPER_SCRIPT,
      "addDataOutput with a ByteString property" => DATA_BYTESTRING_SCRIPT
    }.each do |label, source|
      assert_empty typecheck_errors(source), "#{label} was rejected"
      refute_empty compile_hex(source), "#{label} compiled to an empty script"
    end
  end

  # Non-vacuity: "it compiled" would also hold for a tier that discarded the
  # scriptBytes operand. Two DIFFERENT ByteString operands must lower to
  # different scripts.
  def test_script_bytes_operand_reaches_codegen
    a = compile_hex(RAW_BYTESTRING_SCRIPT)
    b = compile_hex(RAW_STATE_SCRIPT)
    refute_equal a, b,
                 "two different scriptBytes operands produced the same script -- the operand is being dropped"
  end
end
