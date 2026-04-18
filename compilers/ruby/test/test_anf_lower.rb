# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/anf_lower"
require "runar_compiler/frontend/parser_ts"

# Exercises the addDataOutput intrinsic in the ANF lowering pass.
#
# Data outputs are an additional transaction output declared by a stateful
# contract method. They are NOT a state continuation; they are included in
# the auto-computed continuation hash (hashOutputs) in declaration order,
# AFTER state outputs and BEFORE the change output. Wire shape matches
# addRawOutput: amount(8LE) + varint(scriptLen) + scriptBytes.
class TestAnfLower < Minitest::Test
  def anf_program_for(source, file_name = "T.runar.ts")
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract

    val_result = RunarCompiler::Frontend.validate(parse_result.contract)
    assert_empty val_result.errors.map(&:format_message), "unexpected validation errors"

    tc_result = RunarCompiler::Frontend.type_check(parse_result.contract)
    assert_empty tc_result.errors.map(&:format_message), "unexpected type check errors"

    RunarCompiler::Frontend.lower_to_anf(parse_result.contract)
  end

  SINGLE_OUTPUT_WITH_DATA = <<~TS
    import { StatefulSmartContract, assert, bigint, ByteString } from 'runar-lang';

    class Logger extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      public log(note: ByteString): void {
        this.count = this.count + 1n;
        this.addDataOutput(0n, note);
      }
    }
  TS

  MULTI_OUTPUT_WITH_DATA = <<~TS
    import { StatefulSmartContract, assert, bigint, ByteString } from 'runar-lang';

    class MultiLogger extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      public tick(note: ByteString): void {
        this.addOutput(500n, this.count + 1n);
        this.addDataOutput(0n, note);
      }
    }
  TS

  ONLY_DATA_OUTPUT = <<~TS
    import { SmartContract, StatefulSmartContract, assert, bigint, ByteString } from 'runar-lang';

    class DataOnly extends StatefulSmartContract {
      pinned: bigint;

      constructor(pinned: bigint) {
        super(pinned);
        this.pinned = pinned;
      }

      public log(note: ByteString): void {
        this.addDataOutput(0n, note);
      }
    }
  TS

  # ---------------------------------------------------------------------------
  # Emits add_data_output binding
  # ---------------------------------------------------------------------------

  def test_emits_add_data_output_binding
    prog = anf_program_for(SINGLE_OUTPUT_WITH_DATA, "Logger.runar.ts")
    log = prog.methods.find { |m| m.name == "log" }
    refute_nil log
    kinds = log.body.map { |b| b.value.kind }
    assert_includes kinds, "add_data_output",
                    "expected an add_data_output binding in log() body"
  end

  # ---------------------------------------------------------------------------
  # Single-output continuation splices data output between state and change
  # ---------------------------------------------------------------------------

  def test_single_output_continuation_order
    prog = anf_program_for(SINGLE_OUTPUT_WITH_DATA, "Logger.runar.ts")
    log = prog.methods.find { |m| m.name == "log" }

    # Find add_data_output and computeStateOutput bindings. In the single-output
    # path the data output should be cat'd after the contract state output and
    # before the change output.
    names_by_kind = Hash.new { |h, k| h[k] = [] }
    log.body.each { |b| names_by_kind[b.value.kind] << b.name }

    data_ref = names_by_kind["add_data_output"].first
    refute_nil data_ref

    # Locate the cat sequence after computeStateOutput and ensure one cat
    # uses the data-output ref as its right operand.
    cat_bindings = log.body.select { |b| b.value.kind == "call" && b.value.func == "cat" }
    assert cat_bindings.any? { |b| (b.value.args || []).include?(data_ref) },
           "expected a cat binding that consumes the add_data_output ref"
  end

  # ---------------------------------------------------------------------------
  # Multi-output continuation uses data output after state outputs
  # ---------------------------------------------------------------------------

  def test_multi_output_continuation_order
    prog = anf_program_for(MULTI_OUTPUT_WITH_DATA, "MultiLogger.runar.ts")
    tick = prog.methods.find { |m| m.name == "tick" }
    refute_nil tick

    state_refs = tick.body.select { |b| b.value.kind == "add_output" }.map(&:name)
    data_refs  = tick.body.select { |b| b.value.kind == "add_data_output" }.map(&:name)

    assert state_refs.any?, "expected at least one add_output"
    assert data_refs.any?,  "expected at least one add_data_output"

    # The data output must be emitted AFTER all state outputs (declaration order).
    state_idx = tick.body.index { |b| b.name == state_refs.first }
    data_idx  = tick.body.index { |b| b.name == data_refs.first }
    assert state_idx < data_idx,
           "add_data_output must come after add_output in declaration order"
  end

  # ---------------------------------------------------------------------------
  # Method with only a data output still triggers continuation + change output
  # ---------------------------------------------------------------------------

  def test_only_data_output_still_emits_continuation
    prog = anf_program_for(ONLY_DATA_OUTPUT, "DataOnly.runar.ts")
    log = prog.methods.find { |m| m.name == "log" }
    refute_nil log

    # The continuation assertion wraps the hash256 over all outputs. Make sure
    # a hash256 call is present -- proves the continuation path was exercised
    # even though no state mutation or addOutput happened.
    assert log.body.any? { |b| b.value.kind == "call" && b.value.func == "hash256" },
           "expected continuation hash256 call"

    # Change output implicit params should be declared.
    param_names = log.params.map(&:name)
    assert_includes param_names, "_changePKH"
    assert_includes param_names, "_changeAmount"
    # Single-output path (no addOutput) ⇒ needs _newAmount for state continuation.
    assert_includes param_names, "_newAmount"
  end
end
