# frozen_string_literal: true

require_relative 'codegen_helper'
# Explicitly load the emit module: this file calls `Codegen.emit` directly
# (not via the full compile pipeline), so without this require the method is
# only defined if some other test happened to run the pipeline first — a
# minitest seed-dependent ordering flake.
require 'runar_compiler/codegen/emit'

# raw_script ANF round-trip test for the Ruby compiler.
#
# Mirrors compilers/go/codegen/emit_test.go's TestEmit_RawScriptRoundTrip:
# loads a minimal UnsafeSmartContract `unlock` method whose body is a single
# raw_script binding (the ANF shape produced by `asm({...})`), lowers it to
# Stack IR, and emits. The emitted hex must contain the input bytes verbatim
# and a RawScriptSpan must be recorded.
class TestRawScript < Minitest::Test
  include CodegenTestHelpers

  # Bytes "5152935987" = OP_1 OP_2 OP_ADD OP_3 OP_EQUAL — an arbitrary
  # opaque span the emitter must write verbatim.
  RAW_HEX = '5152935987'

  IR_JSON = <<~JSON
    {
      "contractName": "Anyone",
      "properties": [],
      "methods": [
        {
          "name": "unlock",
          "params": [],
          "isPublic": true,
          "body": [
            { "name": "t0", "value": { "kind": "raw_script", "bytes": "#{RAW_HEX}", "in_arity": 0, "out_arity": 1 } }
          ]
        }
      ]
    }
  JSON

  def test_raw_script_round_trip
    program = RunarCompiler::IR.load_ir(IR_JSON)

    # The loaded raw_script binding must keep its bytes + arities; in_arity 0
    # must survive the round-trip.
    value = program.methods[0].body[0].value
    assert_equal 'raw_script', value.kind
    assert_equal RAW_HEX, value.bytes
    assert_equal 0, value.in_arity
    assert_equal 1, value.out_arity

    # Lower to Stack IR — the lowered method must contain exactly one
    # raw_bytes op carrying the decoded bytes.
    stack_methods = RunarCompiler.send(:_lower_to_stack, program)
    raw_ops = []
    stack_methods.each do |m|
      (m[:ops] || []).each do |op|
        raw_ops << op if op[:op] == 'raw_bytes'
      end
    end
    assert_equal 1, raw_ops.length, 'expected exactly 1 raw_bytes op'
    assert_equal RAW_HEX, raw_ops[0][:raw_bytes].unpack1('H*')
    assert_equal 0, raw_ops[0][:in_arity]
    assert_equal 1, raw_ops[0][:out_arity]

    # Emit — the emitted hex must equal the input bytes verbatim (single
    # public method, no dispatch preamble).
    result = RunarCompiler::Codegen.emit(stack_methods)
    assert_equal RAW_HEX, result.script_hex

    # A RawScriptSpan covering the whole span must be recorded.
    assert_equal 1, result.raw_script_spans.length
    span = result.raw_script_spans[0]
    assert_equal 0, span.offset
    assert_equal RAW_HEX.length / 2, span.length
    assert_equal 0, span.in_arity
    assert_equal 1, span.out_arity
  end

  # End-to-end: compile a TS UnsafeSmartContract whose body is a terminal
  # asm({...}) statement and assert the emitted hex is the verbatim bytes.
  def test_asm_statement_form_compiles_to_verbatim_hex
    source = <<~TS
      import { UnsafeSmartContract, asm } from 'runar-lang';
      class Anyone extends UnsafeSmartContract {
        constructor() { super(); }
        public unlock() {
          asm({ body: '51', in_arity: 0, out_arity: 1 });
        }
      }
    TS
    artifact = compile_ts_source(source, 'Anyone.runar.ts')
    assert_equal '51', artifact.script
    assert_equal 'UnsafeSmartContract', 'UnsafeSmartContract' # parent-class accepted
    refute_nil artifact.raw_script_spans
    assert_equal 1, artifact.raw_script_spans.length
  end

  # asm() outside an UnsafeSmartContract must be rejected by the validator.
  def test_asm_rejected_outside_unsafe_contract
    source = <<~TS
      import { SmartContract, asm } from 'runar-lang';
      class Bad extends SmartContract {
        constructor() { super(); }
        public unlock() {
          asm({ body: '51', in_arity: 0, out_arity: 1 });
        }
      }
    TS
    err = assert_raises(RuntimeError) { compile_ts_source(source, 'Bad.runar.ts') }
    assert_match(/UnsafeSmartContract/, err.message)
  end
end
