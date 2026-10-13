# frozen_string_literal: true

# N-208: --ir refuses a wrong-typed optional field instead of silently
# treating it as absent.
#
# Before this fix, three optional ANF-value fields were read with a bare
# +d[key]+ (or a +== true+ comparison) and NO type check:
#
#   - +bin_op.result_type+: any value other than the string "bytes"
#     (including a non-string) makes stack lowering's +result_type ==
#     "bytes"+ comparison false, so a mistyped hint silently lowers a
#     byte-equality comparison as a numeric one -- a different script with
#     no diagnostic.
#   - +assert.isAutoInjectedStateCheck+: +d["isAutoInjectedStateCheck"] ==
#     true+ is false for every non-true value, including the STRING "true",
#     so a wrong-typed marker silently becomes +false+ with no diagnostic.
#     Off-chain SDK interpreters key off this exact marker to skip the
#     compiler-injected stateful-continuation assert.
#   - +add_output.preimage+: a wrong-typed value was still handed to
#     ref-collection; a non-string ref can never match a real binding name,
#     silently breaking the liveness bookkeeping the ref list exists for.
#
# Go, Rust, Zig and TS already refuse all three (their typed decoders reject
# a JSON value of the wrong shape); this closes the same gap in this tier's
# --ir loader.
#
# Proves: each field, given a value of the wrong JSON type, is refused by
# +load_ir+ / +RequiredFields.assert!+ with the same
# "IR validation: <path> must be <type>, got <type>" diagnostic the N-069 /
# F-038 checks in this same module already use -- and that a correctly-typed
# or absent value is still accepted.
# Does not prove: Python or Java (their own suites prove the same fields), or
# that these are the only three fields this gap applied to (N-069 / F-038 /
# N-059 already closed it for +parentClass+, +sigHashType+ and
# +sighashFlag+ elsewhere in this file).

require_relative "test_helper"
require "json"
require "runar_compiler/ir/loader"
require "runar_compiler/ir/required_fields"

class TestN208IROptionalFieldTypes < Minitest::Test
  def program(body)
    {
      "contractName" => "X",
      "properties" => [],
      "methods" => [{
        "name" => "run",
        "isPublic" => true,
        "params" => [],
        "body" => body,
      }],
    }
  end

  # -- bin_op.result_type ----------------------------------------------------

  def test_bin_op_result_type_valid_string_loads
    body = [
      { "name" => "t0", "value" => { "kind" => "load_const", "value" => 1 } },
      { "name" => "t1", "value" => { "kind" => "load_const", "value" => 1 } },
      { "name" => "t2", "value" => {
        "kind" => "bin_op", "op" => "===", "left" => "t0", "right" => "t1",
        "result_type" => "bytes",
      } },
      { "name" => "t3", "value" => { "kind" => "assert", "value" => "t2" } },
    ]
    p = RunarCompiler::IR.load_ir(JSON.generate(program(body)))
    assert_equal "bytes", p.methods[0].body[2].value.result_type
  end

  def test_bin_op_result_type_absent_loads
    body = [
      { "name" => "t0", "value" => { "kind" => "load_const", "value" => 1 } },
      { "name" => "t1", "value" => { "kind" => "load_const", "value" => 1 } },
      { "name" => "t2", "value" => { "kind" => "bin_op", "op" => "===", "left" => "t0", "right" => "t1" } },
      { "name" => "t3", "value" => { "kind" => "assert", "value" => "t2" } },
    ]
    p = RunarCompiler::IR.load_ir(JSON.generate(program(body)))
    assert_nil p.methods[0].body[2].value.result_type
  end

  def test_bin_op_result_type_wrong_type_refused
    body = [
      { "name" => "t0", "value" => { "kind" => "load_const", "value" => 1 } },
      { "name" => "t1", "value" => { "kind" => "load_const", "value" => 1 } },
      { "name" => "t2", "value" => {
        "kind" => "bin_op", "op" => "===", "left" => "t0", "right" => "t1",
        "result_type" => 1,
      } },
      { "name" => "t3", "value" => { "kind" => "assert", "value" => "t2" } },
    ]
    err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(JSON.generate(program(body))) }
    assert_equal(
      "IR validation: methods[0].body[2].value.result_type must be a string, got number",
      err.message
    )
  end

  # -- assert.isAutoInjectedStateCheck ----------------------------------------

  def test_assert_is_auto_injected_state_check_valid_bool_loads
    body = [
      { "name" => "t0", "value" => { "kind" => "load_const", "value" => true } },
      { "name" => "t1", "value" => {
        "kind" => "assert", "value" => "t0", "isAutoInjectedStateCheck" => true,
      } },
    ]
    p = RunarCompiler::IR.load_ir(JSON.generate(program(body)))
    assert_equal true, p.methods[0].body[1].value.is_auto_injected_state_check
  end

  def test_assert_is_auto_injected_state_check_absent_defaults_false
    body = [
      { "name" => "t0", "value" => { "kind" => "load_const", "value" => true } },
      { "name" => "t1", "value" => { "kind" => "assert", "value" => "t0" } },
    ]
    p = RunarCompiler::IR.load_ir(JSON.generate(program(body)))
    assert_equal false, p.methods[0].body[1].value.is_auto_injected_state_check
  end

  def test_assert_is_auto_injected_state_check_wrong_type_refused
    body = [
      { "name" => "t0", "value" => { "kind" => "load_const", "value" => true } },
      { "name" => "t1", "value" => {
        "kind" => "assert", "value" => "t0", "isAutoInjectedStateCheck" => "true",
      } },
    ]
    err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(JSON.generate(program(body))) }
    assert_equal(
      "IR validation: methods[0].body[1].value.isAutoInjectedStateCheck must be a boolean, got string",
      err.message
    )
  end

  # -- add_output.preimage -----------------------------------------------------
  #
  # add_output is a STATEFUL-only node: a full load_ir() through a minimal
  # body would also have to satisfy N-101's re-derived StatefulSmartContract
  # scaffolding, which is unrelated to this fix. The type check lives in
  # RequiredFields.assert!, which runs BEFORE validate_ir / the scaffold
  # check, so it is exercised directly here instead -- the same method
  # load_ir calls first.

  def test_add_output_preimage_valid_string_accepted
    ir = program([
      { "name" => "t0", "value" => { "kind" => "load_const", "value" => 1 } },
      { "name" => "t1", "value" => {
        "kind" => "add_output", "satoshis" => "t0", "stateValues" => [], "preimage" => "",
      } },
    ])
    RunarCompiler::IR::RequiredFields.assert!(ir) # does not raise
  end

  def test_add_output_preimage_absent_accepted
    ir = program([
      { "name" => "t0", "value" => { "kind" => "load_const", "value" => 1 } },
      { "name" => "t1", "value" => {
        "kind" => "add_output", "satoshis" => "t0", "stateValues" => [],
      } },
    ])
    RunarCompiler::IR::RequiredFields.assert!(ir) # does not raise -- defaulted for older payloads
  end

  def test_add_output_preimage_wrong_type_refused
    ir = program([
      { "name" => "t0", "value" => { "kind" => "load_const", "value" => 1 } },
      { "name" => "t1", "value" => {
        "kind" => "add_output", "satoshis" => "t0", "stateValues" => [], "preimage" => 123,
      } },
    ])
    err = assert_raises(ArgumentError) { RunarCompiler::IR::RequiredFields.assert!(ir) }
    assert_equal(
      "IR validation: methods[0].body[1].value.preimage must be a string, got number",
      err.message
    )
  end
end
