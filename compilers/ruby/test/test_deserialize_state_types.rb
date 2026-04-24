# frozen_string_literal: true

require_relative "test_helper"

# Pull in frontend + codegen modules.
require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/anf_lower"
require "runar_compiler/frontend/parser_ts"
require "runar_compiler/codegen/stack"

# Tests that `deserialize_state` codegen supports the full set of
# property types the validator allows. Historically the Ruby codegen
# allowlist was narrower than the validator's VALID_PROP_TYPES — valid
# stateful contracts using e.g. Ripemd160 or P256Point as mutable fields
# crashed in codegen with "deserialize_state: unsupported type".
#
# This mirrors the Rust compiler fix in commit e879e58 and extends the
# Ruby codegen to the full 14-type allowlist.
class TestDeserializeStateTypes < Minitest::Test
  # Compile a stateful contract with a single mutable property of the
  # given TS type. Returns the artifact on success, raises on failure.
  def compile_stateful_with_type(ts_type, contract_name)
    source = <<~TS
      import { StatefulSmartContract, #{ts_type} } from 'runar-lang';

      class #{contract_name} extends StatefulSmartContract {
        value: #{ts_type};

        constructor(value: #{ts_type}) {
          super(value);
          this.value = value;
        }

        public update(newValue: #{ts_type}): void {
          this.value = newValue;
        }
      }
    TS

    parse_result = RunarCompiler.send(:_parse_source, source, "#{contract_name}.runar.ts")
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract

    val_result = RunarCompiler::Frontend.validate(parse_result.contract)
    assert_empty val_result.errors.map(&:format_message), "unexpected validation errors"

    tc_result = RunarCompiler::Frontend.type_check(parse_result.contract)
    assert_empty tc_result.errors.map(&:format_message), "unexpected type check errors"

    program = RunarCompiler::Frontend.lower_to_anf(parse_result.contract)
    RunarCompiler.compile_from_program(program, disable_constant_folding: true)
  end

  # ---------------------------------------------------------------------------
  # Fixed-length byte-string subtypes
  # ---------------------------------------------------------------------------

  def test_deserialize_state_ripemd160_codegens_cleanly
    artifact = compile_stateful_with_type("Ripemd160", "TagR160")
    refute_nil artifact
    assert artifact.script.length > 0, "Ripemd160 contract should have non-empty script"
    assert_equal "TagR160", artifact.contract_name
  end

  def test_deserialize_state_p256point_codegens_cleanly
    artifact = compile_stateful_with_type("P256Point", "TagP256")
    refute_nil artifact
    assert artifact.script.length > 0, "P256Point contract should have non-empty script"
    assert_equal "TagP256", artifact.contract_name
  end

  def test_deserialize_state_p384point_codegens_cleanly
    artifact = compile_stateful_with_type("P384Point", "TagP384")
    refute_nil artifact
    assert artifact.script.length > 0, "P384Point contract should have non-empty script"
    assert_equal "TagP384", artifact.contract_name
  end

  # ---------------------------------------------------------------------------
  # Numeric (bigint-aliased) subtypes — same 8-byte layout as bigint,
  # must emit OP_BIN2NUM after OP_SPLIT like bigint/boolean.
  # ---------------------------------------------------------------------------

  def test_deserialize_state_rabin_sig_codegens_cleanly
    artifact = compile_stateful_with_type("RabinSig", "TagRSig")
    refute_nil artifact
    assert artifact.script.length > 0, "RabinSig contract should have non-empty script"
    assert_equal "TagRSig", artifact.contract_name
  end

  def test_deserialize_state_rabin_pubkey_codegens_cleanly
    artifact = compile_stateful_with_type("RabinPubKey", "TagRPk")
    refute_nil artifact
    assert artifact.script.length > 0, "RabinPubKey contract should have non-empty script"
    assert_equal "TagRPk", artifact.contract_name
  end

  # ---------------------------------------------------------------------------
  # Variable-length byte-string subtypes — must use push-data-decode path,
  # not a fixed OP_SPLIT.
  # ---------------------------------------------------------------------------

  def test_deserialize_state_sig_codegens_cleanly
    artifact = compile_stateful_with_type("Sig", "TagSig")
    refute_nil artifact
    assert artifact.script.length > 0, "Sig contract should have non-empty script"
    assert_equal "TagSig", artifact.contract_name
  end

  def test_deserialize_state_sighash_preimage_codegens_cleanly
    artifact = compile_stateful_with_type("SigHashPreimage", "TagShp")
    refute_nil artifact
    assert artifact.script.length > 0, "SigHashPreimage contract should have non-empty script"
    assert_equal "TagShp", artifact.contract_name
  end
end
