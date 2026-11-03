# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/anf_lower"
require "runar_compiler/frontend/parser_ts"

# constructor_args shape validation -- `_apply_constructor_args` must reject
# inputs that would silently bake nothing and emit placeholder scripts that
# fail opaquely at runtime:
#
#  (a) positional arrays (natural guess, but keys match no property names)
#  (b) keys that don't match any contract property (typos)
#  (c) referenced readonly properties left unbaked after applying the args
class TestConstructorArgsValidation < Minitest::Test
  HASH_LOCK_SOURCE = <<~TS
    class HashLock extends SmartContract {
      readonly hashValue: Sha256;

      constructor(hashValue: Sha256) {
        super(hashValue);
        this.hashValue = hashValue;
      }

      public unlock(preimage: ByteString) {
        assert(sha256(preimage) === this.hashValue);
      }
    }
  TS

  TWO_PROP_SOURCE = <<~TS
    class TwoProp extends SmartContract {
      readonly target: bigint;
      readonly unused: bigint;

      constructor(target: bigint, unused: bigint) {
        super(target, unused);
        this.target = target;
        this.unused = unused;
      }

      public check(x: bigint) {
        assert(x === this.target);
      }
    }
  TS

  HASH = "aa" * 32

  def build_program(source, file_name = "Test.runar.ts")
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract
    RunarCompiler::Frontend.lower_to_anf(parse_result.contract)
  end

  # Apply args (raises on invalid) then compile.
  def compile_with_args(source, args, file_name = "Test.runar.ts")
    program = build_program(source, file_name)
    RunarCompiler.send(:_apply_constructor_args, program, args)
    RunarCompiler.compile_from_program(program, disable_constant_folding: true)
  end

  def apply_args(source, args, file_name = "Test.runar.ts")
    program = build_program(source, file_name)
    RunarCompiler.send(:_apply_constructor_args, program, args)
  end

  def test_rejects_a_positional_array
    # Positional array -- the shape RunarContract takes, but NOT what the
    # compiler baking path takes. Previously baked nothing silently.
    err = assert_raises(RunarCompiler::CompilationError) do
      apply_args(HASH_LOCK_SOURCE, [HASH], "HashLock.runar.ts")
    end
    assert_match(/positional array/i, err.message)
  end

  def test_rejects_keys_that_match_no_contract_property
    err = assert_raises(RunarCompiler::CompilationError) do
      apply_args(HASH_LOCK_SOURCE, { "hashVal" => HASH }, "HashLock.runar.ts") # typo: hashValue
    end
    assert_includes err.message, "'hashVal'"
    assert_includes err.message, "hashValue"
  end

  def test_rejects_when_a_referenced_readonly_property_remains_unbaked
    # 'target' is referenced by check() but not provided.
    err = assert_raises(RunarCompiler::CompilationError) do
      apply_args(TWO_PROP_SOURCE, { "unused" => 1 }, "TwoProp.runar.ts")
    end
    assert_match(/'target'/, err.message)
    assert_match(/placeholder/, err.message)
  end

  def test_accepts_an_unreferenced_readonly_property_left_unbaked
    # 'unused' is never referenced by a method -- DCE eliminates it, so
    # leaving it unbaked is fine.
    artifact = compile_with_args(TWO_PROP_SOURCE, { "target" => 42 }, "TwoProp.runar.ts")
    refute_nil artifact.script
    refute_empty artifact.script
  end

  def test_accepts_a_complete_named_record
    artifact = compile_with_args(HASH_LOCK_SOURCE, { "hashValue" => HASH }, "HashLock.runar.ts")
    assert_includes artifact.script, HASH
    slots = artifact.constructor_slots
    assert(slots.nil? || slots.empty?, "expected no constructor slots for a fully baked record")
  end

  def test_still_compiles_placeholder_artifacts_when_no_args_given
    program = build_program(HASH_LOCK_SOURCE, "HashLock.runar.ts")
    RunarCompiler.send(:_apply_constructor_args, program, nil)
    artifact = RunarCompiler.compile_from_program(program, disable_constant_folding: true)
    assert_operator artifact.constructor_slots.length, :>=, 1
  end

  def test_empty_record_is_the_unchecked_placeholder_path
    # An empty record bakes nothing and must not trip the referenced-readonly
    # check (byte-identical to the no-args placeholder path).
    program = build_program(HASH_LOCK_SOURCE, "HashLock.runar.ts")
    RunarCompiler.send(:_apply_constructor_args, program, {})
    artifact = RunarCompiler.compile_from_program(program, disable_constant_folding: true)
    assert_operator artifact.constructor_slots.length, :>=, 1
  end

  # F-101 -- (d) value kind / byte-width check.
  #
  # Before the fix `_apply_constructor_args` baked any value into the property:
  # `true` against a 20-byte hash pushed OP_1, `42` a 1-byte number, a 6-byte
  # hex string a 6-byte push -- every one compiled and is unspendable. Proves:
  # each mismatch is refused with the TypeScript reference's diagnostic, naming
  # the property, its declared type and the expected shape. Does NOT prove
  # anything about the SDK's deploy-time constructorSlots path.
  def f101_p2pkh(type)
    <<~TS
      class P2PKH extends SmartContract {
        readonly pubKeyHash: #{type};
        constructor(pubKeyHash: #{type}) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
        public unlock(sig: Sig, pubKey: PubKey) {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS
  end

  F101_FLAGGED = <<~TS
    class Flagged extends SmartContract {
      readonly target: bigint;
      readonly on: boolean;
      constructor(target: bigint, on: boolean) { super(target, on); this.target = target; this.on = on; }
      public check(x: bigint) { assert(this.on); assert(x === this.target); }
    }
  TS

  def test_f101_rejects_a_value_that_does_not_match_the_property_type
    [
      ["ByteString", true, "must be a hex string, got a boolean"],
      ["Addr", true, "must be exactly 20 bytes of hex, got a boolean"],
      ["Addr", 42, "must be exactly 20 bytes of hex, got an integer"],
      ["Addr", "aabbccddeeff", "must be exactly 20 bytes of hex, got 6 bytes of hex"],
      ["Addr", "zzzz-not-hex", "must be exactly 20 bytes of hex, got a non-hex string"],
      ["ByteString", "abc", "must be a hex string, got a non-hex string"],
      ["ByteString", 1.5, "must be a hex string, got an unsupported value"],
    ].each do |type, value, want|
      err = assert_raises(RunarCompiler::CompilationError, "#{type} <- #{value.inspect}") do
        compile_with_args(f101_p2pkh(type), { "pubKeyHash" => value }, "P2PKH.runar.ts")
      end
      assert_includes err.message, "property 'pubKeyHash' (#{type})"
      assert_includes err.message, want
    end
  end

  def test_f101_rejects_bigint_and_boolean_mismatches
    err = assert_raises(RunarCompiler::CompilationError) do
      compile_with_args(F101_FLAGGED, { "target" => "2a", "on" => 1 }, "Flagged.runar.ts")
    end
    assert_includes err.message, "property 'target' (bigint) must be an integer, got 1 bytes of hex"
    assert_includes err.message, "property 'on' (boolean) must be a boolean, got an integer"
  end

  def test_f101_accepts_correctly_typed_values
    artifact = compile_with_args(f101_p2pkh("Addr"), { "pubKeyHash" => "AB" * 20 }, "P2PKH.runar.ts")
    assert_includes artifact.script.downcase, "ab" * 20
    compile_with_args(f101_p2pkh("ByteString"), { "pubKeyHash" => "" }, "P2PKH.runar.ts")
    compile_with_args(F101_FLAGGED, { "target" => 42, "on" => true }, "Flagged.runar.ts")
  end
end
