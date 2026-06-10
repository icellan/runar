# frozen_string_literal: true

# Tests for arbitrary-precision BigIntLiteral widening.
#
# Verifies the secp256k1 group order (256 bits) survives parse -> ANF -> IR ->
# codegen end-to-end without truncation, and that the cross-tier `"...n"`
# decimal-string discriminator round-trips losslessly.
#
# Background: BUG-001 added an `assert(within(s, 1n, EC_N))` malleability gate
# to the Schnorr ZKP example. Prior to this change Ruby's parsers clamped any
# value above int64 to 0 (a defensive stub mirroring Python's pre-fix
# behaviour), which silently rewrote the bound to OP_0 and broke cross-tier
# byte parity. The conformance fixture's "compilers" allowlist excluded Ruby
# until this widening landed; with this change Ruby produces hex identical
# to the TS / Go / Python references.

require 'open3'
require_relative 'test_helper'
# Frontend and codegen modules are lazy-loaded by compiler.rb; require them
# directly so the unit tests below can exercise _make_load_const_int and
# encode_push_big_int without triggering a full compile.
require 'runar_compiler/frontend/anf_lower'
require 'runar_compiler/codegen/emit'

class TestBigIntLiteralWidening < Minitest::Test
  EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  EC_N_DECIMAL = '115792089237316195423570985008687907852837564279074904382605163141518161494337'

  # 33-byte canonical Bitcoin Script number encoding of EC_N:
  # 32 bytes of the little-endian value plus a trailing 0x00 sign byte
  # (because the MSB has the high bit set in the positive representation).
  EC_N_SCRIPT_NUMBER_HEX = '414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00'

  # 33-byte push: length prefix 0x21 followed by the 33-byte script number.
  EC_N_PUSH_HEX = '21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00'

  def test_decimal_bigint_literal_predicate
    assert RunarCompiler::IR.decimal_bigint_literal?('0n')
    assert RunarCompiler::IR.decimal_bigint_literal?('-1n')
    assert RunarCompiler::IR.decimal_bigint_literal?("#{EC_N}n")
    refute RunarCompiler::IR.decimal_bigint_literal?('n')
    refute RunarCompiler::IR.decimal_bigint_literal?('123')
    refute RunarCompiler::IR.decimal_bigint_literal?('3030')        # hex bytestring lookalike
    refute RunarCompiler::IR.decimal_bigint_literal?('deadbeef')
    refute RunarCompiler::IR.decimal_bigint_literal?('')
    refute RunarCompiler::IR.decimal_bigint_literal?(123)           # not a string
    refute RunarCompiler::IR.decimal_bigint_literal?('12.3n')       # non-digit body
  end

  def test_make_load_const_int_promotes_oversize_to_n_suffix
    v = RunarCompiler::Frontend._make_load_const_int(EC_N)
    parsed = JSON.parse(v.raw_value)
    assert_equal "#{EC_N_DECIMAL}n", parsed
    assert_equal EC_N, v.const_big_int
  end

  def test_make_load_const_int_keeps_int64_as_json_number
    v = RunarCompiler::Frontend._make_load_const_int(42)
    parsed = JSON.parse(v.raw_value)
    assert_equal 42, parsed
    assert_equal 42, v.const_big_int
  end

  def test_make_load_const_int_int64_boundary_stays_numeric
    boundary = RunarCompiler::Frontend::INT64_MAX_LOAD_CONST
    v = RunarCompiler::Frontend._make_load_const_int(boundary)
    parsed = JSON.parse(v.raw_value)
    assert_equal boundary, parsed
  end

  def test_make_load_const_int_just_above_int64_uses_n_suffix
    over = RunarCompiler::Frontend::INT64_MAX_LOAD_CONST + 1
    v = RunarCompiler::Frontend._make_load_const_int(over)
    parsed = JSON.parse(v.raw_value)
    assert_equal "#{over}n", parsed
  end

  def test_decode_const_value_accepts_n_suffix_string
    v = RunarCompiler::IR::ANFValue.new(kind: 'load_const')
    v.raw_value = "#{EC_N_DECIMAL}n"
    RunarCompiler::IR.decode_constants(
      RunarCompiler::IR::ANFProgram.new(
        contract_name: 'C',
        properties: [],
        methods: [
          RunarCompiler::IR::ANFMethod.new(
            name: 'm',
            params: [],
            body: [RunarCompiler::IR::ANFBinding.new(name: 't0', value: v)],
            is_public: true,
          ),
        ],
      ),
    )
    assert_equal EC_N, v.const_big_int
    assert_nil v.const_string
  end

  def test_decode_const_value_keeps_hex_bytestring
    v = RunarCompiler::IR::ANFValue.new(kind: 'load_const')
    v.raw_value = 'deadbeef' # no `n` suffix => hex bytestring
    RunarCompiler::IR.decode_constants(
      RunarCompiler::IR::ANFProgram.new(
        contract_name: 'C',
        properties: [],
        methods: [
          RunarCompiler::IR::ANFMethod.new(
            name: 'm',
            params: [],
            body: [RunarCompiler::IR::ANFBinding.new(name: 't0', value: v)],
            is_public: true,
          ),
        ],
      ),
    )
    assert_equal 'deadbeef', v.const_string
    assert_nil v.const_big_int
  end

  def test_encode_push_big_int_emits_canonical_ec_n_bytes
    hex_str, = RunarCompiler::Codegen.encode_push_big_int(EC_N)
    assert_equal EC_N_PUSH_HEX, hex_str
  end

  def test_encode_script_number_emits_33_bytes_for_ec_n
    bytes = RunarCompiler::Codegen.encode_script_number(EC_N)
    assert_equal 33, bytes.bytesize
    assert_equal EC_N_SCRIPT_NUMBER_HEX, bytes.unpack1('H*')
  end

  RUBY_CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)

  def test_schnorr_zkp_ts_source_matches_reference_hex
    # End-to-end: compile the canonical TS schnorr-zkp source with Ruby and
    # verify byte-identity against the conformance reference hex (produced by
    # TS / Go / Python). This is the gate that lets Ruby drop out of the
    # `"compilers": ["ts", "go", "python"]` allowlist on schnorr-zkp.
    # Subprocess invocation mirrors conformance_goldens_test.rb to avoid the
    # Ruby/TS parser constant-namespace collision flagged there.
    ts_source_path = ConformanceFixture.resolve('schnorr-zkp', '.runar.ts')
    expected_hex = File.read(
      File.join(ConformanceFixture::CONFORMANCE_DIR, 'schnorr-zkp', 'expected-script.hex'),
    ).chomp
    stdout, stderr, status = Open3.capture3(
      RUBY_CLI,
      '--source', ts_source_path,
      '--hex',
      '--disable-constant-folding',
    )
    assert status.success?, "compile failed: #{stderr}"
    assert_equal expected_hex, stdout.chomp
  end
end
