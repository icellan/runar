# frozen_string_literal: true

require_relative 'codegen_helper'
require 'json'
require 'digest'
require 'runar_compiler/codegen/emit'
require 'runar_compiler/codegen/ec'
require 'runar_compiler/codegen/p256_p384'

# Cross-tier parity for the EXPERIMENTAL EC size flags.
#
# The flags default off, so the ordinary conformance suite -- which compiles
# with defaults -- cannot see them at all. Seven tiers could each ship a
# DIFFERENT --ec-constant-pool and the suite would stay green.
#
# That matters because the flags are not cosmetic: they change which reduction
# form is emitted and which addition formula each ladder round uses. A tier that
# ports the constant pool but not the sign lattice's REDUCED precondition
# produces a script that is smaller, passes its own tests, and is wrong on
# ecAdd((0,1), (2^256-1,1)). Byte-identical output against a single reference is
# the only cheap check that catches that.
#
# conformance/ec-flag-parity/expected.json is derived from the TypeScript
# reference compiler and re-derived by its own vitest, so it cannot go stale.
class TestEcFlagParity < Minitest::Test
  C = RunarCompiler::Codegen

  FIXTURE_PATH = File.expand_path(
    '../../../../conformance/ec-flag-parity/expected.json', __dir__
  )

  FIELD_MAP = {
    'constantPool' => :constant_pool,
    'reductionSinking' => :reduction_sinking,
    'fixedBaseComb' => :fixed_base_comb
  }.freeze

  # Adapt an emitter the flags cannot reach to the options-taking shape. These
  # are deliberately included: a tier that accidentally made ecModReduce or
  # ecPointX flag-sensitive would be diverging just as badly as one that ignored
  # a flag.
  IGNORE_OPTS = ->(f) { ->(e, _o = nil) { f.call(e) } }

  def emitters
    {
      'EcAdd' => C::EC.method(:emit_ec_add),
      'EcMul' => C::EC.method(:emit_ec_mul),
      'EcMulGen' => C::EC.method(:emit_ec_mul_gen),
      'EcNegate' => C::EC.method(:emit_ec_negate),
      'EcOnCurve' => C::EC.method(:emit_ec_on_curve),
      'EcModReduce' => IGNORE_OPTS.call(C::EC.method(:emit_ec_mod_reduce)),
      'EcEncodeCompressed' => IGNORE_OPTS.call(C::EC.method(:emit_ec_encode_compressed)),
      'EcMakePoint' => IGNORE_OPTS.call(C::EC.method(:emit_ec_make_point)),
      'EcPointX' => IGNORE_OPTS.call(C::EC.method(:emit_ec_point_x)),
      'EcPointY' => IGNORE_OPTS.call(C::EC.method(:emit_ec_point_y)),
      'P256Add' => C::NISTEC.method(:emit_p256_add),
      'P256Mul' => C::NISTEC.method(:emit_p256_mul),
      'P256MulGen' => C::NISTEC.method(:emit_p256_mul_gen),
      'P256Negate' => C::NISTEC.method(:emit_p256_negate),
      'P256OnCurve' => C::NISTEC.method(:emit_p256_on_curve),
      'P256EncodeCompressed' => IGNORE_OPTS.call(C::NISTEC.method(:emit_p256_encode_compressed)),
      'VerifyECDSA_P256' => C::NISTEC.method(:emit_verify_ecdsa_p256),
      'P384Add' => C::NISTEC.method(:emit_p384_add),
      'P384Mul' => C::NISTEC.method(:emit_p384_mul),
      'P384MulGen' => C::NISTEC.method(:emit_p384_mul_gen),
      'P384Negate' => C::NISTEC.method(:emit_p384_negate),
      'P384OnCurve' => C::NISTEC.method(:emit_p384_on_curve),
      'P384EncodeCompressed' => IGNORE_OPTS.call(C::NISTEC.method(:emit_p384_encode_compressed)),
      'VerifyECDSA_P384' => C::NISTEC.method(:emit_verify_ecdsa_p384)
    }
  end

  def fixture
    @fixture ||= JSON.parse(File.read(FIXTURE_PATH))
  end

  def emit_and_hash(fn, opts)
    ops = []
    fn.call(->(o) { ops << o }, opts)
    res = C.emit_method({ name: 't', ops: ops })
    raw = [res[:script_hex]].pack('H*')
    [raw.bytesize, Digest::SHA256.hexdigest(raw)]
  end

  def test_ec_flag_parity_against_typescript_reference
    emitters.each do |name, fn|
      want = fixture['emitters'][name]
      refute_nil want, "#{name}: no entry in the parity fixture"
      fixture['variants'].each do |variant, spec|
        opts = if spec.empty?
                 nil
               else
                 C::EC::EcCodegenOptions.new(**spec.to_h { |k, v| [FIELD_MAP[k], v] })
               end
        got = emit_and_hash(fn, opts)
        expect = [want[variant]['bytes'], want[variant]['sha256']]
        assert_equal expect, got,
                     "#{name} under #{variant}: Ruby and the TypeScript reference disagree"
      end
    end
  end

  # nil options must reproduce the shipping output. This is what keeps the
  # existing goldens, the size baseline and every cross-tier hex comparison from
  # moving while the flags are experimental.
  def test_ec_flags_default_off_is_byte_identical
    emitters.each do |name, fn|
      none = emit_and_hash(fn, nil)
      off = emit_and_hash(fn, C::EC::EcCodegenOptions.new)
      assert_equal none, off, "#{name}: nil and all-false options disagree"
      assert_equal fixture['emitters'][name]['off']['sha256'], none[1],
                   "#{name}: default output moved"
    end
  end
end
