# frozen_string_literal: true

require_relative 'codegen_helper'
require_relative '../../lib/runar_compiler/codegen/slh_dsa'
require 'digest'

# Unit-vector test for the Ruby SLH-DSA (FIPS 205) codegen module
# (compilers/ruby/lib/runar_compiler/codegen/slh_dsa.rb). SLH-DSA-SHA2-128s
# is the smallest of the 6 parameter sets so it is the cheapest to
# compile in a unit test while still exercising the full WOTS / FORS /
# Merkle authentication-path machinery.

class TestSlhDsaCodegen < Minitest::Test
  include CodegenTestHelpers

  def test_verify_slhdsa_sha2_128s_emits_large_script
    source = <<~TS
      import { SmartContract, assert, verifySLHDSA_SHA2_128s } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class SlhDsaVerifyTest extends SmartContract {
        readonly pubKey: ByteString;

        constructor(pubKey: ByteString) {
          super(pubKey);
          this.pubKey = pubKey;
        }

        public verify(message: ByteString, signature: ByteString) {
          assert(verifySLHDSA_SHA2_128s(message, signature, this.pubKey));
        }
      }
    TS

    artifact = compile_ts_source(source, 'SlhDsaVerifyTest.runar.ts')
    assert_equal 'SlhDsaVerifyTest', artifact.contract_name
    assert artifact.script.length.positive?, 'script must be non-empty'

    # SLH-DSA-SHA2-128s scripts are ~200 KB. Use a generous lower bound
    # so the assertion remains stable across script-shape tweaks.
    script_bytes = artifact.script.length / 2
    assert_operator script_bytes, :>, 50_000,
                    "verifySLHDSA_SHA2_128s should produce a multi-tens-of-KB script (got #{script_bytes} bytes)"

    # SLH-DSA verification is dominated by SHA-256 calls (Merkle trees,
    # FORS leaves, WOTS chains, message hash).
    assert_includes artifact.asm, 'OP_SHA256'
  end

  # F-034: parameter table vs FIPS 205 Table 2. SHA2_256f shipped FORS height
  # a=8 (48,736-byte signature) in all 7 tiers; FIPS 205 says a=9 (49,856
  # bytes), so the compiled verifier rejected every honest 256f signature at
  # its OP_SIZE gate. Proves the table and the emitted exact-length gate; does
  # NOT prove a real signature verifies (that is the real-crypto witness
  # conformance/witnesses/real-crypto/post-quantum-slhdsa-256f.json).
  FIPS205_TABLE2 = {
    'SHA2_128s' => [[16, 63, 7, 9, 12, 14], 7856],
    'SHA2_128f' => [[16, 66, 22, 3, 6, 33], 17_088],
    'SHA2_192s' => [[24, 63, 7, 9, 14, 17], 16_224],
    'SHA2_192f' => [[24, 66, 22, 3, 8, 33], 35_664],
    'SHA2_256s' => [[32, 64, 8, 8, 14, 22], 29_792],
    'SHA2_256f' => [[32, 68, 17, 4, 9, 35], 49_856]
  }.freeze

  def test_params_match_fips205_table2
    FIPS205_TABLE2.each do |key, (dims, sig_len)|
      p = RunarCompiler::Codegen::SLHDSA::SLH_PARAMS.fetch(key)
      assert_equal dims, [p.n, p.h, p.d, p.hp, p.a, p.k], "#{key} (n,h,d,h',a,k) vs FIPS 205 Table 2"
      ops = []
      RunarCompiler::Codegen::SLHDSA.emit_verify_slh_dsa(->(op) { ops << op }, key)
      i = ops.index { |o| o[:op] == 'opcode' && o[:code] == 'OP_SIZE' }
      refute_nil i, "#{key}: no OP_SIZE gate"
      assert_equal({ op: 'push', value: { kind: 'bigint', big_int: sig_len } }, ops[i + 1],
                   "#{key}: OP_SIZE gate vs FIPS signature size")
    end
  end

  # F-327: five of the six FIPS 205 SHA2 parameter sets had no Ruby codegen
  # golden -- only SHA2_128s (above) compared compiled output against
  # anything. The FIPS205_TABLE2 test above pins the six *input* parameters
  # (n, h, d, h', a, k) but never runs them through the emitter, so a bug
  # confined to the emitter itself (not the parameter table) -- e.g. the
  # real F-034/funds-bug class of defect, a block-ordering or byte-window
  # mistake that only misbehaves for specific (a, digest-length) shapes --
  # was invisible to the Ruby suite for 5 of 6 parameter sets. The scripts
  # are 200 KB-1.5 MB, so each test compares a SHA-256 of the lowercase hex,
  # not the hex itself, against the TS-reference-stamped, cross-tier-pinned
  # conformance golden (conformance/tests/post-quantum-slhdsa-<set>/
  # expected-script.hex, which carries no "compilers" allowlist, so Ruby is
  # already a required, graded tier for every one of these fixtures --
  # this just gives a local failure instead of only a conformance one).
  #
  # Mutation proof (F-327 TDD, not left in the tree): temporarily
  # reinstating the historical swap bug fixed in _emit_slh_hmsg (the final
  # MGF1 block gets CAT'd in as `block || resultAcc` instead of
  # `resultAcc || block` for any digest spanning >1 SHA-256 block) left
  # test_verify_slhdsa_sha2_128s_emits_large_script and
  # test_params_match_fips205_table2 BOTH green (128s's 30-byte digest is
  # single-block, and the table test never compiles anything), while each
  # of the five tests below failed with a SHA-256 mismatch -- all five
  # parameter sets here have a >32-byte Hmsg digest (34/39/42/47/49 bytes
  # respectively), so all five exercise the multi-block CAT path the
  # mutation corrupts.
  SLH_GOLDEN_SHA256 = {
    'SHA2_128f' => '85967033e86155bcb7c172eb22773e0411ada44e4e7a358e220be2a2a782f070',
    'SHA2_192s' => 'e33a62fd0e330909bb843fc42d95bbe784a102bf26f7874880eb74b5094ed35a',
    'SHA2_192f' => '0193e75bc98aac84b87562a9e7402aba6dc2360cfad64c16ef669e8e14e1d9b8',
    'SHA2_256s' => 'b02a5315446fdce88caab5b7868b072dd2bbcedd8882b676c94e92202603c5a1',
    'SHA2_256f' => 'b46ea6196be67da1915f3e20e1eb19a4379319305974a70950c1a86eb1668828'
  }.freeze

  SLH_GOLDEN_SHA256.each do |param_key, expected_sha256|
    suffix = param_key.sub('SHA2_', '').downcase
    fixture = "post-quantum-slhdsa-#{suffix}"

    define_method("test_verify_slhdsa_#{suffix}_matches_ts_reference_golden") do
      source_path = ConformanceFixture.resolve(fixture, '.runar.ts')
      artifact = RunarCompiler.compile_from_source(source_path, disable_constant_folding: true)

      got_sha256 = Digest::SHA256.hexdigest(artifact.script.downcase)
      assert_equal expected_sha256, got_sha256,
                   "verify#{param_key} script diverged from the TS-reference-stamped " \
                   "conformance golden #{fixture}/expected-script.hex"
    end
  end
end
