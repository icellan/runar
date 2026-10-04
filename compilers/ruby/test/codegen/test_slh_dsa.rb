# frozen_string_literal: true

require_relative 'codegen_helper'
require_relative '../../lib/runar_compiler/codegen/slh_dsa'

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
end
