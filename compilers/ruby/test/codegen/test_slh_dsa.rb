# frozen_string_literal: true

require_relative 'codegen_helper'

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
end
