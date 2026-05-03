# frozen_string_literal: true

# SLH-DSA-SHA2-128s integration spec — exercises the
# `verifySLHDSA_SHA2_128s` builtin standalone (without the ECDSA hybrid
# wrapper covered by sphincs_wallet_spec.rb).
#
# Ported from integration/ts and integration/go SLH-DSA tests. The full
# spend path requires raw-transaction construction with a 7,856-byte
# signature; this spec covers the compile-and-deploy half so a
# regression in the SLH-DSA codegen module is caught at the SDK level
# without committing the test suite to maintaining a Ruby SLH-DSA signer.

require 'spec_helper'

SLHDSA_INLINE_SOURCE = <<~TS.freeze
  import { SmartContract, assert, verifySLHDSA_SHA2_128s } from 'runar-lang';
  import type { ByteString } from 'runar-lang';

  class SlhDsaVerify extends SmartContract {
    readonly pubKey: ByteString;
    constructor(pubKey: ByteString) { super(pubKey); this.pubKey = pubKey; }

    public verify(message: ByteString, signature: ByteString) {
      assert(verifySLHDSA_SHA2_128s(message, signature, this.pubKey));
    }
  }
TS

def compile_source_slhdsa(source, file_name)
  script = <<~JS
    (async () => {
      const { compile } = await import('#{PROJECT_ROOT}/packages/runar-compiler/dist/index.js');
      const result = compile(#{source.inspect}, { fileName: #{file_name.inspect} });
      if (!result.success) { console.error(JSON.stringify(result.diagnostics)); process.exit(1); }
      const json = JSON.stringify(result.artifact, (k, v) => typeof v === 'bigint' ? v.toString() + 'n' : v);
      process.stdout.write(json);
    })();
  JS
  node = ENV['NODE_BIN'] || 'node'
  output = `#{node} -e #{Shellwords.escape(script)} 2>&1`
  raise "Compile failed: #{output}" unless Process.last_status&.success?
  Runar::SDK::RunarArtifact.from_json(output)
end

RSpec.describe 'verifySLHDSA_SHA2_128s' do # rubocop:disable RSpec/DescribeClass
  it 'compiles a contract calling verifySLHDSA_SHA2_128s' do
    artifact = compile_source_slhdsa(SLHDSA_INLINE_SOURCE, 'SlhDsaVerify.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('SlhDsaVerify')
    expect(artifact.script.length).to be > 0
  end

  it 'produces a multi-tens-of-KB SLH-DSA verification script' do
    artifact = compile_source_slhdsa(SLHDSA_INLINE_SOURCE, 'SlhDsaVerify.runar.ts')
    script_bytes = artifact.script.length / 2
    expect(script_bytes).to be > 50_000
    expect(script_bytes).to be < 500_000
  end

  it 'deploys an SLH-DSA-locked UTXO on regtest' do
    # Deterministic SLH-DSA test public key (32 bytes hex: PK.seed[16] || PK.root[16]).
    test_pk = '00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf'

    artifact = compile_source_slhdsa(SLHDSA_INLINE_SOURCE, 'SlhDsaVerify.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [test_pk])
    txid, _count = contract.deploy(
      provider, wallet[:signer],
      Runar::SDK::DeployOptions.new(satoshis: 50_000)
    )
    expect(txid).to be_truthy
    expect(txid.length).to eq(64)
  end
end
