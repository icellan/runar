# frozen_string_literal: true

# WOTS+ integration spec — exercises the standalone `verifyWOTS` builtin
# (without the ECDSA hybrid wrapper covered by post_quantum_wallet_spec.rb).
#
# Ported from integration/ts and integration/go WOTS tests. The full spend
# path requires raw-transaction construction with a 2,144-byte signature;
# this spec covers the compile-and-deploy half so a regression in the
# WOTS codegen module is caught at the SDK level.

require 'spec_helper'

WOTS_INLINE_SOURCE = <<~TS.freeze
  import { SmartContract, assert, verifyWOTS } from 'runar-lang';
  import type { ByteString } from 'runar-lang';

  class WotsVerify extends SmartContract {
    readonly pkRoot: ByteString;
    constructor(pkRoot: ByteString) { super(pkRoot); this.pkRoot = pkRoot; }

    public verify(message: ByteString, signature: ByteString) {
      assert(verifyWOTS(message, signature, this.pkRoot));
    }
  }
TS

def compile_source_wots(source, file_name)
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

RSpec.describe 'verifyWOTS' do # rubocop:disable RSpec/DescribeClass
  it 'compiles a contract calling verifyWOTS' do
    artifact = compile_source_wots(WOTS_INLINE_SOURCE, 'WotsVerify.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('WotsVerify')
    expect(artifact.script.length).to be > 0
  end

  it 'produces a ~10 KB WOTS+ verification script' do
    artifact = compile_source_wots(WOTS_INLINE_SOURCE, 'WotsVerify.runar.ts')
    script_bytes = artifact.script.length / 2
    expect(script_bytes).to be > 5_000
    expect(script_bytes).to be < 50_000
  end

  it 'deploys a WOTS+-locked UTXO on regtest' do
    seed     = "\x42" + ("\x00" * 31)
    pub_seed = "\x01" + ("\x00" * 31)

    kp = wots_keygen(seed, pub_seed)

    artifact = compile_source_wots(WOTS_INLINE_SOURCE, 'WotsVerify.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [kp[:pk]])
    txid, _count = contract.deploy(
      provider, wallet[:signer],
      Runar::SDK::DeployOptions.new(satoshis: 20_000)
    )
    expect(txid).to be_truthy
    expect(txid.length).to eq(64)
  end
end
