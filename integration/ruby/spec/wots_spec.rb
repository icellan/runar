# frozen_string_literal: true

# WOTS+ integration spec — exercises the standalone `verifyWOTS` builtin
# (without the ECDSA hybrid wrapper covered by post_quantum_wallet_spec.rb).
#
# The contract stores the 64-byte WOTS+ public key and calls verifyWOTS on it
# directly, so it is deployed with the raw key (kp[:pk]). The spend legs
# (GK-GAP-007) prove a valid signature unlocks the deployed UTXO on regtest and
# a tampered one is refused by the node.

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

  WOTS_SPEND_MSG = 'runar wots integration spend'

  def deploy_wots_verify(provider, signer, kp)
    artifact = compile_source_wots(WOTS_INLINE_SOURCE, 'WotsVerify.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [kp[:pk]])
    contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 20_000))
    contract
  end

  def wots_test_keypair
    wots_keygen("\x42" + ("\x00" * 31), "\x01" + ("\x00" * 31))
  end

  it 'spends a WOTS+-locked UTXO with a valid signature on regtest' do
    kp       = wots_test_keypair
    provider = create_provider
    wallet   = create_funded_wallet(provider)
    contract = deploy_wots_verify(provider, wallet[:signer], kp)

    sig_hex = wots_sign(WOTS_SPEND_MSG.b, kp[:sk], kp[:pub_seed])
    txid, _tx = contract.call('verify', [WOTS_SPEND_MSG.b.unpack1('H*'), sig_hex], provider, wallet[:signer])
    expect(txid.length).to eq(64)
  end

  it 'rejects a tampered WOTS+ signature at the node' do
    kp       = wots_test_keypair
    provider = create_provider
    wallet   = create_funded_wallet(provider)
    contract = deploy_wots_verify(provider, wallet[:signer], kp)

    sig_hex = wots_sign(WOTS_SPEND_MSG.b, kp[:sk], kp[:pub_seed])
    tampered = (sig_hex[0, 2].to_i(16) ^ 0x01).to_s(16).rjust(2, '0') + sig_hex[2..]

    before = provider.broadcast_attempts
    expect do
      contract.call('verify', [WOTS_SPEND_MSG.b.unpack1('H*'), tampered], provider, wallet[:signer])
    end.to raise_error(RuntimeError, /mandatory-script-verify-flag-failed/)
    # The attack transaction reached the node; the refusal is consensus, not
    # an SDK-side failure before broadcast.
    expect(provider.broadcast_attempts).to be > before
  end
end
