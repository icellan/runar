# frozen_string_literal: true

# NULLFAIL multi-method regression spec — verifies that a stateful
# contract whose public methods mix checkSig-using and non-checkSig
# branches still satisfies the BIP-146 NULLFAIL rule across spend
# chains.
#
# Ported from integration/ts/nullfail-multimethod.test.ts. The bug this
# guards against is:
#   "Signature must be zero for failed CHECK(MULTI)SIG operation"
# triggered when the non-taken checkSig branch left a non-empty
# placeholder on the stack after several chained spends.

require 'spec_helper'

MULTI_METHOD_SOURCE = <<~TS.freeze
  import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
  import type { PubKey, Sig, ByteString } from 'runar-lang';

  class MultiMethodContract extends StatefulSmartContract {
    stateRoot: ByteString;
    blockNumber: bigint;
    frozen: bigint;
    readonly governanceKey: PubKey;

    constructor(stateRoot: ByteString, blockNumber: bigint, frozen: bigint, governanceKey: PubKey) {
      super(stateRoot, blockNumber, frozen, governanceKey);
      this.stateRoot = stateRoot;
      this.blockNumber = blockNumber;
      this.frozen = frozen;
      this.governanceKey = governanceKey;
    }

    public advanceState(newStateRoot: ByteString, newBlockNumber: bigint) {
      assert(this.frozen === 0n);
      assert(newBlockNumber > this.blockNumber);
      this.stateRoot = newStateRoot;
      this.blockNumber = newBlockNumber;
    }

    public freeze(sig: Sig) {
      assert(checkSig(sig, this.governanceKey));
      this.frozen = 1n;
    }
  }
TS

def compile_source_nullfail(source, file_name)
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

RSpec.describe 'NULLFAIL multi-method' do # rubocop:disable RSpec/DescribeClass
  it 'compiles a multi-method contract that mixes checkSig and non-checkSig branches' do
    artifact = compile_source_nullfail(MULTI_METHOD_SOURCE, 'MultiMethodContract.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('MultiMethodContract')
    expect(artifact.script.length).to be > 0
  end

  it 'chains 5 advanceState calls without triggering NULLFAIL' do
    artifact = compile_source_nullfail(MULTI_METHOD_SOURCE, 'MultiMethodContract.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    initial_root = '00' * 32
    contract = Runar::SDK::RunarContract.new(
      artifact, [initial_root, 0, 0, wallet[:pub_key_hex]]
    )
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))

    5.times do |i|
      block_num = i + 1
      new_root  = (block_num.to_s(16).rjust(2, '0')) * 32
      txid, _ = contract.call(
        'advanceState', [new_root, block_num], provider, wallet[:signer],
        Runar::SDK::CallOptions.new(
          new_state: { 'stateRoot' => new_root, 'blockNumber' => block_num, 'frozen' => 0 }
        )
      )
      expect(txid).to be_truthy
      expect(txid.length).to eq(64)
    end
  end

  it 'rejects advanceState when the contract is frozen' do
    artifact = compile_source_nullfail(MULTI_METHOD_SOURCE, 'MultiMethodContract.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    initial_root = '00' * 32
    contract = Runar::SDK::RunarContract.new(
      artifact, [initial_root, 0, 1, wallet[:pub_key_hex]] # already frozen
    )
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))

    new_root = '01' * 32
    expect do
      contract.call(
        'advanceState', [new_root, 1], provider, wallet[:signer],
        Runar::SDK::CallOptions.new(
          new_state: { 'stateRoot' => new_root, 'blockNumber' => 1, 'frozen' => 1 }
        )
      )
    end.to raise_error(StandardError)
  end
end
