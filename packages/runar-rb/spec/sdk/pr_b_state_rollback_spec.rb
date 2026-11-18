# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'runar/sdk'

# +prepare_call+ advances the contract's local state to the post-call state
# BEFORE +finalize_call+ broadcasts. When the broadcast was refused nothing put
# it back, so the next call was built from a state the chain never reached (same
# bug as the TS SDK, packages/runar-sdk/src/__tests__/pr-b-state-rollback.test.ts).
#
# Ruby ships no ScriptVM, so MockProvider cannot refuse the failing covenant on
# its own; the refusal comes from a MockProvider whose broadcast raises while
# +refuse+ is set, like a node rejecting the transaction.
#
# Proves: after a refused broadcast, +get_state+ and +get_utxo+ equal their
# pre-call values, and an honest follow-up call commits n = 1.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'PR B: a refused broadcast leaves the local state untouched' do
  # rubocop:enable RSpec/DescribeClass
  let(:caller_address) { '00' * 20 }
  let(:caller_pub_key) { '02' + ('00' * 32) }

  GATE_SRC = <<~TS
    import { StatefulSmartContract, assert } from 'runar-lang';

    class Gate extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      public bump(k: bigint) {
        assert(k === 7n);
        this.n = this.n + 1n;
      }
    }
  TS

  refusing_provider = Class.new(Runar::SDK::MockProvider) do
    attr_accessor :refuse

    def broadcast(raw_tx)
      raise 'node refused the transaction (mandatory-script-verify-flag-failed)' if refuse

      super
    end
  end

  def load_artifact(dir)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    path = File.join(dir, 'Gate.runar.ts')
    File.write(path, GATE_SRC)
    Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
  end

  define_method(:deploy_gate) do |dir|
    contract = Runar::SDK::RunarContract.new(load_artifact(dir), [0])
    provider = refusing_provider.new
    signer   = Runar::SDK::MockSigner.new(pub_key_hex: caller_pub_key, address: caller_address)
    contract.connect(provider, signer)
    provider.add_utxo(caller_address, Runar::SDK::Utxo.new(txid: 'aa' * 32, output_index: 0, satoshis: 5_000_000,
                                                           script: "76a914#{caller_address}88ac"))
    contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 50_000))
    [contract, provider]
  end

  it 'rolls back state and the tracked UTXO; the next honest call commits n = 1' do
    Dir.mktmpdir do |dir|
      contract, provider = deploy_gate(dir)
      state_before = contract.get_state
      utxo_before  = contract.get_utxo.dup

      provider.refuse = true
      expect { contract.call('bump', [8]) }.to raise_error(/refused/)
      expect(contract.get_state).to eq(state_before)
      expect(contract.get_utxo.to_h).to eq(utxo_before.to_h)

      provider.refuse = false
      contract.call('bump', [7])
      expect(contract.get_state).to eq('n' => 1)
    end
  end

  # A PreparedCall whose broadcast was refused can be finalized again: the retry
  # commits the post-call state. A further finalize of the now-committed
  # PreparedCall that fails must not rewind the state the chain reached.
  it 'commits on a retried finalize and ignores a refused repeat of a committed one' do
    Dir.mktmpdir do |dir|
      contract, provider = deploy_gate(dir)
      utxo_before = contract.get_utxo.to_h

      prepared = contract.prepare_call('bump', [7])
      provider.refuse = true
      expect { contract.finalize_call(prepared, {}) }.to raise_error(/refused/)
      expect(contract.get_state).to eq('n' => 0)
      expect(contract.get_utxo.to_h).to eq(utxo_before)

      provider.refuse = false
      contract.finalize_call(prepared, {})
      expect(contract.get_state).to eq('n' => 1)
      utxo_after = contract.get_utxo.to_h

      provider.refuse = true
      expect { contract.finalize_call(prepared, {}) }.to raise_error(/refused/)
      expect(contract.get_state).to eq('n' => 1)
      expect(contract.get_utxo.to_h).to eq(utxo_after)
    end
  end
end
