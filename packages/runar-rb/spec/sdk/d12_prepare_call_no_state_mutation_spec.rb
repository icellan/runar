# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'runar/sdk'

# D12 SDK-F1/F2: +prepare_call+ must never leave the tracked state or UTXO
# changed. It used to advance @state and then do more fallible work
# (get_fee_rate / get_utxos / funding signing); a raise there left the state at
# n+1 while the chain was at n. An abandoned or superseded PreparedCall did the
# same. Now the post-state travels in the PreparedCall and +finalize_call+
# commits it only after a successful broadcast.
#
# Proves: a get_fee_rate / get_utxos failure inside prepare_call and an
# abandoned PreparedCall leave state + UTXO untouched; prepare A, prepare B,
# finalize A ok, finalize B fails -> state is A's post-state.
# Does not prove: interpreter verdicts (Ruby ships no ScriptVM).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'D12: prepare_call does not mutate tracked state' do
  # rubocop:enable RSpec/DescribeClass
  let(:caller_address) { '00' * 20 }
  let(:caller_pub_key) { '02' + ('00' * 32) }

  D12_GATE_SRC = <<~TS
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

  flaky_provider = Class.new(Runar::SDK::MockProvider) do
    attr_accessor :fail_on, :refuse

    def get_fee_rate
      if fail_on == :fee
        self.fail_on = nil
        raise 'HTTP 503'
      end
      super
    end

    def get_utxos(address)
      if fail_on == :utxos
        self.fail_on = nil
        raise 'ECONNRESET'
      end
      super
    end

    def broadcast(raw_tx)
      raise 'node refused the transaction' if refuse

      super
    end
  end

  def load_d12_artifact(dir)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    path = File.join(dir, 'Gate.runar.ts')
    File.write(path, D12_GATE_SRC)
    Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
  end

  define_method(:deploy_d12_gate) do |dir|
    contract = Runar::SDK::RunarContract.new(load_d12_artifact(dir), [0])
    provider = flaky_provider.new
    signer   = Runar::SDK::MockSigner.new(pub_key_hex: caller_pub_key, address: caller_address)
    contract.connect(provider, signer)
    provider.add_utxo(caller_address, Runar::SDK::Utxo.new(txid: 'aa' * 32, output_index: 0, satoshis: 5_000_000,
                                                           script: "76a914#{caller_address}88ac"))
    contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 50_000))
    [contract, provider]
  end

  %i[fee utxos].each do |which|
    it "leaves state and UTXO untouched when prepare_call raises (#{which})" do
      Dir.mktmpdir do |dir|
        contract, provider = deploy_d12_gate(dir)
        utxo_before = contract.get_utxo.to_h
        provider.fail_on = which
        expect { contract.call('bump', [7]) }.to raise_error(/503|ECONNRESET/)
        expect(contract.get_state).to eq('n' => 0)
        expect(contract.get_utxo.to_h).to eq(utxo_before)
        contract.call('bump', [7])
        expect(contract.get_state).to eq('n' => 1)
      end
    end
  end

  it 'leaves state untouched for an abandoned PreparedCall' do
    Dir.mktmpdir do |dir|
      contract, = deploy_d12_gate(dir)
      contract.prepare_call('bump', [7])
      expect(contract.get_state).to eq('n' => 0)
      contract.call('bump', [7])
      expect(contract.get_state).to eq('n' => 1)
    end
  end

  it 'keeps the first finalize commit when a superseded PreparedCall then fails' do
    Dir.mktmpdir do |dir|
      contract, provider = deploy_d12_gate(dir)
      a = contract.prepare_call('bump', [7])
      b = contract.prepare_call('bump', [7])
      expect(contract.get_state).to eq('n' => 0)
      contract.finalize_call(a, {})
      expect(contract.get_state).to eq('n' => 1)
      utxo_after = contract.get_utxo.to_h
      provider.refuse = true
      expect { contract.finalize_call(b, {}) }.to raise_error(StandardError)
      expect(contract.get_state).to eq('n' => 1)
      expect(contract.get_utxo.to_h).to eq(utxo_after)
    end
  end
end
