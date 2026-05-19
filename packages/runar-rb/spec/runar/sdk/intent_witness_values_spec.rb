# frozen_string_literal: true

# R-6 — SDK consumer support for intent-intrinsic auto-injected witness params
# (`_prevOutScript_<i>`, `_serialisedOutputs`).
#
# Covers:
#   - filter: auto-injected witness params are NOT part of the user arg count
#   - setters: set_prev_out_script / set_serialised_outputs store witness bytes
#   - errors: missing witness raises a typed WitnessValueMissingError
#   - wiring: witness bytes are appended to the primary unlocking script in
#     ABI order (`_prevOutScript_*` first, then `_serialisedOutputs`)

require 'spec_helper'
require 'runar/sdk'

RSpec.describe 'R-6 — intent-intrinsic witness values' do
  let(:mock_addr) { '00' * 20 }

  def make_intent_artifact(prev_out_inputs:, serialised:)
    params = [
      { 'name' => 'amount', 'type' => 'bigint' },
      { 'name' => '_changePKH', 'type' => 'Ripemd160' },
      { 'name' => '_changeAmount', 'type' => 'bigint' },
      { 'name' => '_newAmount', 'type' => 'bigint' },
      { 'name' => 'txPreimage', 'type' => 'SigHashPreimage' },
    ]
    prev_out_inputs.each do |i|
      params << { 'name' => "_prevOutScript_#{i}", 'type' => 'ByteString' }
    end
    params << { 'name' => '_serialisedOutputs', 'type' => 'ByteString' } if serialised

    Runar::SDK::RunarArtifact.from_hash(
      'version' => 'runar-v0.1.0',
      'compilerVersion' => '0.1.0',
      'contractName' => 'IntentWitnessTest',
      'script' => '51',
      'asm' => '',
      'abi' => {
        'constructor' => { 'params' => [{ 'name' => 'count', 'type' => 'bigint' }] },
        'methods' => [{ 'name' => 'move', 'params' => params, 'isPublic' => true }],
      },
      'stateFields' => [{ 'name' => 'count', 'type' => 'bigint', 'index' => 0 }],
      'codeSeparatorIndex' => 0,
      'buildTimestamp' => '2026-05-18T00:00:00.000Z',
    )
  end

  def setup_and_deploy(artifact)
    contract = Runar::SDK::RunarContract.new(artifact, [0])
    signer = Runar::SDK::MockSigner.new(pub_key_hex: '02' + ('00' * 32), address: mock_addr)
    provider = Runar::SDK::MockProvider.new
    provider.add_utxo(mock_addr, Runar::SDK::Utxo.new(
      txid: 'aa' * 32, output_index: 0, satoshis: 100_000,
      script: '76a914' + ('00' * 20) + '88ac'
    ))
    contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 50_000))
    # Funding UTXO for the call
    provider.add_utxo(mock_addr, Runar::SDK::Utxo.new(
      txid: 'bb' * 32, output_index: 1, satoshis: 100_000,
      script: '76a914' + ('00' * 20) + '88ac'
    ))
    [contract, provider, signer]
  end

  describe 'arg-count filter' do
    it 'excludes auto-injected witness params from the user-facing arg count' do
      artifact = make_intent_artifact(prev_out_inputs: [0, 1], serialised: true)
      contract, provider, signer = setup_and_deploy(artifact)

      contract.set_prev_out_script(0, 'aa')
      contract.set_prev_out_script(1, 'bb')
      contract.set_serialised_outputs('cc')

      contract.call('move', [123], provider, signer,
                    Runar::SDK::CallOptions.new(new_state: { 'count' => 1 }))
      expect(contract.get_state['count']).to eq(1)
    end

    it 'still rejects real arg count mismatches' do
      artifact = make_intent_artifact(prev_out_inputs: [0], serialised: true)
      contract, provider, signer = setup_and_deploy(artifact)

      expect {
        contract.call('move', [1, 2], provider, signer)
      }.to raise_error(ArgumentError, /expects 1 args, got 2/)
    end
  end

  describe 'missing witness raises WitnessValueMissingError' do
    it 'raises when _prevOutScript_<i> is not set' do
      artifact = make_intent_artifact(prev_out_inputs: [0], serialised: false)
      contract, provider, signer = setup_and_deploy(artifact)

      expect {
        contract.call('move', [1], provider, signer)
      }.to raise_error(Runar::SDK::WitnessValueMissingError) do |err|
        expect(err.param_name).to eq('_prevOutScript_0')
        expect(err.method_name).to eq('move')
        expect(err.contract_name).to eq('IntentWitnessTest')
      end
    end

    it 'raises when _serialisedOutputs is not set' do
      artifact = make_intent_artifact(prev_out_inputs: [], serialised: true)
      contract, provider, signer = setup_and_deploy(artifact)

      expect {
        contract.call('move', [1], provider, signer)
      }.to raise_error(Runar::SDK::WitnessValueMissingError) do |err|
        expect(err.param_name).to eq('_serialisedOutputs')
      end
    end
  end

  describe 'witness bytes appear in the broadcast unlocking script' do
    it 'appends multiple _prevOutScript_* pushes in ABI order' do
      artifact = make_intent_artifact(prev_out_inputs: [0, 1], serialised: false)
      contract, provider, signer = setup_and_deploy(artifact)

      contract.set_prev_out_script(0, 'deadbeef')
      contract.set_prev_out_script(1, 'cafebabe')

      contract.call('move', [1], provider, signer,
                    Runar::SDK::CallOptions.new(new_state: { 'count' => 1 }))

      txs = provider.get_broadcasted_txs
      expect(txs.length).to eq(2)
      call_hex = txs[1]
      push0 = '04deadbeef'
      push1 = '04cafebabe'
      idx0 = call_hex.index(push0)
      idx1 = call_hex.index(push1)
      expect(idx0).not_to be_nil
      expect(idx1).to be > idx0
    end

    it 'appends _prevOutScript_<i> then _serialisedOutputs (prevOut first)' do
      artifact = make_intent_artifact(prev_out_inputs: [0], serialised: true)
      contract, provider, signer = setup_and_deploy(artifact)

      contract.set_prev_out_script(0, '11223344')
      contract.set_serialised_outputs('55667788')

      contract.call('move', [1], provider, signer,
                    Runar::SDK::CallOptions.new(new_state: { 'count' => 1 }))

      call_hex = provider.get_broadcasted_txs[1]
      idx_prev = call_hex.index('0411223344')
      idx_serial = call_hex.index('0455667788')
      expect(idx_prev).not_to be_nil
      expect(idx_serial).to be > idx_prev
    end

    it 'rejects invalid hex inputs' do
      artifact = make_intent_artifact(prev_out_inputs: [0], serialised: false)
      contract = Runar::SDK::RunarContract.new(artifact, [0])
      expect { contract.set_prev_out_script(0, 'not-hex!') }.to raise_error(ArgumentError)
      expect { contract.set_serialised_outputs('abc') }.to raise_error(ArgumentError)
    end
  end
end
