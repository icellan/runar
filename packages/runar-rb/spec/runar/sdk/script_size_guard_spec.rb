# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

RSpec.describe 'Item 8 — ScriptSizeExceededError at SDK entry points' do
  let(:limit) { Runar::SDK::MAX_SCRIPT_BYTES }
  let(:oversized_script) { '51' * (limit + 1) }
  let(:at_limit_script)  { '51' * limit }
  let(:mock_addr) { '00' * 20 }

  # Minimal stateless artifact whose `script` is the oversized hex.
  def oversized_artifact
    Runar::SDK::RunarArtifact.from_hash(
      'version' => 'runar-v0.1.0',
      'compilerVersion' => '0.1.0',
      'contractName' => 'OversizedContract',
      'script' => oversized_script,
      'asm' => '',
      'abi' => { 'constructor' => { 'params' => [] }, 'methods' => [] },
      'buildTimestamp' => '2026-05-18T00:00:00.000Z',
    )
  end

  def small_artifact_with_method
    Runar::SDK::RunarArtifact.from_hash(
      'version' => 'runar-v0.1.0',
      'compilerVersion' => '0.1.0',
      'contractName' => 'OversizedContract',
      'script' => '51',
      'asm' => '',
      'abi' => {
        'constructor' => { 'params' => [] },
        'methods' => [{ 'name' => 'spend', 'params' => [], 'isPublic' => true }],
      },
      'buildTimestamp' => '2026-05-18T00:00:00.000Z',
    )
  end

  def funded_provider
    p = Runar::SDK::MockProvider.new
    p.add_utxo(mock_addr, Runar::SDK::Utxo.new(
      txid: 'aa' * 32, output_index: 0, satoshis: 100_000,
      script: '76a914' + ('00' * 20) + '88ac'
    ))
    p
  end

  def mock_signer
    Runar::SDK::MockSigner.new(pub_key_hex: '02' + ('00' * 32), address: mock_addr)
  end

  # -------------------------------------------------------------------------
  # deploy()
  # -------------------------------------------------------------------------

  describe 'RunarContract#deploy' do
    it 'rejects oversized locking scripts with ScriptSizeExceededError' do
      contract = Runar::SDK::RunarContract.new(oversized_artifact, [])
      provider = funded_provider
      signer = mock_signer

      expect {
        contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 1_000))
      }.to raise_error(Runar::SDK::ScriptSizeExceededError) do |err|
        expect(err.limit).to eq(limit)
        expect(err.actual).to eq(limit + 1)
        expect(err.context).to include('OversizedContract.deploy')
        expect(err.message).to include("limit=#{limit}")
        expect(err.message).to include("actual=#{limit + 1}")
      end

      # No broadcast should have happened — guard fires BEFORE signing/broadcast.
      expect(provider.get_broadcasted_txs).to be_empty
    end
  end

  # -------------------------------------------------------------------------
  # call()
  # -------------------------------------------------------------------------

  describe 'RunarContract#call' do
    it 'rejects oversized current_utxo.script with ScriptSizeExceededError' do
      # Use from_utxo to simulate a reconnect with a poisoned (oversized) script.
      poisoned_utxo = Runar::SDK::Utxo.new(
        txid: 'aa' * 32, output_index: 0, satoshis: 50_000,
        script: oversized_script
      )
      contract = Runar::SDK::RunarContract.from_utxo(
        small_artifact_with_method, poisoned_utxo
      )
      provider = funded_provider
      signer = mock_signer

      expect {
        contract.call('spend', [], provider, signer)
      }.to raise_error(Runar::SDK::ScriptSizeExceededError) do |err|
        expect(err.limit).to eq(limit)
        expect(err.actual).to eq(limit + 1)
        expect(err.context).to include('OversizedContract.call(spend)')
      end

      expect(provider.get_broadcasted_txs).to be_empty
    end
  end

  # -------------------------------------------------------------------------
  # MockProvider — get_utxos / get_contract_utxo
  # -------------------------------------------------------------------------

  describe 'MockProvider#get_utxos' do
    it 'rejects oversized UTXO scripts with ScriptSizeExceededError' do
      provider = Runar::SDK::MockProvider.new
      provider.add_utxo('addr', Runar::SDK::Utxo.new(
        txid: 'bb' * 32, output_index: 0, satoshis: 1_000,
        script: oversized_script
      ))
      expect {
        provider.get_utxos('addr')
      }.to raise_error(Runar::SDK::ScriptSizeExceededError) do |err|
        expect(err.limit).to eq(limit)
        expect(err.actual).to eq(limit + 1)
        expect(err.context).to include('MockProvider.get_utxos')
      end
    end

    it 'passes at-limit scripts without error' do
      provider = Runar::SDK::MockProvider.new
      provider.add_utxo('addr', Runar::SDK::Utxo.new(
        txid: 'dd' * 32, output_index: 0, satoshis: 1_000,
        script: at_limit_script
      ))
      utxos = provider.get_utxos('addr')
      expect(utxos.length).to eq(1)
      expect(utxos[0].script.length).to eq(limit * 2)
    end
  end

  describe 'MockProvider#get_contract_utxo' do
    it 'rejects oversized contract UTXO scripts' do
      provider = Runar::SDK::MockProvider.new
      provider.add_contract_utxo('script-hash', Runar::SDK::Utxo.new(
        txid: 'cc' * 32, output_index: 0, satoshis: 1_000,
        script: oversized_script
      ))
      expect {
        provider.get_contract_utxo('script-hash')
      }.to raise_error(Runar::SDK::ScriptSizeExceededError) do |err|
        expect(err.context).to include('MockProvider.get_contract_utxo')
      end
    end
  end
end
