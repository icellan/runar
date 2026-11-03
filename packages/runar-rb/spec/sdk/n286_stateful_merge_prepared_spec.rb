# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'

# N-286 — a stateful merge through the two-phase API (prepare_call /
# finalize_call). Replays the shared cross-SDK vector
# conformance/sdk-call/stateful-merge-prepared.json (produced by the TS SDK,
# whose MockProvider Spend-validated all three inputs; re-checked with Spend in
# conformance/sdk-call/stateful-merge.test.ts).
#
# Proves: given the vector's artifact, two contract UTXOs, funding UTXO and
# key, the Ruby SDK's prepare_call yields the same primary sighash and sig
# indices, and finalize_call with the vector's primary signature broadcasts a
# tx byte-equal to the TS reference (extra contract input's unlock, fee and
# change included).
# Does not prove: script execution in this tier (Ruby has no ScriptVM); the
# on-chain verdict rests on the TS Spend replay of the identical bytes.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-286 — stateful merge through prepare_call/finalize_call' do
  # rubocop:enable RSpec/DescribeClass
  n286_vector_path = File.expand_path('../../../../conformance/sdk-call/stateful-merge-prepared.json', __dir__)

  def n286_utxo(h)
    Runar::SDK::Utxo.new(txid: h['txid'], output_index: h['outputIndex'], satoshis: h['satoshis'], script: h['script'])
  end

  it 'reproduces the shared TS vector byte for byte' do
    v = JSON.parse(File.read(n286_vector_path))
    e = v['expected']
    art = Runar::SDK::RunarArtifact.from_hash(v['artifact'])

    signer = Runar::SDK::LocalSigner.new(v['privKeyHex'])
    provider = Runar::SDK::MockProvider.new
    provider.add_utxo(signer.get_address, n286_utxo(v['fundingUtxo']))
    cu = n286_utxo(v['contractUtxo'])
    eu = n286_utxo(v['extraContractUtxo'])
    provider.add_contract_utxo(cu.script, cu)
    provider.add_contract_utxo("#{eu.script}:extra", eu)

    contract = Runar::SDK::RunarContract.from_utxo(art, cu)
    prepared = contract.prepare_call(v['method'], [nil], provider, signer,
                                     Runar::SDK::CallOptions.new(additional_contract_inputs: [eu]))
    expect(prepared.sig_indices).to eq(e['sigIndices'])
    expect(prepared.sighash).to eq(e['sighash'])

    contract.finalize_call(prepared, { 0 => e['primarySignatureHex'] }, provider)
    txs = provider.get_broadcasted_txs
    expect(txs.length).to eq(1)
    expect(txs[0]).to eq(e['referenceTxHex'])
  end
end
