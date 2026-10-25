# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'

# N-412 — a STATELESS contract method that takes the auto-injected intent
# witness `_prevOutScript_0`. Replays the shared cross-SDK vector
# conformance/sdk-call/stateless-witness.json (produced by the TS SDK, whose
# MockProvider Spend-validated every input; re-checked with @bsv/sdk Spend —
# including a tampered/omitted witness push — in
# conformance/sdk-call/stateless-witness.test.ts).
#
# Proves: the Ruby SDK's call (no-Sig `peek`, Sig `spend`) and prepare_call +
# finalize_call (`spend`) push `<declared args> <witness> <selector>` on input
# 0 and broadcast a tx byte-equal to the TS reference.
# Does not prove: script execution in this tier (Ruby has no ScriptVM; the
# on-chain verdict rests on the TS Spend replay of the identical bytes), or
# `_serialisedOutputs` on a stateless method (the compiler refuses
# requireOutputP2PKH outside StatefulSmartContract).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-412 — stateless method with an intent-witness param' do
  # rubocop:enable RSpec/DescribeClass
  n412_vector_path = File.expand_path('../../../../conformance/sdk-call/stateless-witness.json', __dir__)
  let(:vector) { JSON.parse(File.read(n412_vector_path)) }

  def n412_utxo(h)
    Runar::SDK::Utxo.new(txid: h['txid'], output_index: h['outputIndex'], satoshis: h['satoshis'], script: h['script'])
  end

  def n412_fresh(v)
    art = Runar::SDK::RunarArtifact.from_hash(v['artifact'])
    signer = Runar::SDK::LocalSigner.new(v['privKeyHex'])
    provider = Runar::SDK::MockProvider.new
    provider.add_utxo(signer.get_address, n412_utxo(v['fundingUtxo']))
    cu = n412_utxo(v['contractUtxo'])
    provider.add_contract_utxo(cu.script, cu)
    contract = Runar::SDK::RunarContract.from_utxo(art, cu)
    contract.set_prev_out_script(0, v['prevOutScriptHex'])
    [contract, provider, signer]
  end

  def n412_expect_broadcast(provider, want)
    txs = provider.get_broadcasted_txs
    expect(txs.length).to eq(1)
    expect(txs[0]).to include(want['input0UnlockingHex'])
    expect(txs[0]).to eq(want['referenceTxHex'])
  end

  it 'call(peek) pushes <x> <witness> <selector> and matches the TS vector' do
    contract, provider, signer = n412_fresh(vector)
    contract.call('peek', [5], provider, signer)
    n412_expect_broadcast(provider, vector['expected']['peek'])
  end

  it 'call(spend) pushes <sig> <pubKey> <witness> <selector> and matches the TS vector' do
    contract, provider, signer = n412_fresh(vector)
    contract.call('spend', [nil, vector['pubKeyHex']], provider, signer)
    n412_expect_broadcast(provider, vector['expected']['spend'])
  end

  it 'prepare_call + finalize_call(spend) matches the TS vector' do
    contract, provider, signer = n412_fresh(vector)
    prepared = contract.prepare_call('spend', [nil, vector['pubKeyHex']], provider, signer)
    expect(prepared.sig_indices).to eq([0])
    contract.finalize_call(prepared, { 0 => vector['expected']['spend']['signatureHex'] }, provider)
    n412_expect_broadcast(provider, vector['expected']['spend'])
  end
end
