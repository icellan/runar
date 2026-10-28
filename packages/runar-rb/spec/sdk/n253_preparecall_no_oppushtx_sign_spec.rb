# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'

# N-253 -- since F-369/N-213 the k=1 OP_PUSH_TX ECDSA signature is unused on
# the stateful prepare_call path (the on-chain script derives it from the
# preimage), yet the path still computed and discarded one per pass. The fix
# adds SDK.compute_op_push_tx_preimage and uses it there; compute_op_push_tx
# stays public and unchanged.
#
# Proves: a stateful merge prepare_call (the shared N-286 vector: primary +
# extra contract input) performs zero OP_PUSH_TX signs, counted by spying
# SDK.sign_preimage_k1; the control shows the spy sees compute_op_push_tx sign
# and that the preimage-only variant returns the same preimage without
# signing. Byte-identity of prepare_call output is proven by the N-286 spec.
# Does not prove anything about the stateless / terminal paths.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-253 -- stateful prepare_call computes no OP_PUSH_TX signature' do
  # rubocop:enable RSpec/DescribeClass
  vector_path = File.expand_path('../../../../conformance/sdk-call/stateful-merge-prepared.json', __dir__)

  def n253_utxo(h)
    Runar::SDK::Utxo.new(txid: h['txid'], output_index: h['outputIndex'], satoshis: h['satoshis'], script: h['script'])
  end

  def n253_count_signs
    count = 0
    allow(Runar::SDK).to receive(:sign_preimage_k1).and_wrap_original do |m, *args|
      count += 1
      m.call(*args)
    end
    -> { count }
  end

  it 'performs no k=1 sign on a stateful merge prepare_call' do
    v = JSON.parse(File.read(vector_path))
    art = Runar::SDK::RunarArtifact.from_hash(v['artifact'])
    signer = Runar::SDK::LocalSigner.new(v['privKeyHex'])
    provider = Runar::SDK::MockProvider.new
    provider.add_utxo(signer.get_address, n253_utxo(v['fundingUtxo']))
    cu = n253_utxo(v['contractUtxo'])
    eu = n253_utxo(v['extraContractUtxo'])
    provider.add_contract_utxo(cu.script, cu)
    provider.add_contract_utxo("#{eu.script}:extra", eu)
    contract = Runar::SDK::RunarContract.from_utxo(art, cu)

    signs = n253_count_signs
    prepared = contract.prepare_call(v['method'], [nil], provider, signer,
                                     Runar::SDK::CallOptions.new(additional_contract_inputs: [eu]))
    expect(prepared.sighash).to eq(v['expected']['sighash'])
    expect(signs.call).to eq(0)
  end

  it 'preimage-only variant matches compute_op_push_tx without signing' do
    v = JSON.parse(File.read(vector_path))
    tx_hex = v['expected']['referenceTxHex']
    cu = v['contractUtxo']
    signs = n253_count_signs
    [0x41, 0x43].each do |flag|
      before = signs.call
      _sig, full = Runar::SDK.compute_op_push_tx(tx_hex, 0, cu['script'], cu['satoshis'], -1, flag)
      expect(signs.call).to eq(before + 1)
      only = Runar::SDK.compute_op_push_tx_preimage(tx_hex, 0, cu['script'], cu['satoshis'], -1, flag)
      expect(signs.call).to eq(before + 1)
      expect(only).to eq(full)
    end
    expect { Runar::SDK.compute_op_push_tx_preimage(tx_hex, 0, '', 1) }.to raise_error(ArgumentError)
  end
end
