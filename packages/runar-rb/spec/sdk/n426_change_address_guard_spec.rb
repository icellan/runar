# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'

# N-426 -- the stateful change-address guard. Replays the shared cross-SDK
# vector conformance/sdk-call/n426-change-address-guard.json (TS reference,
# Spend-validated in conformance/sdk-call/n426-change-address-guard.test.ts).
#
# Proves: on a stateful method that takes _changePKH, prepare_call refuses a
# change_address for another key (no change_pub_key) with the shared message and
# broadcasts nothing; change_address + the matching change_pub_key and a
# change_address equal to the signer's own address are accepted.
# Does not prove: the terminal path, finalize_call, or a live node.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-426 -- stateful change-address guard' do
  # rubocop:enable RSpec/DescribeClass
  dir = File.expand_path('../../../../conformance/sdk-call', __dir__)
  let(:guard) { JSON.parse(File.read(File.join(dir, 'n426-change-address-guard.json'))) }
  let(:base) { JSON.parse(File.read(File.join(dir, 'stateful-merge-prepared.json'))) }

  def n426_utxo(h)
    Runar::SDK::Utxo.new(txid: h['txid'], output_index: h['outputIndex'], satoshis: h['satoshis'], script: h['script'])
  end

  let(:signer) { Runar::SDK::LocalSigner.new(base['privKeyHex']) }
  let(:provider) do
    p = Runar::SDK::MockProvider.new
    p.add_utxo(signer.get_address, n426_utxo(base['fundingUtxo']))
    p.add_contract_utxo(base['contractUtxo']['script'], n426_utxo(base['contractUtxo']))
    p
  end
  let(:contract) do
    Runar::SDK::RunarContract.from_utxo(Runar::SDK::RunarArtifact.from_hash(base['artifact']),
                                        n426_utxo(base['contractUtxo']))
  end

  def prepare(opts)
    contract.prepare_call(base['method'], [nil], provider, signer, Runar::SDK::CallOptions.new(**opts))
  end

  it 'refuses change_address for another key without change_pub_key, before any broadcast' do
    want = guard['message'].sub('{changeAddress}', guard['otherAddress'])
    expect { prepare(change_address: guard['otherAddress']) }.to raise_error(StandardError, /#{Regexp.escape(want)}/)
    expect(provider.get_broadcasted_txs).to be_empty
  end

  it 'accepts change_address with the matching change_pub_key' do
    prepared = prepare(change_address: guard['otherAddress'], change_pub_key: guard['otherPubKeyHex'])
    expect(prepared.sig_indices).to eq([0])
    # The covenant's _changePKH (pushed in the unlock) and the change output both carry hash160(otherPubKey).
    pkh = Digest::RMD160.hexdigest(Digest::SHA256.digest([guard['otherPubKeyHex']].pack('H*')))
    expect(prepared.tx_hex.scan(pkh).length).to eq(2)
  end

  it "accepts change_address equal to the signer's own address" do
    expect(signer.get_address).to eq(guard['ownAddress'])
    expect(prepare(change_address: guard['ownAddress']).sig_indices).to eq([0])
  end
end
