# frozen_string_literal: true

# F-040: WhatsOnChainProvider#get_utxos returned script '' for every UTXO,
# because WoC's GET /address/{a}/unspent listing carries no locking script.
# The empty string became the BIP-143 scriptCode in LocalSigner#sign, so every
# funding signature was computed over a zero-length scriptCode that no real
# P2PKH OP_CHECKSIG accepts.
#
# Proves: with the shared recorded responses (conformance/sdk-woc/vectors.json)
# get_utxos fetches GET /tx/{txid}/hex per UTXO and returns the real locking
# script; it fails loudly on a body for another txid, a missing output, a value
# that disagrees with the tx, an unavailable tx and an empty output script; and
# LocalSigner / WalletSigner refuse an empty subscript.
# Does NOT prove: that the live WoC API still serves these shapes (vectors
# recorded 2026-09-29), or anything about get_contract_utxo. The Spend.validate
# harm demo lives in packages/runar-sdk/src/__tests__/f040-woc-utxo-script.test.ts.

require 'spec_helper'
require 'runar/sdk'
require 'runar/sdk/wallet'
require 'json'

F040_VECTORS = JSON.parse(
  File.read(File.expand_path('../../../../conformance/sdk-woc/vectors.json', __dir__))
)
F040_PREFIX = '/v1/bsv/main'
# 1-in/1-out tx spending 11..11:0.
F040_SPEND_TX_HEX = "0100000001#{'11' * 32}00000000" + '00ffffffff01' + '8403000000000000' + '0151' + '00000000'

class F040RecordingWallet < Runar::SDK::WalletClient
  attr_reader :calls

  def initialize
    @calls = []
  end

  def get_public_key(protocol_id:, key_id:)
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  end

  def create_signature(hash_to_sign:, protocol_id:, key_id:)
    @calls << hash_to_sign
    '30' + ('ab' * 34)
  end
end

RSpec.describe Runar::SDK::WhatsOnChainProvider do
  # Stub Net::HTTP: the listing, each raw tx at /tx/{txid}/hex, 404 otherwise.
  def stub_woc(address, unspent_body, raw_tx_hex)
    routes = { "#{F040_PREFIX}/address/#{address}/unspent" => unspent_body }
    raw_tx_hex.each { |txid, body| routes["#{F040_PREFIX}/tx/#{txid}/hex"] = body }
    fake = Object.new
    fake.define_singleton_method(:use_ssl=) { |_v| nil }
    fake.define_singleton_method(:request) do |req|
      body = routes[req.path]
      resp = body ? Net::HTTPOK.new('1.1', '200', 'OK') : Net::HTTPNotFound.new('1.1', '404', 'Not Found')
      resp.instance_variable_set(:@read, true)
      resp.instance_variable_set(:@body, body || 'Not Found')
      resp
    end
    allow(Net::HTTP).to receive(:new).and_return(fake)
  end

  describe '#get_utxos (F-040 recorded vectors)' do
    it 'returns each UTXO with its real locking script and value' do
      stub_woc(F040_VECTORS['address'], F040_VECTORS['unspentBody'], F040_VECTORS['rawTxHex'])
      utxos = described_class.new.get_utxos(F040_VECTORS['address'])
      got = utxos.map do |u|
        { 'txid' => u.txid, 'outputIndex' => u.output_index, 'satoshis' => u.satoshis, 'script' => u.script }
      end
      expect(got).to eq(F040_VECTORS['expected'])
    end

    F040_VECTORS['rejection_vectors'].each do |rv|
      it "rejects #{rv['name']}" do
        stub_woc(F040_VECTORS['address'], rv['unspentBody'], rv['rawTxHex'])
        expect { described_class.new.get_utxos(F040_VECTORS['address']) }
          .to raise_error(RuntimeError, /#{Regexp.escape(rv['error'])}/)
      end
    end
  end
end

RSpec.describe 'F-040 signers refuse an empty subscript' do
  it 'LocalSigner#sign raises on an empty subscript' do
    signer = Runar::SDK::LocalSigner.new('01' * 32)
    expect { signer.sign(F040_SPEND_TX_HEX, 0, '', 1000) }
      .to raise_error(ArgumentError, /empty subscript/)
  end

  it 'WalletSigner#sign raises before asking the wallet' do
    wallet = F040RecordingWallet.new
    signer = Runar::SDK::WalletSigner.new(wallet: wallet, protocol_id: [2, 'test'], key_id: '1')
    expect { signer.sign(F040_SPEND_TX_HEX, 0, '', 1000) }
      .to raise_error(ArgumentError, /empty subscript/)
    expect(wallet.calls).to be_empty
  end
end
