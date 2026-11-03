# frozen_string_literal: true

# N-041: WhatsOnChainProvider#get_contract_utxo returned script '' (WoC's
# /script/{h}/unspent listing carries no locking script), and #get_transaction
# read GET /tx/hash/{txid}, whose JSON has no "hex" field (raw was always '')
# and float BSV values. ExternalSigner passed an empty subscript straight to
# its callback.
#
# Proves, with conformance/sdk-woc/contract-utxo-tx-vectors.json and a stubbed
# Net::HTTP: get_contract_utxo returns the real locking script for both the
# legacy array and the {script,result} object listing, nil for an empty
# listing or a 404, and raises on a txid mismatch, a missing output, a value
# mismatch, a script hashing to another scripthash, an empty script and an
# unavailable tx; get_transaction returns the hash-verified served hex as raw
# with inputs/outputs parsed from it and exact 21e14-scale satoshis, and
# refuses a body for another txid; ExternalSigner refuses an empty subscript
# without calling its callback.
# Does NOT prove: that the live WoC API keeps these shapes (recorded
# 2026-09-29), nor which of several listed UTXOs is the right contract UTXO
# (the first entry is used, as before).

require 'spec_helper'
require 'runar/sdk'
require 'json'

N041_VECTORS = JSON.parse(
  File.read(File.expand_path('../../../../conformance/sdk-woc/contract-utxo-tx-vectors.json', __dir__))
)
N041_PREFIX = '/v1/bsv/main'

module N041Stub
  # Stub Net::HTTP: exact paths from routes (relative to the API base), 404 otherwise.
  def stub_routes(routes)
    full = routes.transform_keys { |k| "#{N041_PREFIX}#{k}" }
    fake = Object.new
    fake.define_singleton_method(:use_ssl=) { |_v| nil }
    fake.define_singleton_method(:request) do |req|
      body = full[req.path]
      resp = body ? Net::HTTPOK.new('1.1', '200', 'OK') : Net::HTTPNotFound.new('1.1', '404', 'Not Found')
      resp.instance_variable_set(:@read, true)
      resp.instance_variable_set(:@body, body || 'Not Found')
      resp
    end
    allow(Net::HTTP).to receive(:new).and_return(fake)
  end

  def listing_routes(script_hash, body, raw_tx_hex)
    routes = raw_tx_hex.to_h { |txid, h| ["/tx/#{txid}/hex", h] }
    routes["/script/#{script_hash}/unspent"] = body unless body.nil?
    routes
  end
end

RSpec.describe Runar::SDK::WhatsOnChainProvider do
  include N041Stub

  cu = N041_VECTORS['contractUtxo']

  describe '#get_contract_utxo (N-041 vectors)' do
    { 'legacyBody' => 'expectedLegacy', 'objectBody' => 'expectedObject' }.each do |body_key, exp_key|
      it "returns the real locking script for #{body_key}" do
        stub_routes(listing_routes(cu['scriptHash'], cu[body_key], cu['rawTxHex']))
        u = described_class.new.get_contract_utxo(cu['scriptHash'])
        expect(u).not_to be_nil
        got = { 'txid' => u.txid, 'outputIndex' => u.output_index, 'satoshis' => u.satoshis, 'script' => u.script }
        expect(got).to eq(cu[exp_key])
      end
    end

    cu['null_vectors'].each do |nv|
      it "returns nil for #{nv['name']}" do
        stub_routes(listing_routes(cu['scriptHash'], nv['body'], {}))
        expect(described_class.new.get_contract_utxo(cu['scriptHash'])).to be_nil
      end
    end

    cu['rejection_vectors'].each do |rv|
      it "rejects #{rv['name']}" do
        stub_routes(listing_routes(rv['scriptHash'], rv['body'], rv['rawTxHex']))
        expect { described_class.new.get_contract_utxo(rv['scriptHash']) }
          .to raise_error(RuntimeError, /#{Regexp.escape(rv['error'])}/)
      end
    end
  end

  describe '#get_transaction (N-041 vectors)' do
    N041_VECTORS['getTransaction']['cases'].each do |c|
      it "#{c['name']}: raw present, satoshis exact" do
        stub_routes("/tx/#{c['txid']}/hex" => c['rawTxHex'], "/tx/hash/#{c['txid']}" => c['hashBody'])
        tx = described_class.new.get_transaction(c['txid'])
        exp = c['expected']
        expect(tx.txid).to eq(exp['txid'])
        expect(tx.version).to eq(exp['version'])
        expect(tx.locktime).to eq(exp['locktime'])
        expect(tx.raw).to eq(exp['raw'])
        expect(tx.inputs.map do |i|
          { 'txid' => i.txid, 'outputIndex' => i.output_index, 'script' => i.script, 'sequence' => i.sequence }
        end).to eq(exp['inputs'])
        expect(tx.outputs.map { |o| { 'satoshis' => o.satoshis, 'script' => o.script } }).to eq(exp['outputs'])
        expect(tx.outputs.map(&:satoshis)).to all(be_an(Integer))
      end
    end

    N041_VECTORS['getTransaction']['rejection_vectors'].each do |rv|
      it "rejects #{rv['name']}" do
        routes = {}
        routes["/tx/#{rv['txid']}/hex"] = rv['rawTxHex'] unless rv['rawTxHex'].nil?
        routes["/tx/hash/#{rv['txid']}"] = rv['hashBody'] unless rv['hashBody'].nil?
        stub_routes(routes)
        expect { described_class.new.get_transaction(rv['txid']) }
          .to raise_error(RuntimeError, /#{Regexp.escape(rv['error'])}/)
      end
    end
  end
end

RSpec.describe 'N-041 ExternalSigner refuses an empty subscript' do
  it 'raises before calling the callback' do
    calls = []
    signer = Runar::SDK::ExternalSigner.new(
      pub_key_hex: '02' * 33, address: 'addr',
      sign_fn: ->(*args) { calls << args; 'deadbeef' }
    )
    expect { signer.sign('00', 0, '', 1000) }.to raise_error(ArgumentError, /empty subscript/)
    expect(calls).to be_empty
    expect(signer.sign('00', 0, '51', 1000)).to eq('deadbeef')
    expect(calls.length).to eq(1)
  end
end

# Does not cover a non-empty subscript whose separator is its last byte (still accepted).
RSpec.describe 'N-041 compute_op_push_tx refuses an empty subscript' do
  # 1-in/1-out tx spending 11..11:0.
  tx_hex = "0100000001#{'11' * 32}00000000" + '00ffffffff01' + '8403000000000000' + '0151' + '00000000'

  it 'refuses an empty subscript' do
    expect { Runar::SDK.compute_op_push_tx(tx_hex, 0, '', 1000) }
      .to raise_error(ArgumentError, /empty subscript/)
    _sig, preimage = Runar::SDK.compute_op_push_tx(tx_hex, 0, '51ab51', 1000, 1)
    expect(preimage).not_to be_empty
  end
end
