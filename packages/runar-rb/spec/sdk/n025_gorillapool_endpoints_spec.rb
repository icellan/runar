# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'

# N-025: GorillaPoolProvider must call the routes the GorillaPool API actually
# serves, decode their documented shapes, and surface a 404 as an error. The
# old routes (/tx/{txid}/hex, /address/{a}/utxos, /script/{h}/utxos,
# /inscriptions/address/{a}, /bsv20/balance/..., /bsv20/utxos/...) do not exist,
# and the provider mapped their 404 to [] / nil / '0'.
#
# Proves: replaying the shared recorded responses
# (conformance/sdk-gorillapool/endpoint-vectors.json, recorded 2026-10-05) at
# the Net::HTTP boundary, every call decodes to the independently derived
# expectation, every unrouted (404) request raises, tampered bodies (txid
# mismatch, listing value != raw tx value, inscription content not matching its
# hash) are refused, get_contract_utxo refuses (no documented route), and
# broadcast posts {"rawtx": hex}.
# Does NOT prove: that the live API still serves these shapes; that POST
# /api/tx accepts {"rawtx"} (schema-documented, never sent live); pagination
# beyond the API's default page (100).
RSpec.describe Runar::SDK::GorillaPoolProvider do
  vectors_path = File.expand_path('../../../../conformance/sdk-gorillapool/endpoint-vectors.json', __dir__)
  vf = JSON.parse(File.read(vectors_path))

  snake = {
    'getRawTransaction' => :get_raw_transaction, 'getUtxos' => :get_utxos,
    'getContractUtxo' => :get_contract_utxo, 'getInscriptionsByAddress' => :get_inscriptions_by_address,
    'getInscription' => :get_inscription, 'getBSV20Balance' => :get_bsv20_balance,
    'getBSV21Balance' => :get_bsv21_balance, 'getBSV20Utxos' => :get_bsv20_utxos,
    'getBSV21Utxos' => :get_bsv21_utxos, 'broadcast' => :broadcast
  }

  # Stub Net::HTTP: a request whose method + path matches a route gets that
  # route's status and body; anything else gets the recorded 404.
  def serve_routes(vf, posted)
    fake = Object.new
    fake.define_singleton_method(:use_ssl=) { |_v| nil }
    fake.define_singleton_method(:request) do |req|
      posted << req.body if req.method == 'POST'
      r = vf['routes'].find { |x| x['method'] == req.method && x['path'] == req.path } || vf['notFound']
      klass = Net::HTTPResponse::CODE_TO_OBJ[r['status'].to_s]
      resp = klass.new('1.1', r['status'].to_s, 'stub')
      resp.instance_variable_set(:@read, true)
      resp.instance_variable_set(:@body, [r['bodyHex']].pack('H*'))
      resp
    end
    allow(Net::HTTP).to receive(:new).and_return(fake)
  end

  # Map the provider's return value onto the vector's camelCase JSON shape.
  def normalize(v)
    case v
    when Array then v.map { |x| normalize(x) }
    when Runar::SDK::Utxo
      { 'txid' => v.txid, 'outputIndex' => v.output_index, 'satoshis' => v.satoshis, 'script' => v.script }
    else v
    end
  end

  it 'loads the shared vectors' do
    expect(vf['calls'].length).to be >= 27
  end

  vf['calls'].each_with_index do |c, i|
    label = "##{i} #{c['call']}(#{c['args'].map { |a| a[0, 16] }.join(', ')}) -> " \
            "#{c.key?('expectError') ? "error /#{c['expectError']}/" : 'value'}"
    it label do
      posted = []
      serve_routes(vf, posted)
      provider = described_class.new(network: 'mainnet')
      m = snake.fetch(c['call'])
      if c.key?('expectError')
        expect { provider.public_send(m, *c['args']) }.to raise_error(RuntimeError, /#{Regexp.escape(c['expectError'])}/)
      else
        expect(normalize(provider.public_send(m, *c['args']))).to eq(c['expect'])
      end
      if c.key?('expectRequestJson')
        expect(posted.length).to eq(1)
        expect(JSON.parse(posted[0])).to eq(c['expectRequestJson'])
      end
    end
  end
end
