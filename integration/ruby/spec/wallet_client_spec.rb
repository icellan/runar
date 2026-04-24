# frozen_string_literal: true

# Live-endpoint BRC-100 WalletClient integration spec.
#
# This spec is environment-gated: it runs only when +RUNAR_WALLET_ENDPOINT+ is
# set to the base URL of a BRC-100-compatible wallet JSON-RPC endpoint. When
# unset, the spec skips cleanly with a pending message explaining how to
# enable it. This lets CI run the spec as a real-endpoint smoke test whenever
# a wallet URL is injected into the environment, while keeping local runs
# green without any wallet setup.
#
# The round-trip exercised here covers the minimum surface the Runar SDK
# uses from a BRC-100 wallet: derive a public key, then enumerate spendable
# outputs in a basket. That is enough to prove the HTTP transport, JSON
# envelope, and authentication path work end-to-end without needing to
# broadcast a transaction.
#
# Protocol shape: JSON-over-HTTP POST to
#   {endpoint}/{method}
# with a JSON body matching the BRC-100 request shape for each method. An
# optional +RUNAR_WALLET_AUTH+ env var (bearer token) is sent as an
# +Authorization: Bearer ...+ header if present.
#
# @example enable
#   RUNAR_WALLET_ENDPOINT=https://wallet.example.com/brc100 \
#     bundle exec rspec spec/wallet_client_spec.rb --tag integration

require 'spec_helper'
require 'net/http'
require 'json'
require 'uri'
require 'runar/sdk/wallet'

# Minimal HTTP-backed BRC-100 WalletClient used only by this spec.
#
# Speaks a thin JSON-over-HTTP dialect: POST {endpoint}/{method} with the
# request hash as JSON, parse the response as JSON. No retries, no batching
# — the goal is just to verify a live endpoint round-trip, not a production
# client.
class HttpWalletClient < Runar::SDK::WalletClient
  def initialize(endpoint:, auth_token: nil)
    super()
    @endpoint   = endpoint.sub(%r{/\z}, '')
    @auth_token = auth_token
  end

  def get_public_key(protocol_id:, key_id:)
    resp = post('getPublicKey', protocolID: protocol_id, keyID: key_id)
    resp['publicKey'] || resp[:publicKey] || resp['publicKeyHex'] ||
      raise("getPublicKey: missing publicKey in response: #{resp.inspect}")
  end

  def create_signature(hash_to_sign:, protocol_id:, key_id:)
    resp = post(
      'createSignature',
      hashToDirectlySign: hash_to_sign,
      protocolID: protocol_id,
      keyID: key_id
    )
    resp['signature'] || resp[:signature] ||
      raise("createSignature: missing signature in response: #{resp.inspect}")
  end

  def create_action(description:, outputs:)
    resp = post('createAction', description: description, outputs: outputs)
    {
      txid:   resp['txid']   || resp[:txid],
      raw_tx: resp['rawTx']  || resp[:rawTx] || resp['raw_tx']
    }
  end

  def list_outputs(basket:, tags: [], limit: 100)
    resp = post('listOutputs', basket: basket, tags: tags, limit: limit)
    resp['outputs'] || resp[:outputs] || []
  end

  private

  def post(method, body)
    uri = URI("#{@endpoint}/#{method}")
    req = Net::HTTP::Post.new(uri)
    req['Content-Type'] = 'application/json'
    req['Authorization'] = "Bearer #{@auth_token}" if @auth_token
    req.body = JSON.generate(body)

    resp = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: 10, read_timeout: 30) do |http|
      http.request(req)
    end

    raise "wallet endpoint #{method} HTTP #{resp.code}: #{resp.body}" unless resp.is_a?(Net::HTTPSuccess)

    JSON.parse(resp.body)
  end
end

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'BRC-100 WalletClient live endpoint', :integration do
  # rubocop:enable RSpec/DescribeClass
  let(:endpoint)   { ENV.fetch('RUNAR_WALLET_ENDPOINT', '') }
  let(:auth_token) { ENV['RUNAR_WALLET_AUTH'] }
  let(:basket)     { ENV.fetch('RUNAR_WALLET_BASKET', 'runar-integration-test') }
  let(:protocol)   { [2, 'runar integration'] }
  let(:key_id)     { '1' }

  before do
    if endpoint.nil? || endpoint.empty?
      skip 'RUNAR_WALLET_ENDPOINT not set — skipping live-endpoint wallet round-trip. ' \
           'Set RUNAR_WALLET_ENDPOINT to a BRC-100 wallet URL to enable.'
    end
  end

  it 'performs a minimal round-trip (get_public_key + list_outputs)' do
    wallet = HttpWalletClient.new(endpoint: endpoint, auth_token: auth_token)

    pub_key = wallet.get_public_key(protocol_id: protocol, key_id: key_id)
    expect(pub_key).to be_a(String)
    expect(pub_key).not_to be_empty
    # Compressed secp256k1 public keys are 66 hex chars starting with 02 or 03.
    expect(pub_key.length).to eq(66)
    expect(pub_key[0, 2]).to be_in(%w[02 03])
    expect(pub_key).to match(/\A[0-9a-fA-F]+\z/)

    # list_outputs should return an array (may be empty on a fresh wallet).
    outputs = wallet.list_outputs(basket: basket, limit: 10)
    expect(outputs).to be_a(Array)
    outputs.each do |out|
      expect(out).to be_a(Hash)
      # Require at least one of the canonical fields to confirm shape.
      expect(out.keys.map(&:to_s)).to include('outpoint').or include('satoshis').or include('lockingScript')
    end
  end
end
