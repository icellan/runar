# frozen_string_literal: true

require 'net/http'
require 'json'
require_relative 'provider'
require_relative 'types'
require_relative 'errors'

# RPCProvider — JSON-RPC provider for Bitcoin nodes.
#
# Implements the Provider interface by making JSON-RPC calls to a Bitcoin node
# (BSV or compatible). Uses only Ruby stdlib (net/http, json, base64) — no
# external dependencies required.
#
#   provider = Runar::SDK::RPCProvider.new(
#     host: 'localhost', port: 18332,
#     username: 'bitcoin', password: 'bitcoin',
#     network: 'regtest'
#   )
#
#   # Or use the factory shortcut:
#   provider = Runar::SDK::RPCProvider.regtest

module Runar
  module SDK
    class RPCProvider < Provider
      # @param host     [String]  Bitcoin node hostname (default: 'localhost')
      # @param port     [Integer] RPC port (default: 18332 for regtest)
      # @param username [String]  RPC username (default: 'bitcoin')
      # @param password [String]  RPC password (default: 'bitcoin')
      # @param network  [String]  network name returned by #get_network (default: 'regtest')
      def initialize(host: 'localhost', port: 18_332, username: 'bitcoin', password: 'bitcoin', network: 'regtest')
        @host     = host
        @port     = port
        @auth     = ["#{username}:#{password}"].pack('m0')
        @network  = network
      end

      # Factory method that returns an RPCProvider with default regtest settings.
      #
      # @param host     [String]  hostname (default: 'localhost')
      # @param port     [Integer] port (default: 18332)
      # @param username [String]  RPC username (default: 'bitcoin')
      # @param password [String]  RPC password (default: 'bitcoin')
      # @return [RPCProvider]
      def self.regtest(host: 'localhost', port: 18_332, username: 'bitcoin', password: 'bitcoin')
        new(host: host, port: port, username: username, password: password, network: 'regtest')
      end

      # Fetch a Transaction by txid using getrawtransaction (verbose).
      #
      # @param txid [String] transaction id
      # @return [Transaction]
      def get_transaction(txid)
        raw = rpc_call('getrawtransaction', txid, true)
        raw_hex = raw.fetch('hex', '')

        outputs = Array(raw['vout']).map do |o|
          val_btc = o.fetch('value', 0.0)
          sats    = (val_btc * 1e8).round
          sp      = o.fetch('scriptPubKey', {})
          TxOutput.new(script: sp.fetch('hex', ''), satoshis: sats)
        end

        Transaction.new(txid: txid, version: 1, outputs: outputs, raw: raw_hex)
      end

      # Fetch the raw transaction hex by txid.
      #
      # @param txid [String]
      # @return [String] hex-encoded raw transaction
      def get_raw_transaction(txid)
        result = rpc_call('getrawtransaction', txid, false)
        result.to_s
      end

      # Broadcast a signed raw transaction to the node.
      #
      # @param raw_tx [String] hex-encoded raw transaction
      # @return [String] txid
      def broadcast(raw_tx)
        rpc_call('sendrawtransaction', raw_tx).to_s
      end

      # Return all UTXOs for the given address using listunspent.
      #
      # @param address [String] BSV address
      # @return [Array<Utxo>]
      def get_utxos(address)
        result = Array(rpc_call('listunspent', 0, 9_999_999, [address]))
        utxos = result.map do |u|
          Utxo.new(
            txid: u['txid'],
            output_index: u['vout'].to_i,
            satoshis: (u['amount'].to_f * 1e8).round,
            script: u.fetch('scriptPubKey', '')
          )
        end
        # DoS-bound: reject pathological scripts at the provider boundary.
        utxos.each do |u|
          next if u.script.nil? || u.script.empty?

          SDK.assert_script_hex_under_limit(
            u.script, SDK::MAX_SCRIPT_BYTES,
            "RPCProvider.get_utxos(#{address})"
          )
        end
        utxos
      end

      # Script-hash UTXO lookup via scantxoutset (best-effort).
      #
      # Uses the scantxoutset RPC to scan the UTXO set for outputs matching
      # the given script hash. This is functional for regtest/testnet but slow
      # on mainnet. For production use, consider an electrum-style indexer or
      # track the UTXO manually with RunarContract#from_txid after deployment.
      #
      # @param script_hash [String] hex-encoded script hash to search for
      # @return [Hash, nil] UTXO hash with :txid, :output_index, :satoshis, :script keys, or nil
      def get_contract_utxo(script_hash)
        result = rpc_call('scantxoutset', 'start', ["raw(#{script_hash})"])
        unspents = Array(result['unspents'])
        return nil if unspents.empty?

        u = unspents.first
        {
          txid: u['txid'],
          output_index: u['vout'].to_i,
          satoshis: (u['amount'].to_f * 1e8).round,
          script: u['scriptPubKey']
        }
      rescue StandardError
        raise NotImplementedError,
              'RPCProvider#get_contract_utxo: scantxoutset RPC failed. ' \
              'Your node may not support this command. Alternatives: ' \
              'use an electrum-style indexer, or track the UTXO manually with ' \
              'RunarContract#from_txid after deployment.'
      end

      # Return the network name this provider is connected to.
      #
      # @return [String] e.g. 'regtest', 'testnet', 'mainnet'
      def get_network
        @network
      end

      # Return fee rate in satoshis per kilobyte.
      #
      # Returns 1 sat/KB unconditionally — appropriate for regtest. For
      # production networks, consider wrapping estimatesmartfee.
      #
      # @return [Integer]
      def get_fee_rate
        1
      end

      # Generate +n_blocks+ blocks (regtest only).
      #
      # Uses generatetoaddress with a dummy bech32 address. This will advance
      # the chain and confirm any transactions in the mempool.
      #
      # @param n_blocks [Integer] number of blocks to mine (default: 1)
      # @return [Array<String>] block hashes
      def mine(n_blocks = 1)
        # A standard regtest coinbase address for the dummy recipient.
        dummy_address = 'bcrt1qjrdns4f5zwkv29ln86plqzs092yd5fg6nsz8re'
        rpc_call('generatetoaddress', n_blocks, dummy_address)
      end

      # Low-level JSON-RPC call.
      #
      # @param method [String]  RPC method name
      # @param params [Array]   RPC parameters (splat)
      # @return [Object] the +result+ field of the JSON-RPC response
      # @raise [RuntimeError] on RPC error or HTTP failure
      def rpc_call(method, *params)
        body = JSON.generate(
          jsonrpc: '1.0',
          id: 'runar',
          method: method,
          params: params
        )

        uri = URI::HTTP.build(host: @host, port: @port, path: '/')
        request = Net::HTTP::Post.new(uri)
        request['Content-Type']  = 'application/json'
        request['Authorization'] = "Basic #{@auth}"
        request.body = body

        response = Net::HTTP.start(@host, @port, read_timeout: 600) do |http|
          http.request(request)
        end

        parse_rpc_response(response, method)
      end

      private

      def parse_rpc_response(response, method)
        data = begin
          JSON.parse(response.body)
        rescue JSON::ParserError
          raise "RPC #{method}: HTTP #{response.code} — non-JSON response"
        end

        if data['error']
          err = data['error']
          msg = err.is_a?(Hash) ? err.fetch('message', err.to_s) : err.to_s
          code = err.is_a?(Hash) ? err['code'] : nil
          raise "RPC error #{code}: #{msg}"
        end

        data['result']
      end
    end
  end
end
