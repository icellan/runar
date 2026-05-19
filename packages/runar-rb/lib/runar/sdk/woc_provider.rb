# frozen_string_literal: true

require 'net/http'
require 'json'
require 'uri'
require_relative 'provider'
require_relative 'types'
require_relative 'errors'

# WhatsOnChainProvider — HTTP-based BSV API provider.
#
# Implements the Provider interface by making HTTP requests to the
# WhatsOnChain REST API. Uses only Ruby stdlib (net/http, json, uri).
#
#   provider = Runar::SDK::WhatsOnChainProvider.new(network: 'mainnet')
#   utxos = provider.get_utxos('1A1zP1eP...')

module Runar
  module SDK
    class WhatsOnChainProvider < Provider
      # @param network [String] 'mainnet' or 'testnet'
      def initialize(network: 'mainnet')
        @network = network
        @base_url = if network == 'mainnet'
                      'https://api.whatsonchain.com/v1/bsv/main'
                    else
                      'https://api.whatsonchain.com/v1/bsv/test'
                    end
      end

      # Fetch a TransactionData by its txid.
      #
      # @param txid [String] transaction id (64 hex chars)
      # @return [TransactionData]
      def get_transaction(txid)
        data = api_get("/tx/hash/#{txid}")

        inputs = Array(data['vin']).map do |vin|
          TxInput.new(
            txid: vin['txid'],
            output_index: vin['vout'],
            script: vin.dig('scriptSig', 'hex') || '',
            sequence: vin['sequence'] || 0xFFFFFFFF
          )
        end

        outputs = Array(data['vout']).map do |vout|
          satoshis = (vout['value'].to_f * 1e8).round
          TxOutput.new(
            satoshis: satoshis,
            script: vout.dig('scriptPubKey', 'hex') || ''
          )
        end

        TransactionData.new(
          txid: data['txid'],
          version: data['version'] || 1,
          inputs: inputs,
          outputs: outputs,
          locktime: data['locktime'] || 0,
          raw: data['hex'] || ''
        )
      end

      # Broadcast a raw transaction hex to the network.
      #
      # @param raw_tx [String] hex-encoded raw transaction
      # @return [String] txid of the broadcasted transaction
      def broadcast(raw_tx)
        uri = URI("#{@base_url}/tx/raw")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        request = Net::HTTP::Post.new(uri)
        request['Content-Type'] = 'application/json'
        request.body = JSON.generate(txhex: raw_tx)

        response = http.request(request)
        unless response.is_a?(Net::HTTPSuccess)
          raise "WoC broadcast failed (#{response.code}): #{response.body}"
        end

        # WoC returns the txid as a JSON-encoded string.
        JSON.parse(response.body)
      end

      # Return all UTXOs for a given address.
      #
      # Note: WoC does not return locking scripts in UTXO lists, so the
      # script field is set to an empty string.
      #
      # @param address [String] BSV address
      # @return [Array<Utxo>]
      def get_utxos(address)
        entries = api_get("/address/#{address}/unspent")
        return [] unless entries.is_a?(Array)

        utxos = entries.map do |e|
          Utxo.new(
            txid: e['tx_hash'],
            output_index: e['tx_pos'],
            satoshis: e['value'],
            script: ''
          )
        end
        # DoS-bound: defensive — WoC currently returns empty scripts but a
        # future enriched response must not bypass MAX_SCRIPT_BYTES.
        utxos.each do |u|
          next if u.script.nil? || u.script.empty?

          SDK.assert_script_hex_under_limit(
            u.script, SDK::MAX_SCRIPT_BYTES,
            "WhatsOnChainProvider.get_utxos(#{address})"
          )
        end
        utxos
      end

      # Find a contract UTXO by its script hash.
      #
      # @param script_hash [String] hex-encoded script hash
      # @return [Utxo, nil]
      def get_contract_utxo(script_hash)
        entries = api_get("/script/#{script_hash}/unspent")
        return nil unless entries.is_a?(Array) && !entries.empty?

        first = entries[0]
        utxo = Utxo.new(
          txid: first['tx_hash'],
          output_index: first['tx_pos'],
          satoshis: first['value'],
          script: ''
        )
        if utxo.script && !utxo.script.empty?
          SDK.assert_script_hex_under_limit(
            utxo.script, SDK::MAX_SCRIPT_BYTES,
            "WhatsOnChainProvider.get_contract_utxo(#{script_hash})"
          )
        end
        utxo
      rescue RuntimeError => e
        # 404 simply means no UTXO found
        return nil if e.message.include?('404')

        raise
      end

      # Return the network this provider is connected to.
      #
      # @return [String] 'mainnet' or 'testnet'
      def get_network
        @network
      end

      # Fetch the raw transaction hex by its txid.
      #
      # @param txid [String]
      # @return [String] hex-encoded raw transaction
      def get_raw_transaction(txid)
        uri = URI("#{@base_url}/tx/#{txid}/hex")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        response = http.request(Net::HTTP::Get.new(uri))
        unless response.is_a?(Net::HTTPSuccess)
          raise "WoC getRawTransaction failed (#{response.code}): #{response.body}"
        end

        response.body.strip
      end

      # Return the current fee rate in satoshis per kilobyte.
      #
      # BSV standard relay fee is 0.1 sat/byte (100 sat/KB).
      #
      # @return [Numeric]
      def get_fee_rate
        100
      end

      private

      # Perform an HTTP GET request against the WoC API and parse the JSON response.
      #
      # @param path [String] API path (appended to base_url)
      # @return [Object] parsed JSON response
      def api_get(path)
        uri = URI("#{@base_url}#{path}")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        response = http.request(Net::HTTP::Get.new(uri))
        unless response.is_a?(Net::HTTPSuccess)
          raise "WoC request failed (#{response.code}): #{response.body}"
        end

        JSON.parse(response.body)
      end
    end
  end
end
