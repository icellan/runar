# frozen_string_literal: true

require 'net/http'
require 'json'
require 'uri'
require_relative 'provider'
require_relative 'types'

# GorillaPoolProvider -- HTTP-based BSV provider for 1sat Ordinals.
#
# Implements the Provider interface plus ordinal-specific methods for
# querying inscriptions, BSV-20/BSV-21 balances, and token UTXOs.
#
# Endpoints:
#   Mainnet: https://ordinals.gorillapool.io/api/
#   Testnet: https://testnet.ordinals.gorillapool.io/api/
#
#   provider = Runar::SDK::GorillaPoolProvider.new(network: 'mainnet')
#   utxos = provider.get_utxos('1A1zP1eP...')

module Runar
  module SDK
    class GorillaPoolProvider < Provider
      # @param network [String] 'mainnet' or 'testnet'
      def initialize(network: 'mainnet')
        @network = network
        @base_url = if network == 'mainnet'
                      'https://ordinals.gorillapool.io/api'
                    else
                      'https://testnet.ordinals.gorillapool.io/api'
                    end
      end

      # -------------------------------------------------------------------
      # Standard Provider methods
      # -------------------------------------------------------------------

      # Fetch a TransactionData by its txid.
      #
      # @param txid [String] transaction id (64 hex chars)
      # @return [TransactionData]
      def get_transaction(txid)
        data = api_get("/tx/#{txid}")

        inputs = Array(data['vin']).map do |vin|
          TxInput.new(
            txid: vin['txid'],
            output_index: vin['vout'],
            script: vin.dig('scriptSig', 'hex') || '',
            sequence: vin['sequence'] || 0xFFFFFFFF
          )
        end

        outputs = Array(data['vout']).map do |vout|
          satoshis = vout['value'].is_a?(Numeric) && vout['value'] < 1000 ? (vout['value'] * 1e8).round : vout['value']
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
        uri = URI("#{@base_url}/tx")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        request = Net::HTTP::Post.new(uri)
        request['Content-Type'] = 'application/json'
        request.body = JSON.generate(rawTx: raw_tx)

        response = http.request(request)
        unless response.is_a?(Net::HTTPSuccess)
          raise "GorillaPool broadcast failed (#{response.code}): #{response.body}"
        end

        result = JSON.parse(response.body)
        result.is_a?(String) ? result : (result['txid'] || '')
      end

      # Return all UTXOs for a given address.
      #
      # @param address [String] BSV address
      # @return [Array<Utxo>]
      def get_utxos(address)
        entries = api_get("/address/#{address}/utxos")
        return [] unless entries.is_a?(Array)

        entries.map do |e|
          Utxo.new(
            txid: e['txid'],
            output_index: e['vout'],
            satoshis: e['satoshis'],
            script: e['script'] || ''
          )
        end
      rescue RuntimeError => e
        return [] if e.message.include?('404')

        raise
      end

      # Find a contract UTXO by its script hash.
      #
      # @param script_hash [String] hex-encoded script hash
      # @return [Utxo, nil]
      def get_contract_utxo(script_hash)
        entries = api_get("/script/#{script_hash}/utxos")
        return nil unless entries.is_a?(Array) && !entries.empty?

        first = entries[0]
        Utxo.new(
          txid: first['txid'],
          output_index: first['vout'],
          satoshis: first['satoshis'],
          script: first['script'] || ''
        )
      rescue RuntimeError => e
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
          raise "GorillaPool getRawTransaction failed (#{response.code}): #{response.body}"
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

      # -------------------------------------------------------------------
      # Ordinal-specific methods
      # -------------------------------------------------------------------

      # Get all inscriptions associated with an address.
      #
      # @param address [String]
      # @return [Array<Hash>] inscription info hashes
      def get_inscriptions_by_address(address)
        entries = api_get("/inscriptions/address/#{address}")
        return [] unless entries.is_a?(Array)

        entries
      rescue RuntimeError => e
        return [] if e.message.include?('404')

        raise
      end

      # Get inscription details (including content) by inscription ID.
      #
      # @param inscription_id [String] format: "<txid>_<vout>"
      # @return [Hash] inscription detail hash
      def get_inscription(inscription_id)
        api_get("/inscriptions/#{inscription_id}")
      end

      # Get BSV-20 (v1, tick-based) token balance for an address.
      #
      # @param address [String]
      # @param tick [String]
      # @return [String] balance
      def get_bsv20_balance(address, tick)
        result = api_get("/bsv20/balance/#{address}/#{URI.encode_www_form_component(tick)}")
        result.is_a?(String) ? result : (result['balance'] || '0').to_s
      rescue RuntimeError => e
        return '0' if e.message.include?('404')

        raise
      end

      # Get BSV-20 token UTXOs for an address and ticker.
      #
      # @param address [String]
      # @param tick [String]
      # @return [Array<Utxo>]
      def get_bsv20_utxos(address, tick)
        entries = api_get("/bsv20/utxos/#{address}/#{URI.encode_www_form_component(tick)}")
        return [] unless entries.is_a?(Array)

        entries.map do |e|
          Utxo.new(
            txid: e['txid'],
            output_index: e['vout'],
            satoshis: e['satoshis'],
            script: e['script'] || ''
          )
        end
      rescue RuntimeError => e
        return [] if e.message.include?('404')

        raise
      end

      # Get BSV-21 (v2, ID-based) token balance for an address.
      #
      # @param address [String]
      # @param id [String] token ID (format: "<txid>_<vout>")
      # @return [String] balance
      def get_bsv21_balance(address, id)
        result = api_get("/bsv20/balance/#{address}/#{URI.encode_www_form_component(id)}")
        result.is_a?(String) ? result : (result['balance'] || '0').to_s
      rescue RuntimeError => e
        return '0' if e.message.include?('404')

        raise
      end

      # Get BSV-21 token UTXOs for an address and token ID.
      #
      # @param address [String]
      # @param id [String] token ID (format: "<txid>_<vout>")
      # @return [Array<Utxo>]
      def get_bsv21_utxos(address, id)
        entries = api_get("/bsv20/utxos/#{address}/#{URI.encode_www_form_component(id)}")
        return [] unless entries.is_a?(Array)

        entries.map do |e|
          Utxo.new(
            txid: e['txid'],
            output_index: e['vout'],
            satoshis: e['satoshis'],
            script: e['script'] || ''
          )
        end
      rescue RuntimeError => e
        return [] if e.message.include?('404')

        raise
      end

      private

      # Perform an HTTP GET request against the GorillaPool API and parse the JSON response.
      #
      # @param path [String] API path (appended to base_url)
      # @return [Object] parsed JSON response
      def api_get(path)
        uri = URI("#{@base_url}#{path}")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        response = http.request(Net::HTTP::Get.new(uri))
        unless response.is_a?(Net::HTTPSuccess)
          raise "GorillaPool request failed (#{response.code}): #{response.body}"
        end

        JSON.parse(response.body)
      end
    end
  end
end
