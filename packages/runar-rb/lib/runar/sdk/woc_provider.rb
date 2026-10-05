# frozen_string_literal: true

require 'net/http'
require 'json'
require 'uri'
require 'digest'
require_relative 'provider'
require_relative 'types'
require_relative 'errors'
require_relative 'gorillapool_provider'

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
      # N-041: GET /tx/hash/{txid} has no "hex" field and reports values as
      # float BSV, so raw was always ''. The serialized tx is fetched via
      # GET /tx/{txid}/hex instead, its double-SHA256 must equal the txid, and
      # inputs/outputs (with integer satoshis) are parsed from those bytes.
      #
      # @param txid [String] transaction id (64 hex chars)
      # @return [TransactionData]
      def get_transaction(txid)
        fetch_verified_tx(txid, 'getTransaction')
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

      # Return all UTXOs for a given address, each with its real locking script.
      #
      # WoC's GET /address/{address}/unspent listing carries outpoints and
      # values but no locking script. The script is the BIP-143 scriptCode a
      # signer commits to, so an empty one yields signatures no OP_CHECKSIG
      # accepts (F-040). Each distinct txid is therefore fetched via
      # GET /tx/{txid}/hex, its double-SHA256 must equal the txid, and tx_pos
      # must be an output whose value equals the listed value. Any failure
      # raises; no UTXO is returned with an empty script.
      #
      # Note: WoC caps this legacy listing at about 1000 entries, so an
      # address holding more UTXOs is returned truncated.
      #
      # @param address [String] BSV address
      # @return [Array<Utxo>]
      def get_utxos(address)
        entries = api_get("/address/#{address}/unspent")
        return [] unless entries.is_a?(Array)

        txs = {}
        entries.map do |e|
          txid = e['tx_hash']
          tx_pos = e['tx_pos']
          value = e['value']
          txs[txid] ||= fetch_verified_tx(txid, 'getUtxos')
          outputs = txs[txid].outputs
          unless tx_pos.is_a?(Integer) && tx_pos >= 0 && tx_pos < outputs.length
            raise "WoC getUtxos: no output #{tx_pos} in tx #{txid} (#{outputs.length} outputs)"
          end

          out = outputs[tx_pos]
          unless out.satoshis == value
            raise "WoC getUtxos: value mismatch for #{txid}:#{tx_pos}: listing says #{value}, tx says #{out.satoshis}"
          end

          script = out.script
          raise "WoC getUtxos: empty locking script for #{txid}:#{tx_pos}" if script.empty?

          SDK.assert_script_hex_under_limit(
            script, SDK::MAX_SCRIPT_BYTES,
            "WhatsOnChainProvider.get_utxos(#{address})"
          )
          Utxo.new(txid: txid, output_index: tx_pos, satoshis: value, script: script)
        end
      end

      # Find a contract UTXO by its script hash, with its real locking script.
      #
      # N-041: WoC's GET /script/{scriptHash}/unspent listing (a legacy array,
      # or a {script, result} object on the /unspent/all family) carries
      # outpoints and values but no locking script. The first entry's tx is
      # fetched via GET /tx/{txid}/hex and hash-verified; tx_pos must be an
      # output whose value equals the listed value, whose script is non-empty
      # and hashes (sha256, reversed: WoC's scripthash) to script_hash. Any
      # failure raises.
      #
      # @param script_hash [String] hex-encoded script hash
      # @return [Utxo, nil]
      def get_contract_utxo(script_hash)
        begin
          listing = api_get("/script/#{script_hash}/unspent")
        rescue RuntimeError => e
          # 404 simply means no UTXO found
          return nil if e.message.include?('404')

          raise
        end
        entries = if listing.is_a?(Array)
                    listing
                  elsif listing.is_a?(Hash) && listing['result'].is_a?(Array)
                    listing['result']
                  else
                    raise "WoC getContractUtxo: unexpected listing shape for #{script_hash}"
                  end
        return nil if entries.empty?

        first = entries[0]
        txid = first['tx_hash']
        tx_pos = first['tx_pos']
        value = first['value']
        outputs = fetch_verified_tx(txid, 'getContractUtxo').outputs
        unless tx_pos.is_a?(Integer) && tx_pos >= 0 && tx_pos < outputs.length
          raise "WoC getContractUtxo: no output #{tx_pos} in tx #{txid} (#{outputs.length} outputs)"
        end

        out = outputs[tx_pos]
        unless out.satoshis == value
          raise "WoC getContractUtxo: value mismatch for #{txid}:#{tx_pos}: listing says #{value}, tx says #{out.satoshis}"
        end

        script = out.script
        raise "WoC getContractUtxo: empty locking script for #{txid}:#{tx_pos}" if script.empty?

        got = Digest::SHA256.digest([script].pack('H*')).reverse.unpack1('H*')
        unless got == script_hash.downcase
          raise "WoC getContractUtxo: script hash mismatch for #{txid}:#{tx_pos}: " \
                "output script hashes to #{got}, requested #{script_hash}"
        end

        SDK.assert_script_hex_under_limit(
          script, SDK::MAX_SCRIPT_BYTES,
          "WhatsOnChainProvider.get_contract_utxo(#{script_hash})"
        )
        Utxo.new(txid: txid, output_index: tx_pos, satoshis: value, script: script)
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

      # Fetch GET /tx/{txid}/hex and parse it, requiring the body to hash to
      # txid (F-040 / N-041). Parsed with GorillaPool's bounds-checked decoder
      # (F-027), which keeps scriptSigs and reads exact 8-byte values.
      #
      # @param txid [String]
      # @param context [String] caller name for error messages
      # @return [TransactionData]
      def fetch_verified_tx(txid, context)
        raw_hex = get_raw_transaction(txid)
        raise "WoC #{context}: /tx/#{txid}/hex body is not hex" unless raw_hex.match?(/\A(?:[0-9a-fA-F]{2})*\z/)

        raw = [raw_hex].pack('H*')
        body_txid = Digest::SHA256.digest(Digest::SHA256.digest(raw)).reverse.unpack1('H*')
        unless body_txid == txid.downcase
          raise "WoC #{context}: txid mismatch: /tx/#{txid}/hex body hashes to #{body_txid}"
        end

        begin
          GorillaPoolProvider.decode_raw_tx(body_txid, raw)
        rescue RuntimeError => e
          raise "WoC #{context}: parsing tx #{txid}: #{e.message}"
        end
      end

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
