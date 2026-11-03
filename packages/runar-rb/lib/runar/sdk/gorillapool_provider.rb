# frozen_string_literal: true

require 'net/http'
require 'json'
require 'digest'
require 'uri'
require_relative 'provider'
require_relative 'types'
require_relative 'errors'

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
        # Inscription content is served from the host root (/content/{outpoint}).
        @content_base_url = @base_url.delete_suffix('/api')
      end

      # -------------------------------------------------------------------
      # Standard Provider methods
      # -------------------------------------------------------------------

      # Fetch a TransactionData by its txid via GET /tx/{txid}/raw (the bare
      # serialized transaction). Each output's satoshis is read from its
      # 8-byte little-endian field, so values are exact (F-027: the former JSON
      # `vout[].value` decode with its `< 1000 -> BTC` guess targeted a field
      # GorillaPool never returns). The body must hash to the requested txid.
      #
      # @param txid [String] transaction id (64 hex chars)
      # @return [TransactionData]
      def get_transaction(txid)
        raw = fetch_verified_raw(txid, 'getTransaction')
        self.class.decode_raw_tx(txid.downcase, raw)
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
        # N-025: the documented Broadcast body is {"rawtx": string} (lowercase).
        request.body = JSON.generate(rawtx: raw_tx)

        response = http.request(request)
        unless response.is_a?(Net::HTTPSuccess)
          raise "GorillaPool broadcast failed (#{response.code}): #{response.body}"
        end

        result = JSON.parse(response.body)
        result.is_a?(String) ? result : (result['txid'] || '')
      end

      # N-025: GET /txos/address/{address}/unspent (Txo[]). The listing carries
      # no locking script, so each entry's tx is fetched via /tx/{txid}/raw
      # (hash-verified); the output must exist, its value must equal the
      # listing's, and its script is returned. Any non-2xx (404 included)
      # raises. N-159: entries whose `origin` is set (1-sat ordinal
      # inscriptions, BSV-20 / BSV-21 token outputs) are dropped before any
      # fetch -- spending one as a fee input destroys the inscription or
      # token. They remain available via get_inscriptions_by_address /
      # get_bsv20_utxos / get_bsv21_utxos.
      #
      # @param address [String] BSV address
      # @return [Array<Utxo>]
      def get_utxos(address)
        entries = api_get("/txos/address/#{address}/unspent", 'getUtxos')
        txs = {}
        entries.reject { |e| !e['origin'].nil? }.map do |e|
          txid = e['txid']
          vout = e['vout']
          tx = (txs[txid] ||= self.class.decode_raw_tx(txid.downcase, fetch_verified_raw(txid, 'getUtxos')))
          out = vout.is_a?(Integer) && vout >= 0 ? tx.outputs[vout] : nil
          if out.nil?
            raise "GorillaPool getUtxos: no output #{vout} in tx #{txid} (#{tx.outputs.length} outputs)"
          end
          unless out.satoshis == e['satoshis']
            raise "GorillaPool getUtxos: value mismatch for #{txid}_#{vout}: " \
                  "listing says #{e['satoshis']}, tx says #{out.satoshis}"
          end
          raise "GorillaPool getUtxos: empty locking script for #{txid}_#{vout}" if out.script.empty?

          SDK.assert_script_hex_under_limit(
            out.script, SDK::MAX_SCRIPT_BYTES,
            "GorillaPoolProvider.get_utxos(#{address})"
          )
          Utxo.new(txid: txid, output_index: vout, satoshis: out.satoshis, script: out.script)
        end
      end

      # N-025: the GorillaPool API has no documented route that looks UTXOs up
      # by script hash (the former /script/{hash}/utxos is a 404), so this
      # refuses rather than reporting "no UTXO".
      #
      # @param script_hash [String] hex-encoded script hash
      # @return [Utxo, nil]
      def get_contract_utxo(script_hash)
        raise "GorillaPool getContractUtxo(#{script_hash}): lookup by script hash " \
              'is not supported by the GorillaPool API'
      end

      # Return the network this provider is connected to.
      #
      # @return [String] 'mainnet' or 'testnet'
      def get_network
        @network
      end

      # N-025: GET /tx/{txid}/raw (binary), hash-verified, returned as hex.
      #
      # @param txid [String]
      # @return [String] hex-encoded raw transaction
      def get_raw_transaction(txid)
        fetch_verified_raw(txid, 'getRawTransaction').unpack1('H*')
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

      # N-025: inscriptions currently held by an address -- the unspent Txos
      # from GET /txos/address/{address}/unspent whose `origin` is set.
      #
      # @param address [String]
      # @return [Array<Hash>] {txid, vout, origin, contentType, contentLength, height}
      def get_inscriptions_by_address(address)
        entries = api_get("/txos/address/#{address}/unspent", 'getInscriptionsByAddress')
        entries.reject { |t| t['origin'].nil? }.map { |t| inscription_info(t) }
      end

      # N-025: GET /inscriptions/{outpoint} returns a Txo (not a content
      # record). The content is GET /content/{outpoint} (host root), and its
      # base64 sha256 must equal origin.data.insc.file.hash.
      #
      # @param inscription_id [String] format: "<txid>_<vout>"
      # @return [Hash] inscription info plus 'data' (hex content)
      def get_inscription(inscription_id)
        t = api_get("/inscriptions/#{inscription_id}", 'getInscription')
        if !t.is_a?(Hash) || t['origin'].nil?
          raise "GorillaPool getInscription: #{inscription_id} is not an inscription (no origin)"
        end

        info = inscription_info(t)
        content = http_get_bytes("#{@content_base_url}/content/#{inscription_id}", 'getInscription content')
        want = t.dig('origin', 'data', 'insc', 'file', 'hash')
        got = [Digest::SHA256.digest(content)].pack('m0')
        if want.nil? || got != want
          raise "GorillaPool getInscription: content hash mismatch for #{inscription_id}: " \
                "sha256 #{got}, inscription says #{want || '(none)'}"
        end
        info.merge('data' => content.unpack1('H*'))
      end

      # N-025: BSV-20 (v1, tick-based) confirmed balance, from
      # GET /bsv20/{address}/balance. No entry for the tick means "0".
      #
      # @param address [String]
      # @param tick [String]
      # @return [String] balance
      def get_bsv20_balance(address, tick)
        rows = api_get("/bsv20/#{address}/balance", 'getBSV20Balance')
        row = rows.find { |r| r['tick'] == tick }
        row ? row['all']['confirmed'].to_s : '0'
      end

      # N-025: BSV-20 token UTXOs, from GET /bsv20/{address}/tick/{tick}.
      #
      # @param address [String]
      # @param tick [String]
      # @return [Array<Utxo>]
      def get_bsv20_utxos(address, tick)
        rows = api_get("/bsv20/#{address}/tick/#{URI.encode_www_form_component(tick)}", 'getBSV20Utxos')
        rows.map { |r| bsv20_utxo(r, 'getBSV20Utxos') }
      end

      # N-025: BSV-21 (v2, ID-based) confirmed balance, from
      # GET /bsv20/{address}/balance. No entry for the id means "0".
      #
      # @param address [String]
      # @param id [String] token ID (format: "<txid>_<vout>")
      # @return [String] balance
      def get_bsv21_balance(address, id)
        rows = api_get("/bsv20/#{address}/balance", 'getBSV21Balance')
        row = rows.find { |r| r['id'] == id }
        row ? row['all']['confirmed'].to_s : '0'
      end

      # N-025: BSV-21 token UTXOs, from GET /bsv20/{address}/id/{id}.
      #
      # @param address [String]
      # @param id [String] token ID (format: "<txid>_<vout>")
      # @return [Array<Utxo>]
      def get_bsv21_utxos(address, id)
        rows = api_get("/bsv20/#{address}/id/#{URI.encode_www_form_component(id)}", 'getBSV21Utxos')
        rows.map { |r| bsv20_utxo(r, 'getBSV21Utxos') }
      end

      private

      # GET {url}; any non-2xx (a 404 included) raises. Returns the body bytes.
      #
      # @param url [String]
      # @param method [String] name used in the error message
      # @return [String] response body bytes (ASCII-8BIT)
      def http_get_bytes(url, method)
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        response = http.request(Net::HTTP::Get.new(uri))
        unless response.is_a?(Net::HTTPSuccess)
          raise "GorillaPool #{method} failed (#{response.code}): #{response.body}"
        end

        response.body.b
      end

      # Perform an HTTP GET request and return the raw (binary) response body.
      #
      # @param path [String] API path (appended to base_url)
      # @param method [String] name used in the error message
      # @return [String] response body bytes (ASCII-8BIT)
      def api_get_raw(path, method = 'getTransaction')
        http_get_bytes("#{@base_url}#{path}", method)
      end

      # GET /tx/{txid}/raw; the body must hash (sha256d, reversed) to txid.
      def fetch_verified_raw(txid, method)
        raw = api_get_raw("/tx/#{txid}/raw", method)
        body_txid = Digest::SHA256.digest(Digest::SHA256.digest(raw)).reverse.unpack1('H*')
        unless body_txid == txid.downcase
          raise "GorillaPool #{method}: txid mismatch: response body hashes to #{body_txid}, requested #{txid}"
        end

        raw
      end

      def inscription_info(t)
        file = t.dig('origin', 'data', 'insc', 'file') || {}
        {
          'txid' => t['txid'], 'vout' => t['vout'], 'origin' => t['origin']['outpoint'],
          'contentType' => file['type'] || '', 'contentLength' => file['size'] || 0,
          'height' => t['height'] || 0
        }
      end

      def bsv20_utxo(r, method)
        script = r['script'].is_a?(String) ? r['script'].unpack1('m').unpack1('H*') : ''
        raise "GorillaPool #{method}: no locking script for #{r['txid']}_#{r['vout']}" if script.empty?

        SDK.assert_script_hex_under_limit(script, SDK::MAX_SCRIPT_BYTES, "GorillaPoolProvider.#{method}")
        Utxo.new(txid: r['txid'], output_index: r['vout'], satoshis: r['satoshis'], script: script)
      end

      # Decode a serialized transaction into TransactionData, keeping the input
      # scripts. The SDK's other raw-tx parsers (Bip143 / OpPushTx) discard
      # scriptSigs, so this one is local. A class method so
      # WhatsOnChainProvider can share it (N-041).
      #
      # @param txid [String]
      # @param raw [String] binary transaction bytes
      # @return [TransactionData]
      def self.decode_raw_tx(txid, raw)
        pos = 0
        read = lambda do |n|
          raise 'GorillaPool getTransaction: truncated transaction' if pos + n > raw.bytesize

          chunk = raw.byteslice(pos, n)
          pos += n
          chunk
        end
        read_varint = lambda do
          first = read.call(1).unpack1('C')
          case first
          when 0xFD then read.call(2).unpack1('v')
          when 0xFE then read.call(4).unpack1('V')
          when 0xFF then read.call(8).unpack1('Q<')
          else first
          end
        end

        version = read.call(4).unpack1('V')
        inputs = Array.new(read_varint.call) do
          prev_txid = read.call(32).reverse.unpack1('H*')
          prev_index = read.call(4).unpack1('V')
          script = read.call(read_varint.call).unpack1('H*')
          TxInput.new(txid: prev_txid, output_index: prev_index, script: script,
                      sequence: read.call(4).unpack1('V'))
        end
        outputs = Array.new(read_varint.call) do
          satoshis = read.call(8).unpack1('Q<')
          TxOutput.new(satoshis: satoshis, script: read.call(read_varint.call).unpack1('H*'))
        end
        locktime = read.call(4).unpack1('V')
        raise 'GorillaPool getTransaction: trailing bytes after transaction' unless pos == raw.bytesize

        TransactionData.new(txid: txid, version: version, inputs: inputs, outputs: outputs,
                            locktime: locktime, raw: raw.unpack1('H*'))
      end

      # Perform an HTTP GET request against the GorillaPool API and parse the
      # JSON response. Any non-2xx (a 404 included) raises.
      #
      # @param path [String] API path (appended to base_url)
      # @param method [String] name used in the error message
      # @return [Object] parsed JSON response
      def api_get(path, method = 'request')
        JSON.parse(http_get_bytes("#{@base_url}#{path}", method).force_encoding('UTF-8'))
      end
    end
  end
end
