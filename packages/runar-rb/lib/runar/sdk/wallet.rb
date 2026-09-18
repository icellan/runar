# frozen_string_literal: true

require 'digest'
require 'json'
require 'uri'

# BRC-100 Wallet integration for the Runar Ruby SDK.
#
# Provides a WalletClient abstraction, a WalletProvider (Provider backed by
# a BRC-100 wallet), and a WalletSigner (Signer backed by a BRC-100 wallet).
#
# WalletClient is the abstract base class that wraps the four wallet
# operations required by the BRC-100 standard:
#   - get_public_key   — derive a public key from protocol + key IDs
#   - create_signature — sign a pre-hashed digest
#   - create_action    — create and broadcast a wallet-funded transaction
#   - list_outputs     — enumerate UTXOs in a basket
#
# WalletProvider adapts a WalletClient into the Runar SDK Provider interface
# so existing RunarContract deploy/call flows work seamlessly.
#
# WalletSigner adapts a WalletClient into the Runar SDK Signer interface,
# computing the BIP-143 sighash locally and delegating signing to the wallet.

require 'digest'
require_relative 'types'
require_relative 'provider'
require_relative 'signer'
require_relative 'deployment'
require_relative 'oppushtx'
require_relative 'state'

module Runar
  module SDK
    # Abstract BRC-100 wallet client.
    #
    # Subclasses must implement all four methods. In practice, the concrete
    # implementation talks to a BRC-100 compatible wallet (e.g. via HTTP,
    # browser extension bridge, or in-process SDK).
    #
    # @example
    #   class MyAppWallet < Runar::SDK::WalletClient
    #     def get_public_key(protocol_id:, key_id:)
    #       # call real wallet ...
    #     end
    #     # ...
    #   end
    class WalletClient
      # Derive a compressed public key for the given protocol + key pair.
      #
      # @param protocol_id [Array] BRC-100 protocol ID tuple, e.g. [2, 'my app']
      # @param key_id      [String] key derivation identifier, e.g. '1'
      # @return [String] hex-encoded compressed public key (66 hex chars)
      def get_public_key(protocol_id:, key_id:)
        raise NotImplementedError, "#{self.class}#get_public_key is not implemented"
      end

      # Sign a pre-hashed digest with the wallet's derived key.
      #
      # The wallet signs the hash directly (no additional hashing).
      #
      # @param hash_to_sign [String] hex-encoded hash to sign directly
      # @param protocol_id  [Array]  BRC-100 protocol ID tuple
      # @param key_id       [String] key derivation identifier
      # @return [String] DER-encoded signature as hex
      def create_signature(hash_to_sign:, protocol_id:, key_id:)
        raise NotImplementedError, "#{self.class}#create_signature is not implemented"
      end

      # Create a wallet-funded transaction with the specified outputs.
      #
      # The wallet selects inputs, computes the fee, signs, and broadcasts
      # the transaction internally.
      #
      # @param description [String] human-readable action description
      # @param outputs     [Array<Hash>] output specifications, each with
      #   :locking_script (hex), :satoshis (Integer), and optional
      #   :output_description (String), :basket (String), :tags (Array<String>)
      # @return [Hash] result with :txid (String) and optional :raw_tx (String)
      def create_action(description:, outputs:)
        raise NotImplementedError, "#{self.class}#create_action is not implemented"
      end

      # List spendable outputs in a wallet basket.
      #
      # @param basket [String] basket name
      # @param tags   [Array<String>] filter tags (default: [])
      # @param limit  [Integer] maximum number of outputs to return (default: 100)
      # @return [Array<Hash>] output records, each with :outpoint (String "txid.vout"),
      #   :satoshis (Integer), :locking_script (String hex), :spendable (Boolean)
      def list_outputs(basket:, tags: [], limit: 100)
        raise NotImplementedError, "#{self.class}#list_outputs is not implemented"
      end
    end

    # BRC-100 wallet-backed Provider.
    #
    # Adapts a WalletClient into the Runar SDK Provider interface. UTXOs are
    # fetched from the wallet's basket via +list_outputs+. Broadcast is
    # handled by the wallet's +create_action+ or by submitting raw hex to
    # an ARC endpoint.
    #
    # @example
    #   wallet  = MyAppWallet.new
    #   signer  = Runar::SDK::WalletSigner.new(wallet: wallet, protocol_id: [2, 'app'], key_id: '1')
    #   provider = Runar::SDK::WalletProvider.new(
    #     wallet: wallet, signer: signer, basket: 'my-app'
    #   )
    #   contract.connect(provider, signer)
    class WalletProvider < Provider
      # The default ARC broadcaster. A MAINNET endpoint — see R-179.
      MAINNET_ARC_URL = 'https://arc.gorillapool.io'

      DEFAULT_FEE_RATE = 100

      attr_reader :wallet, :basket

      # @param wallet       [WalletClient]   BRC-100 wallet instance
      # @param signer       [Signer]         signer derived from the same wallet
      # @param basket       [String]         wallet basket name for UTXO management
      # @param funding_tag  [String]         tag for funding UTXOs (default: 'funding')
      # @param arc_url      [String, nil]    ARC endpoint; REQUIRED unless network is 'mainnet' (R-179)
      # @param network      [String]         'mainnet' or 'testnet' (default: 'mainnet')
      # @param fee_rate     [Integer]        satoshis per kilobyte (default: 100)
      def initialize(wallet:, signer:, basket:, funding_tag: 'funding',
                     arc_url: nil, overlay_url: nil,
                     network: 'mainnet', fee_rate: DEFAULT_FEE_RATE)
        @wallet      = wallet
        @signer      = signer
        @basket      = basket
        @funding_tag = funding_tag
        # R-179: arc_url and network used to be defaulted independently, so a
        # provider configured for testnet reported get_network == 'testnet' and
        # broadcast every transaction to the MAINNET ARC. There is no canonical
        # testnet ARC endpoint to default to, so a non-mainnet provider has to
        # name its own instead of inheriting one that points at real money.
        @arc_url =
          if arc_url
            arc_url
          elsif network == 'mainnet'
            MAINNET_ARC_URL
          else
            raise ArgumentError,
                  "WalletProvider: no default ARC endpoint for network #{network.inspect} — " \
                  "#{MAINNET_ARC_URL} is a MAINNET broadcaster. Pass arc_url explicitly."
          end
        @overlay_url = overlay_url
        @network     = network
        @fee_rate    = fee_rate
        @tx_cache    = {}
      end

      # Cache a raw transaction hex by its txid.
      #
      # @param txid    [String]
      # @param raw_hex [String]
      def cache_tx(txid, raw_hex)
        @tx_cache[txid] = raw_hex
      end

      # -- Provider interface ---------------------------------------------------

      def get_transaction(txid)
        raw = @tx_cache[txid]
        raise "WalletProvider: transaction #{txid} not found in cache" unless raw

        TransactionData.new(txid: txid, version: 1, raw: raw)
      end

      def get_raw_transaction(txid)
        return @tx_cache[txid] if @tx_cache.key?(txid)

        # Try overlay service if configured
        if @overlay_url
          begin
            require 'net/http'
            uri = URI("#{@overlay_url}/api/tx/#{txid}/hex")
            resp = Net::HTTP.get_response(uri)
            if resp.is_a?(Net::HTTPSuccess)
              raw = resp.body.strip
              @tx_cache[txid] = raw
              return raw
            end
          rescue StandardError
            # Overlay unreachable
          end
        end

        raise "WalletProvider: raw transaction #{txid} not found in cache or overlay"
      end

      def broadcast(raw_tx)
        raw_bytes = [raw_tx].pack('H*')
        # Compute txid locally as fallback
        txid = Digest::SHA256.hexdigest(Digest::SHA256.digest(raw_bytes))
        txid = [txid].pack('H*').reverse.unpack1('H*')

        # POST to ARC as application/octet-stream
        begin
          require 'net/http'
          uri = URI("#{@arc_url}/v1/tx")
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == 'https'
          http.open_timeout = 10
          http.read_timeout = 30
          req = Net::HTTP::Post.new(uri.path)
          req['Content-Type'] = 'application/octet-stream'
          req.body = raw_bytes
          resp = http.request(req)
          if resp.is_a?(Net::HTTPSuccess)
            json = JSON.parse(resp.body) rescue {}
            txid = json['txid'] if json['txid']
          end
        rescue StandardError
          # ARC unreachable — use locally computed txid
        end

        @tx_cache[txid] = raw_tx
        txid
      end

      def get_utxos(_address)
        outputs = @wallet.list_outputs(
          basket: @basket,
          tags: [@funding_tag],
          limit: 100
        )

        expected_pub_key = @signer.get_public_key
        expected_script  = SDK.build_p2pkh_script(expected_pub_key)

        utxos = []
        Array(outputs).each do |out|
          next unless out[:spendable] || out['spendable']

          locking_script = out[:locking_script] || out['locking_script'] || ''
          next unless locking_script == expected_script || locking_script.empty?

          outpoint = out[:outpoint] || out['outpoint'] || ''
          txid, vout_str = outpoint.split('.')
          next unless txid && vout_str

          satoshis = out[:satoshis] || out['satoshis'] || 0

          utxos << Utxo.new(
            txid: txid,
            output_index: vout_str.to_i,
            satoshis: satoshis,
            script: locking_script
          )
        end

        utxos
      end

      def get_contract_utxo(_script_hash)
        nil
      end

      def get_network
        @network
      end

      def get_fee_rate
        @fee_rate
      end
    end

    # BRC-100 wallet-backed Signer.
    #
    # Computes the BIP-143 sighash locally from the raw transaction, then
    # delegates ECDSA signing to the WalletClient's +create_signature+
    # method, which signs the pre-hashed digest directly.
    #
    # @example
    #   signer = Runar::SDK::WalletSigner.new(
    #     wallet: wallet, protocol_id: [2, 'app'], key_id: '1'
    #   )
    #   signer.get_public_key  #=> "03..."
    #   signer.sign(tx_hex, 0, subscript, satoshis)
    class WalletSigner < Signer
      # @param wallet      [WalletClient] BRC-100 wallet instance
      # @param protocol_id [Array]        BRC-100 protocol ID tuple, e.g. [2, 'my app']
      # @param key_id      [String]       key derivation identifier, e.g. '1'
      def initialize(wallet:, protocol_id:, key_id:)
        @wallet      = wallet
        @protocol_id = protocol_id
        @key_id      = key_id
        @cached_pub_key = nil
      end

      def get_public_key
        return @cached_pub_key if @cached_pub_key

        @cached_pub_key = @wallet.get_public_key(
          protocol_id: @protocol_id,
          key_id: @key_id
        )
      end

      def get_address
        pub_key_hex = get_public_key
        # hash160 of the compressed public key = 40-char hex pub key hash
        pub_key_bytes = [pub_key_hex].pack('H*')
        sha = Digest::SHA256.digest(pub_key_bytes)
        ripemd = Digest::RMD160.digest(sha)
        ripemd.unpack1('H*')
      end

      # Sign a transaction input via the BRC-100 wallet.
      #
      # Computes the BIP-143 sighash locally, then sends the double-SHA256
      # digest to the wallet for ECDSA signing via +create_signature+.
      #
      # @param tx_hex       [String]       raw transaction hex
      # @param input_index  [Integer]      index of the input being signed
      # @param subscript    [String]       hex-encoded subscript (locking script)
      # @param satoshis     [Integer]      value of the input UTXO in satoshis
      # @param sighash_type [Integer, nil] sighash type (default: SIGHASH_ALL|FORKID = 0x41)
      # @return [String] DER + sighash byte, hex-encoded
      def sign(tx_hex, input_index, subscript, satoshis, sighash_type = nil)
        sighash_type ||= SIGHASH_ALL_FORKID

        # 1. Compute BIP-143 preimage
        preimage_hex = SDK.compute_preimage(tx_hex, input_index, subscript, satoshis, sighash_type)

        # 2. Double-SHA256 → sighash
        sighash_hex = SDK.double_sha256(preimage_hex)

        # 3. Delegate to wallet for signing (wallet signs the hash directly)
        der_sig_hex = @wallet.create_signature(
          hash_to_sign: sighash_hex,
          protocol_id: @protocol_id,
          key_id: @key_id
        )

        # 4. Append sighash type byte
        der_sig_hex + format('%02x', sighash_type)
      end

      # Sign a pre-computed sighash directly, without computing BIP-143.
      #
      # Useful for multi-signer flows where the sighash has already been
      # computed by +prepare_call+.
      #
      # @param sighash_hex [String] pre-computed sighash as hex
      # @return [String] DER-encoded signature hex (without sighash flag byte)
      def sign_hash(sighash_hex)
        @wallet.create_signature(
          hash_to_sign: sighash_hex,
          protocol_id: @protocol_id,
          key_id: @key_id
        )
      end
    end
  end
end
