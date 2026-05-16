# frozen_string_literal: true

require 'digest'

require_relative '../ecdsa'
require_relative '../ec_primitives'
require_relative 'bip143'

# LocalSigner — private key held in memory.
#
# Priority:
#   1. If the +bsv-sdk+ gem is installed, use it (C-backed, fastest).
#   2. Otherwise, fall back to the bundled pure-Ruby ECDSA implementation
#      (+Runar::ECDSA+ + +Runar::SDK::BIP143+) which provides BIP-143 sighash
#      computation and RFC-6979 deterministic low-S signing.
#   3. Only raise +RuntimeError+ if neither path is usable (essentially never
#      — the fallback has no external dependencies).
#
# The public API does not change between modes:
#   LocalSigner.new(key_hex)
#   #get_public_key  -> compressed 66-hex-char public key
#   #get_address     -> Base58Check P2PKH address (mainnet)
#   #sign(tx_hex, input_index, subscript, satoshis, sighash_type = nil)

module Runar
  module SDK
    # Holds a secp256k1 private key in memory and produces DER-encoded ECDSA
    # signatures for transaction inputs using BIP-143 sighash.
    #
    # Suitable for CLI tooling and automated tests where a hot key is
    # acceptable.  For production wallets use {ExternalSigner} with a
    # hardware-wallet callback instead.
    #
    # @example
    #   signer = Runar::SDK::LocalSigner.new('...64-char hex key...')
    #   signer.get_public_key  #=> "03..." (66 hex chars)
    #   signer.get_address     #=> "1..."
    #   signer.sign(tx_hex, 0, subscript_hex, satoshis)
    class LocalSigner < Signer
      # Attempt to load the bsv-sdk gem once at class definition time.
      # We store the result in a constant so every instance can check it
      # without rescuing again.
      begin
        require 'bsv-sdk'
        BSV_SDK_AVAILABLE = true
      rescue LoadError
        BSV_SDK_AVAILABLE = false
      end

      # The pure-Ruby fallback only relies on stdlib + Runar's own ECDSA
      # module, so this constant is effectively always +true+.  It exists
      # so tests can stub it to exercise the "neither backend usable" path.
      FALLBACK_AVAILABLE = true

      # Default sighash flag: SIGHASH_ALL | SIGHASH_FORKID = 0x41 (BSV).
      SIGHASH_ALL_FORKID = 0x41

      # Create a LocalSigner from a hex-encoded private key.
      #
      # @param key_hex [String] 64-character hex private key
      # @raise [RuntimeError] when neither bsv-sdk nor the pure-Ruby fallback
      #                       is usable (essentially never)
      def initialize(key_hex)
        super()

        if BSV_SDK_AVAILABLE
          @backend = :bsv
          @private_key = BSV::Primitives::PrivateKey.from_hex(key_hex)
          @public_key  = @private_key.public_key
          return
        end

        if FALLBACK_AVAILABLE
          @backend = :fallback
          init_fallback(key_hex)
          return
        end

        raise 'LocalSigner: no signing backend available. ' \
              "Install the bsv-sdk gem (gem 'bsv-sdk') or restore the " \
              'bundled Runar::ECDSA fallback.'
      end

      # Return the hex-encoded compressed public key (66 chars).
      #
      # @return [String] compressed public key hex
      # rubocop:disable Naming/AccessorMethodName
      def get_public_key
        return @public_key.compressed.unpack1('H*') if @backend == :bsv

        @pub_key_hex
      end

      # Return the BSV mainnet P2PKH address for this key.
      #
      # @return [String] Base58Check address
      def get_address
        return @public_key.address if @backend == :bsv

        @address
      end
      # rubocop:enable Naming/AccessorMethodName

      # Sign a transaction input using BIP-143 sighash and real ECDSA.
      #
      # Returns the DER-encoded signature with the sighash byte appended,
      # hex-encoded.
      #
      # @param tx_hex       [String]       raw unsigned transaction hex
      # @param input_index  [Integer]      index of the input to sign
      # @param subscript    [String]       hex-encoded locking script (scriptCode)
      # @param satoshis     [Integer]      value of the UTXO being spent
      # @param sighash_type [Integer, nil] sighash flags (default: SIGHASH_ALL|FORKID = 0x41)
      # @return [String] DER + sighash byte, hex-encoded
      def sign(tx_hex, input_index, subscript, satoshis, sighash_type = nil)
        flag = sighash_type || default_sighash_flag

        if @backend == :bsv
          sign_with_bsv(tx_hex, input_index, subscript, satoshis, flag)
        else
          sign_with_fallback(tx_hex, input_index, subscript, satoshis, flag)
        end
      end

      private

      attr_reader :private_key

      # Default sighash flag: BSV's ALL|FORKID, taken from bsv-sdk when
      # available and otherwise the well-known constant 0x41.
      def default_sighash_flag
        return BSV::Transaction::Sighash::ALL_FORK_ID if @backend == :bsv

        SIGHASH_ALL_FORKID
      end

      # ---- bsv-sdk backend --------------------------------------------------

      # Attach source output data to the input, compute the sighash, and sign.
      def sign_with_bsv(tx_hex, input_index, subscript, satoshis, flag)
        tx = BSV::Transaction::Transaction.from_hex(tx_hex)
        locking_script = BSV::Script::Script.from_binary([subscript].pack('H*'))
        input = tx.inputs[input_index]
        input.source_satoshis = satoshis
        input.source_locking_script = locking_script

        hash = tx.sighash(input_index, flag, subscript: locking_script)
        (private_key.sign(hash).to_der + [flag].pack('C')).unpack1('H*')
      end

      # ---- pure-Ruby fallback backend --------------------------------------

      # Derive the compressed public key + P2PKH address from a hex private key.
      def init_fallback(key_hex)
        raise ArgumentError, "LocalSigner: expected 64-char hex private key, got #{key_hex.length} chars" \
          unless key_hex.length == 64
        raise ArgumentError, 'LocalSigner: private key contains non-hex characters' \
          unless key_hex.match?(/\A[0-9a-fA-F]+\z/)

        priv_int = key_hex.to_i(16)
        n = Runar::ECPrimitives::SECP256K1_N
        raise ArgumentError, 'LocalSigner: private key out of range [1, n-1]' \
          if priv_int < 1 || priv_int >= n

        @private_int = priv_int

        x, y = Runar::ECPrimitives.point_mul(
          priv_int,
          [Runar::ECPrimitives::SECP256K1_GX, Runar::ECPrimitives::SECP256K1_GY]
        )
        prefix = y.even? ? 0x02 : 0x03
        pub_key_bytes = [prefix].pack('C') + [x.to_s(16).rjust(64, '0')].pack('H*')
        @pub_key_hex = pub_key_bytes.unpack1('H*')

        # Mainnet P2PKH address: Base58Check(0x00 || HASH160(pubkey))
        sha = Digest::SHA256.digest(pub_key_bytes)
        pkh = OpenSSL::Digest.new('ripemd160').digest(sha)
        @address = BIP143.base58check_encode("\x00".b + pkh)
      end

      def sign_with_fallback(tx_hex, input_index, subscript, satoshis, flag)
        tx_bytes = [tx_hex].pack('H*')
        parsed = BIP143.parse_raw_tx(tx_bytes)

        if input_index >= parsed[:inputs].length
          raise ArgumentError,
                "LocalSigner: input index #{input_index} out of range " \
                "(tx has #{parsed[:inputs].length} inputs)"
        end

        subscript_bytes = [subscript].pack('H*')
        sighash = BIP143.bip143_sighash(parsed, input_index, subscript_bytes, satoshis.to_i, flag)

        der = Runar::ECDSA.ecdsa_sign(@private_int, sighash)
        der.unpack1('H*') + format('%02x', flag & 0xff)
      end
    end
  end
end
