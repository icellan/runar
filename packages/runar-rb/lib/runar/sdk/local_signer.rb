# frozen_string_literal: true

# LocalSigner — private key held in memory, signing via the bsv-sdk gem.
#
# Requires the +bsv-sdk+ gem to be installed:
#
#   gem 'bsv-sdk'
#
# If bsv-sdk is not available the class can still be required; attempting to
# instantiate it will raise a RuntimeError with an install hint.  This keeps
# the lazy-load pattern consistent with the Python implementation.

module Runar
  module SDK
    # Holds a secp256k1 private key in memory and delegates real ECDSA signing
    # to the bsv-sdk gem.
    #
    # Suitable for CLI tooling and automated tests where a hot key is acceptable.
    # For production wallets consider ExternalSigner with a hardware-wallet
    # callback instead.
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

      # Create a LocalSigner from a hex-encoded private key.
      #
      # @param key_hex [String] 64-character hex private key
      # @raise [RuntimeError] when the bsv-sdk gem is not installed
      def initialize(key_hex)
        super()
        unless BSV_SDK_AVAILABLE
          raise 'LocalSigner requires the bsv-sdk gem. ' \
                "Add it to your Gemfile: gem 'bsv-sdk'"
        end

        @private_key = BSV::Primitives::PrivateKey.from_hex(key_hex)
        @public_key  = @private_key.public_key
      end

      # Return the hex-encoded compressed public key (66 chars).
      #
      # @return [String] compressed public key hex
      # rubocop:disable Naming/AccessorMethodName
      def get_public_key
        @public_key.compressed.unpack1('H*')
      end

      # Return the BSV mainnet P2PKH address for this key.
      #
      # @return [String] Base58Check address
      def get_address
        @public_key.address
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
        flag = sighash_type || BSV::Transaction::Sighash::ALL_FORK_ID
        build_signature(tx_hex, input_index, subscript, satoshis, flag)
      end

      private

      attr_reader :private_key

      # Attach source output data to the input, compute the sighash, and sign.
      def build_signature(tx_hex, input_index, subscript, satoshis, flag)
        tx = BSV::Transaction::Transaction.from_hex(tx_hex)
        locking_script = BSV::Script::Script.from_binary([subscript].pack('H*'))
        input = tx.inputs[input_index]
        input.source_satoshis = satoshis
        input.source_locking_script = locking_script

        hash = tx.sighash(input_index, flag, subscript: locking_script)
        (private_key.sign(hash).to_der + [flag].pack('C')).unpack1('H*')
      end
    end
  end
end
