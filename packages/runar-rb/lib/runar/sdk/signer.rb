# frozen_string_literal: true

# Signer interface and implementations.
#
# A Signer abstracts private-key operations: signing transaction inputs and
# deriving the public key and address associated with the signing key.

module Runar
  module SDK
    # Abstract base class for signers.
    #
    # Subclasses must implement all abstract methods.
    class Signer
      # Return the hex-encoded compressed public key (66 hex chars).
      def get_public_key
        raise NotImplementedError, "#{self.class}#get_public_key is not implemented"
      end

      # Return the BSV address string.
      def get_address
        raise NotImplementedError, "#{self.class}#get_address is not implemented"
      end

      # Sign a transaction input and return the DER-encoded signature with the
      # sighash byte appended, hex-encoded.
      #
      # @param tx_hex       [String]       raw transaction hex
      # @param input_index  [Integer]      index of the input being signed
      # @param subscript    [String]       subscript (locking script) for BIP-143
      # @param satoshis     [Integer]      value of the input UTXO in satoshis
      # @param sighash_type [Integer, nil] sighash type (defaults to SIGHASH_ALL | SIGHASH_FORKID)
      # @return             [String]       DER + sighash byte, hex-encoded
      def sign(_tx_hex, _input_index, _subscript, _satoshis, _sighash_type = nil)
        raise NotImplementedError, "#{self.class}#sign is not implemented"
      end
    end

    # Deterministic signer for testing. Does not perform real cryptography.
    #
    #   signer = Runar::SDK::MockSigner.new
    #   signer.get_public_key  # => "0200...00" (66 hex chars)
    #   signer.sign(...)       # => "3000...0041" (72-byte mock DER signature)
    class MockSigner < Signer
      DEFAULT_PUB_KEY = ('02' + '00' * 32).freeze
      DEFAULT_ADDRESS = ('00' * 20).freeze

      def initialize(pub_key_hex: '', address: '')
        @pub_key = pub_key_hex.empty? ? DEFAULT_PUB_KEY : pub_key_hex
        @address = address.empty?     ? DEFAULT_ADDRESS  : address
      end

      def get_public_key
        @pub_key
      end

      def get_address
        @address
      end

      # Returns a deterministic 72-byte mock signature:
      # DER prefix (0x30) + 70 zero bytes + sighash byte (0x41).
      def sign(_tx_hex, _input_index, _subscript, _satoshis, _sighash_type = nil)
        '30' + ('00' * 70) + '41'
      end
    end

    # Callback-based signer that delegates to caller-provided Procs or lambdas.
    #
    # Useful for wrapping a real signing library without coupling the SDK to it:
    #
    #   signer = Runar::SDK::ExternalSigner.new(
    #     pub_key_hex: my_pub_key,
    #     address: my_address,
    #     sign_fn: ->(tx_hex, input_index, subscript, satoshis, sighash_type) {
    #       my_library.sign(tx_hex, input_index, subscript, satoshis, sighash_type)
    #     }
    #   )
    class ExternalSigner < Signer
      # @param pub_key_hex [String]   hex-encoded compressed public key
      # @param address     [String]   BSV address
      # @param sign_fn     [#call]    callable accepting (tx_hex, input_index, subscript,
      #                               satoshis, sighash_type) and returning a hex signature
      def initialize(pub_key_hex:, address:, sign_fn:)
        @pub_key = pub_key_hex
        @address = address
        @sign_fn = sign_fn
      end

      def get_public_key
        @pub_key
      end

      def get_address
        @address
      end

      def sign(tx_hex, input_index, subscript, satoshis, sighash_type = nil)
        @sign_fn.call(tx_hex, input_index, subscript, satoshis, sighash_type)
      end
    end
  end
end
