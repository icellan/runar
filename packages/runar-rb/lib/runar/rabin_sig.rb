# frozen_string_literal: true

# Real Rabin signature verification for Runar contract testing.
#
# Rabin verification equation:
#   (sig^2 + padding) mod n === SHA256(msg) mod n
#
# where n is the Rabin public key (modulus), sig is the Rabin signature,
# and padding is a small adjustment value.
#
# All parameters are hex-encoded strings. sig, padding, and pubkey are
# interpreted as unsigned little-endian integers, matching Bitcoin Script's
# OP_MOD / OP_ADD behavior.

require 'digest'

module Runar
  module RabinSig
    # Verify a Rabin signature.
    #
    # All parameters are hex-encoded strings. sig, padding, and pubkey are
    # interpreted as unsigned little-endian integers.
    #
    # @param msg_hex   [String] hex-encoded message bytes
    # @param sig_hex   [String] hex-encoded signature (unsigned LE integer)
    # @param pad_hex   [String] hex-encoded padding (unsigned LE integer)
    # @param pubkey_hex [String] hex-encoded public key / modulus (unsigned LE integer)
    # @return [Boolean] true if the signature is valid
    #
    # --- No domain separation ---
    #
    # The message is hashed directly (SHA-256(msg)) without any domain prefix or
    # context tag. This is inherent to the Rabin signature scheme as used in
    # Bitcoin Script contracts: the locking script encodes the raw hash check,
    # so introducing a domain prefix would change the expected hash value and
    # break existing deployed contracts.
    #
    # The practical implication is that two different applications using the same
    # Rabin key could have cross-signature validity: a signature produced for
    # application A's message is also a valid Rabin signature for that same byte
    # sequence in application B. Callers are responsible for ensuring messages
    # are structurally distinct across use cases (e.g. by including a
    # contract-specific nonce or type tag in the message before signing).
    def self.rabin_verify(msg_hex, sig_hex, pad_hex, pubkey_hex)
      n = bytes_to_unsigned_le([pubkey_hex].pack('H*'))
      return false if n <= 0

      sig_int = bytes_to_unsigned_le([sig_hex].pack('H*'))
      pad_int = bytes_to_unsigned_le([pad_hex].pack('H*'))

      msg_bytes = [msg_hex].pack('H*')
      hash_bytes = Digest::SHA256.digest(msg_bytes)
      hash_int = bytes_to_unsigned_le(hash_bytes)

      lhs = (sig_int * sig_int + pad_int) % n
      rhs = hash_int % n
      lhs == rhs
    end

    # Interpret a binary string as an unsigned little-endian integer.
    def self.bytes_to_unsigned_le(bytes)
      result = 0
      bytes.each_byte.with_index { |b, i| result |= (b << (8 * i)) }
      result
    end
    private_class_method :bytes_to_unsigned_le
  end
end
