# frozen_string_literal: true

# WOTS+ (Winternitz One-Time Signature) reference implementation.
#
# RFC 8391 compatible with tweakable hash function F(pubSeed, ADRS, M).
#
# Parameters: w=16, n=32 (SHA-256).
#   len1 = 64  (message digits: 256 bits / 4 bits per digit)
#   len2 = 3   (checksum digits)
#   len  = 67  (total hash chains)
#
# Signature: 67 x 32 bytes = 2,144 bytes.
# Public key: 64 bytes (pubSeed(32) || pkRoot(32)).
#
# All inputs/outputs are hex-encoded strings, matching the Runar::Builtins
# interface convention for byte data.

require 'digest'
require 'securerandom'

module Runar
  module WOTS
    W     = 16
    N     = 32
    LOG_W = 4
    LEN1  = 64         # ceil(8*N / LOG_W) = 256/4
    LEN2  = 3          # floor(log2(LEN1*(W-1)) / LOG_W) + 1
    LEN   = LEN1 + LEN2 # 67

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    # Generate a WOTS+ keypair.
    #
    # @param seed_hex     [String, nil] optional deterministic seed (hex, 32 bytes)
    # @param pub_seed_hex [String, nil] optional public seed (hex, 32 bytes)
    # @return [Hash] { sk: [hex strings (67x)], pk: hex string, pub_seed: hex string }
    def self.keygen(seed_hex: nil, pub_seed_hex: nil)
      pub_seed_bytes = pub_seed_hex ? [pub_seed_hex].pack('H*') : SecureRandom.bytes(N)
      raise ArgumentError, "pub_seed must be #{N} bytes" if pub_seed_bytes.bytesize != N

      seed_bytes = seed_hex ? [seed_hex].pack('H*') : nil
      raise ArgumentError, "seed must be #{N} bytes" if seed_bytes && seed_bytes.bytesize != N

      sk_bytes = Array.new(LEN) do |i|
        if seed_bytes
          buf = seed_bytes + [i].pack('N') # big-endian 4-byte index
          Digest::SHA256.digest(buf)
        else
          SecureRandom.bytes(N)
        end
      end

      # Compute chain endpoints
      endpoints = String.new(capacity: LEN * N).b
      LEN.times do |i|
        endpoints << chain_bytes(sk_bytes[i], 0, W - 1, pub_seed_bytes, i)
      end

      pk_root = Digest::SHA256.digest(endpoints)
      pk_bytes = pub_seed_bytes + pk_root

      {
        sk:       sk_bytes.map { |b| b.unpack1('H*') },
        pk:       pk_bytes.unpack1('H*'),
        pub_seed: pub_seed_bytes.unpack1('H*')
      }
    end

    # Sign a message (hex) with the given sk (array of hex strings) and
    # pub_seed (hex string). Returns a hex-encoded signature.
    def self.sign(msg_hex, sk_hex, pub_seed_hex)
      msg_bytes      = [msg_hex].pack('H*')
      pub_seed_bytes = [pub_seed_hex].pack('H*')
      sk_bytes       = sk_hex.map { |s| [s].pack('H*') }

      msg_hash = Digest::SHA256.digest(msg_bytes)
      digits   = all_digits(msg_hash)

      sig = String.new(capacity: LEN * N).b
      LEN.times do |i|
        sig << chain_bytes(sk_bytes[i], 0, digits[i], pub_seed_bytes, i)
      end
      sig.unpack1('H*')
    end

    # Verify a WOTS+ signature. All arguments are hex strings.
    # Returns true/false.
    def self.verify(msg_hex, sig_hex, pk_hex)
      return false if msg_hex.nil? || sig_hex.nil? || pk_hex.nil?

      sig_bytes = hex_decode(sig_hex)
      pk_bytes  = hex_decode(pk_hex)
      return false if sig_bytes.nil? || pk_bytes.nil?
      return false if sig_bytes.bytesize != LEN * N
      return false if pk_bytes.bytesize  != 2 * N

      pub_seed = pk_bytes[0, N]
      pk_root  = pk_bytes[N, N]

      msg_bytes = hex_decode(msg_hex)
      return false if msg_bytes.nil?

      msg_hash = Digest::SHA256.digest(msg_bytes)
      digits   = all_digits(msg_hash)

      endpoints = String.new(capacity: LEN * N).b
      LEN.times do |i|
        sig_element = sig_bytes[i * N, N]
        remaining   = (W - 1) - digits[i]
        endpoints << chain_bytes(sig_element, digits[i], remaining, pub_seed, i)
      end

      computed_root = Digest::SHA256.digest(endpoints)
      computed_root == pk_root
    end

    # ------------------------------------------------------------------
    # Private helpers (byte-level)
    # ------------------------------------------------------------------

    # Tweakable hash F(pub_seed, chain_idx, step_idx, msg). All args are bytes.
    def self.f_hash(pub_seed, chain_idx, step_idx, msg)
      Digest::SHA256.digest(pub_seed + [chain_idx, step_idx].pack('CC') + msg)
    end
    private_class_method :f_hash

    # Iterate the tweakable hash `steps` times starting at `start_step`. Byte IO.
    def self.chain_bytes(x, start_step, steps, pub_seed, chain_idx)
      current = x
      (start_step...(start_step + steps)).each do |j|
        current = f_hash(pub_seed, chain_idx, j, current)
      end
      current
    end
    private_class_method :chain_bytes

    # Extract 64 base-16 digits from a 32-byte hash.
    def self.extract_digits(hash_hex_or_bytes)
      bytes = hash_hex_or_bytes.is_a?(String) && hash_hex_or_bytes.encoding != Encoding::ASCII_8BIT ? [hash_hex_or_bytes].pack('H*') : hash_hex_or_bytes
      digits = []
      bytes.each_byte do |b|
        digits << ((b >> 4) & 0x0F)
        digits << (b & 0x0F)
      end
      digits
    end
    private_class_method :extract_digits

    # Compute WOTS+ checksum digits.
    def self.checksum_digits(msg_digits)
      total = msg_digits.inject(0) { |acc, d| acc + ((W - 1) - d) }
      digits = Array.new(LEN2, 0)
      remaining = total
      (LEN2 - 1).downto(0) do |i|
        digits[i] = remaining % W
        remaining /= W
      end
      digits
    end
    private_class_method :checksum_digits

    # Returns all 67 digits: 64 message + 3 checksum.
    def self.all_digits(msg_hash_bytes)
      msg = extract_digits(msg_hash_bytes)
      msg + checksum_digits(msg)
    end
    private_class_method :all_digits

    # Safe hex decode: returns nil if the input isn't well-formed hex.
    def self.hex_decode(hex)
      return nil if hex.nil?
      return nil if hex.length.odd?
      return nil unless hex.match?(/\A[0-9a-fA-F]*\z/)

      [hex].pack('H*')
    end
    private_class_method :hex_decode
  end
end
