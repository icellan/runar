# frozen_string_literal: true

require 'digest'
require 'openssl'
require_relative 'ec_primitives'

# Real ECDSA signing and verification for Runar contract testing.
#
# Uses the pure-Ruby secp256k1 implementation from Runar::ECPrimitives to
# perform real ECDSA operations. Signing uses RFC 6979 deterministic k for
# reproducibility across all four compiler runtimes (TS, Go, Rust, Python).
#
# TEST_MESSAGE is the UTF-8 encoding of "runar-test-message-v1" (21 bytes).
# The ECDSA digest is SHA256(TEST_MESSAGE):
#   ee5e6c74a298854942a9eadd789f2812b38936691230134ad50b884cc1f119fa
module Runar
  # Real secp256k1 ECDSA signing and verification.
  # See the module-level file comment for full documentation.
  # rubocop:disable Metrics/ModuleLength
  module ECDSA
    include ECPrimitives

    # secp256k1 constants — re-exported for convenience.
    CURVE_P  = ECPrimitives::SECP256K1_P
    CURVE_N  = ECPrimitives::SECP256K1_N
    CURVE_GX = ECPrimitives::SECP256K1_GX
    CURVE_GY = ECPrimitives::SECP256K1_GY

    # The canonical test message shared across all Runar SDKs.
    TEST_MESSAGE        = 'runar-test-message-v1'
    TEST_MESSAGE_DIGEST = Digest::SHA256.digest(TEST_MESSAGE)

    module_function

    # ---------------------------------------------------------------------------
    # Public API helpers
    # ---------------------------------------------------------------------------

    # Sign the fixed TEST_MESSAGE with a private key.
    #
    # Returns a hex-encoded DER ECDSA signature. The result is deterministic
    # (RFC 6979) and matches the Python/TypeScript SDK output for the same key.
    #
    # @param priv_key_hex [String] 64-character hex private key
    # @return [String] hex-encoded DER signature
    def sign_test_message(priv_key_hex)
      priv_key = priv_key_hex.to_i(16)
      ecdsa_sign(priv_key, TEST_MESSAGE_DIGEST).unpack1('H*')
    end

    # Derive the compressed public key from a private key.
    #
    # @param priv_key_hex [String] 64-character hex private key
    # @return [String] hex-encoded 33-byte compressed public key
    def pub_key_from_priv_key(priv_key_hex)
      priv_key = priv_key_hex.to_i(16)
      px, py = ECPrimitives.point_mul(priv_key, [CURVE_GX, CURVE_GY])
      prefix = py.even? ? 0x02 : 0x03
      ([prefix].pack('C') + int_to_32_bytes(px)).unpack1('H*')
    end

    # Verify an ECDSA signature over a message hash.
    #
    # @param msg_hash_hex [String] hex-encoded 32-byte SHA-256 message hash
    # @param sig_der_hex  [String] hex-encoded DER signature (with optional
    #                      trailing sighash byte)
    # @param pubkey_hex   [String] hex-encoded compressed or uncompressed
    #                      public key (33 or 65 bytes)
    # @return [Boolean] true if the signature is valid, false otherwise
    def verify(msg_hash_hex, sig_der_hex, pubkey_hex)
      sig_bytes = [sig_der_hex].pack('H*')
      pk_bytes  = [pubkey_hex].pack('H*')
      msg_hash  = [msg_hash_hex].pack('H*')

      ecdsa_verify(sig_bytes, pk_bytes, msg_hash)
    end

    # Parse a DER-encoded ECDSA signature into [r, s] integers.
    #
    # Also handles a trailing sighash byte (Bitcoin convention): if the actual
    # length exceeds the declared DER length by 1, the last byte is stripped.
    #
    # @param hex [String] hex-encoded DER signature
    # @return [Array(Integer, Integer), nil] [r, s] or nil on parse failure
    def parse_der_signature(hex)
      parse_der_signature_bytes([hex].pack('H*'))
    end

    # Decompress a public key to [x, y] integer coordinates.
    #
    # Handles:
    #   - 33-byte compressed keys (0x02 or 0x03 prefix)
    #   - 65-byte uncompressed keys (0x04 prefix)
    #
    # @param hex [String] hex-encoded public key (33 or 65 bytes)
    # @return [Array(Integer, Integer)] [x, y] point coordinates
    # @raise [ArgumentError] if the key is malformed or not on the curve
    def decompress_public_key(hex)
      decompress_pubkey_bytes([hex].pack('H*'))
    end

    # ---------------------------------------------------------------------------
    # Internal — byte-level functions (not part of the public hex API)
    # ---------------------------------------------------------------------------

    # Verify an ECDSA signature (binary inputs).
    #
    # Standard ECDSA verification:
    #   1. w  = s^-1 mod n
    #   2. u1 = z * w mod n
    #   3. u2 = r * w mod n
    #   4. (x, y) = u1*G + u2*Q
    #   5. Valid if x mod n == r
    #
    # @param sig_bytes [String] binary DER signature
    # @param pk_bytes  [String] binary public key (33 or 65 bytes)
    # @param msg_hash  [String] binary 32-byte message hash
    # @return [Boolean]
    # rubocop:disable Metrics/MethodLength, Metrics/AbcSize, Metrics/CyclomaticComplexity
    def ecdsa_verify(sig_bytes, pk_bytes, msg_hash)
      parsed = parse_der_signature_bytes(sig_bytes)
      return false if parsed.nil?

      sig_r, sig_s = parsed
      return false if sig_r <= 0 || sig_r >= CURVE_N || sig_s <= 0 || sig_s >= CURVE_N

      # BIP-62 rule 5 / SCRIPT_VERIFY_LOW_S: reject high-S signatures.
      # Bitcoin nodes enforce this on-chain; the signer already normalizes to
      # low-S (see ecdsa_sign), so the verifier must mirror that enforcement.
      half_n = CURVE_N >> 1
      return false if sig_s > half_n

      qx, qy = decompress_pubkey_bytes(pk_bytes)

      z   = msg_hash.unpack1('H*').to_i(16)
      w   = ECPrimitives.mod_inv(sig_s, CURVE_N)
      u1  = (z * w) % CURVE_N
      u2  = (sig_r * w) % CURVE_N

      pt1   = ECPrimitives.point_mul(u1, [CURVE_GX, CURVE_GY])
      pt2   = ECPrimitives.point_mul(u2, [qx, qy])
      rx_pt = ECPrimitives.point_add(pt1, pt2)

      return false if rx_pt.nil?

      rx_pt[0] % CURVE_N == sig_r
    rescue ArgumentError
      false
    end
    # rubocop:enable Metrics/MethodLength, Metrics/AbcSize, Metrics/CyclomaticComplexity

    # Sign a message hash with a private key integer.
    #
    # @param priv_key [Integer]
    # @param msg_hash [String] binary 32-byte hash
    # @return [String] binary DER-encoded signature
    # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
    def ecdsa_sign(priv_key, msg_hash)
      z = msg_hash.unpack1('H*').to_i(16)
      k = rfc6979_k(priv_key, msg_hash)

      rx_pt = ECPrimitives.point_mul(k, [CURVE_GX, CURVE_GY])
      raise 'ECDSA signing failed: R is infinity' if rx_pt.nil?

      sig_r = rx_pt[0] % CURVE_N
      raise 'ECDSA signing failed: r == 0' if sig_r.zero?

      k_inv = ECPrimitives.mod_inv(k, CURVE_N)
      sig_s = (k_inv * (z + sig_r * priv_key)) % CURVE_N
      raise 'ECDSA signing failed: s == 0' if sig_s.zero?

      # Low-S normalization (BIP 62): if s > n/2, use n - s
      sig_s = CURVE_N - sig_s if sig_s > CURVE_N / 2

      encode_der_signature(sig_r, sig_s)
    end
    # rubocop:enable Metrics/MethodLength, Metrics/AbcSize

    # ---------------------------------------------------------------------------
    # DER encoding / decoding
    # ---------------------------------------------------------------------------

    # Parse a binary DER signature into [r, s] integers, or nil on failure.
    #
    # DER format: 0x30 [total_len] 0x02 [r_len] [r_bytes] 0x02 [s_len] [s_bytes]
    #
    # rubocop:disable Metrics/MethodLength, Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
    def parse_der_signature_bytes(der_bytes)
      bytes = der_bytes.bytes
      return nil if bytes.length < 8
      return nil if bytes[0] != 0x30

      declared_len      = bytes[1]
      expected_pure_der = declared_len + 2

      # Strip trailing sighash byte if present (Bitcoin convention)
      if bytes.length == expected_pure_der + 1
        bytes = bytes[0, expected_pure_der]
      elsif bytes.length != expected_pure_der
        return nil
      end

      idx = 2

      # Parse r
      return nil if idx >= bytes.length || bytes[idx] != 0x02

      idx   += 1
      r_len  = bytes[idx]
      idx   += 1
      return nil if r_len.zero?
      return nil if idx + r_len > bytes.length

      r_component = bytes[idx, r_len]
      # Non-minimal encoding: leading 0x00 when the next byte's high bit is clear
      return nil if r_len > 1 && r_component[0] == 0x00 && r_component[1] & 0x80 == 0

      parsed_r  = r_component.pack('C*').unpack1('H*').to_i(16)
      idx      += r_len

      # Parse s
      return nil if idx >= bytes.length || bytes[idx] != 0x02

      idx   += 1
      s_len  = bytes[idx]
      idx   += 1
      return nil if s_len.zero?
      return nil if idx + s_len > bytes.length

      s_component = bytes[idx, s_len]
      # Non-minimal encoding: leading 0x00 when the next byte's high bit is clear
      return nil if s_len > 1 && s_component[0] == 0x00 && s_component[1] & 0x80 == 0

      parsed_s = s_component.pack('C*').unpack1('H*').to_i(16)

      [parsed_r, parsed_s]
    end
    # rubocop:enable Metrics/MethodLength, Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

    # Encode r and s integers as a binary DER ECDSA signature.
    #
    # DER format: 0x30 [total_len] 0x02 [r_len] [r_bytes] 0x02 [s_len] [s_bytes]
    # Integer bytes are unsigned big-endian with a leading 0x00 if the high bit
    # is set (to keep them positive in DER's signed-integer encoding).
    #
    # rubocop:disable Naming/MethodParameterName
    def encode_der_signature(r, s)
      r_bytes = int_to_der_bytes(r)
      s_bytes = int_to_der_bytes(s)

      inner = "\x02#{[r_bytes.length].pack('C')}#{r_bytes}\x02#{[s_bytes.length].pack('C')}#{s_bytes}"
      "\x30#{[inner.length].pack('C')}#{inner}"
    end
    # rubocop:enable Naming/MethodParameterName

    # Convert a positive integer to unsigned big-endian DER bytes.
    #
    # Prepends a 0x00 byte if the high bit of the first byte is set, to
    # distinguish positive integers from negatives in DER's signed encoding.
    def int_to_der_bytes(value)
      byte_len = (value.bit_length + 7) / 8
      byte_len = 1 if byte_len.zero?

      bytes = byte_len.times.map { |i| (value >> (8 * (byte_len - 1 - i))) & 0xFF }
      bytes.unshift(0x00) if bytes[0] & 0x80 != 0

      bytes.pack('C*')
    end

    # ---------------------------------------------------------------------------
    # Public key decompression
    # ---------------------------------------------------------------------------

    # Decompress a binary public key to [x, y] integer coordinates.
    #
    # Compressed format (33 bytes): 0x02 or 0x03 prefix + 32-byte x-coordinate.
    # y = sqrt(x^3 + 7) mod p, choosing even/odd based on prefix.
    # Since p ≡ 3 (mod 4), sqrt is y = (x^3 + 7)^((p+1)/4) mod p.
    #
    # Uncompressed format (65 bytes): 0x04 prefix + 32-byte x + 32-byte y.
    #
    def decompress_pubkey_bytes(pk_bytes)
      bytes  = pk_bytes.bytes
      prefix = bytes[0]

      return decompress_uncompressed_pubkey(bytes) if prefix == 0x04

      raise ArgumentError, "Expected 33-byte compressed pubkey, got #{bytes.length}" unless bytes.length == 33
      raise ArgumentError, "Invalid compressed pubkey prefix: 0x#{prefix.to_s(16).rjust(2, '0')}" unless
        [0x02, 0x03].include?(prefix)

      decompress_compressed_pubkey(bytes, prefix)
    end

    # ---------------------------------------------------------------------------
    # RFC 6979 deterministic k generation
    # ---------------------------------------------------------------------------

    # Generate deterministic k per RFC 6979 using HMAC-SHA256.
    #
    # Implements the HMAC-DRBG algorithm from Section 3.2 of RFC 6979.
    # Using the same algorithm as Python/TypeScript ensures signing produces
    # identical signatures across all SDK runtimes.
    #
    # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
    def rfc6979_k(priv_key, msg_hash)
      # Private key as 32-byte big-endian binary string
      priv_bytes = int_to_32_bytes(priv_key)

      # Steps b–c: V = 0x01*32, K = 0x00*32
      v     = "\x01" * 32
      k_mac = "\x00" * 32

      # Steps d–g: two rounds of HMAC-DRBG seeding
      k_mac = hmac_sha256(k_mac, "#{v}\x00#{priv_bytes}#{msg_hash}")
      v     = hmac_sha256(k_mac, v)
      k_mac = hmac_sha256(k_mac, "#{v}\x01#{priv_bytes}#{msg_hash}")
      v     = hmac_sha256(k_mac, v)

      # Step h: generate candidate k values
      loop do
        v         = hmac_sha256(k_mac, v)
        candidate = v.unpack1('H*').to_i(16)

        return candidate if candidate >= 1 && candidate < CURVE_N

        # Retry: update K and V
        k_mac = hmac_sha256(k_mac, "#{v}\x00")
        v     = hmac_sha256(k_mac, v)
      end
    end
    # rubocop:enable Metrics/MethodLength, Metrics/AbcSize

    # ---------------------------------------------------------------------------
    # Low-level helpers
    # ---------------------------------------------------------------------------

    # Compute HMAC-SHA256 of +data+ with +key+.
    #
    # @param key  [String] binary key
    # @param data [String] binary data
    # @return [String] 32-byte binary digest
    def hmac_sha256(key, data)
      OpenSSL::HMAC.digest('sha256', key, data)
    end

    # Encode a non-negative integer as a 32-byte big-endian binary string.
    def int_to_32_bytes(value)
      [value.to_s(16).rjust(64, '0')].pack('H*')
    end

    # ---------------------------------------------------------------------------
    # Private decompress helpers (called only from decompress_pubkey_bytes)
    # ---------------------------------------------------------------------------

    # Handle the 0x04 uncompressed key case.
    def decompress_uncompressed_pubkey(bytes)
      raise ArgumentError, "Expected 65-byte uncompressed pubkey, got #{bytes.length}" unless bytes.length == 65

      x = bytes[1, 32].pack('C*').unpack1('H*').to_i(16)
      y = bytes[33, 32].pack('C*').unpack1('H*').to_i(16)
      raise ArgumentError, 'Point not on curve' unless on_curve_secp256k1?(x, y)

      [x, y]
    end

    # Handle the 0x02/0x03 compressed key case.
    # rubocop:disable Metrics/AbcSize
    def decompress_compressed_pubkey(bytes, prefix)
      x    = bytes[1, 32].pack('C*').unpack1('H*').to_i(16)
      y_sq = (x.pow(3, CURVE_P) + 7) % CURVE_P
      y    = y_sq.pow((CURVE_P + 1) / 4, CURVE_P)

      raise ArgumentError, 'Point not on curve' unless (y * y) % CURVE_P == y_sq

      # Choose the correct parity
      if prefix == 0x02 && y.odd?
        y = CURVE_P - y
      elsif prefix == 0x03 && y.even?
        y = CURVE_P - y
      end

      [x, y]
    end
    # rubocop:enable Metrics/AbcSize

    # Check whether (x, y) lies on the secp256k1 curve (y^2 = x^3 + 7 mod p).
    #
    # rubocop:disable Naming/MethodParameterName
    def on_curve_secp256k1?(x, y)
      (y * y) % CURVE_P == (x.pow(3, CURVE_P) + 7) % CURVE_P
    end
    # rubocop:enable Naming/MethodParameterName
  end
  # rubocop:enable Metrics/ModuleLength
end
