# frozen_string_literal: true

# Runar built-in functions.
#
# Real ECDSA and Rabin verification for check_sig, check_multi_sig, and
# verify_rabin_sig. Real hash functions use Ruby's Digest stdlib (no external
# dependencies). All byte data is represented as hex-encoded strings.

require 'digest'
require_relative 'ecdsa'
require_relative 'rabin_sig'

module Runar
  module Builtins
    # The fixed test message digest shared across all Runar SDKs.
    # SHA256("runar-test-message-v1") — matches Python TEST_MESSAGE_DIGEST.
    TEST_MESSAGE_DIGEST = Digest::SHA256.hexdigest('runar-test-message-v1').freeze

    # -- Assertion -------------------------------------------------------------

    # Runar assertion. Raises RuntimeError if condition is falsey.
    def assert(condition)
      raise 'runar: assertion failed' unless condition
    end

    # -- Real ECDSA Verification -----------------------------------------------

    # Verify an ECDSA signature over the fixed TEST_MESSAGE_DIGEST.
    # Both sig and pk are hex-encoded strings.
    def check_sig(sig, pk)
      Runar::ECDSA.verify(TEST_MESSAGE_DIGEST, sig, pk)
    end

    # Verify multiple ECDSA signatures (Bitcoin-style ordered multi-sig).
    # Each signature must verify against the next unused public key in order.
    # Both sigs and pks are arrays of hex-encoded strings.
    def check_multi_sig(sigs, pks)
      return false if sigs.length > pks.length

      pk_idx = 0
      sigs.each do |sig|
        matched = false
        while pk_idx < pks.length
          if check_sig(sig, pks[pk_idx])
            pk_idx += 1
            matched = true
            break
          end
          pk_idx += 1
        end
        return false unless matched
      end
      true
    end

    def check_preimage(_preimage)
      true
    end

    # Verify a Rabin signature.
    # All parameters are hex-encoded strings. sig, padding, and pk are
    # interpreted as unsigned little-endian integers.
    def verify_rabin_sig(msg, sig, padding, pk)
      Runar::RabinSig.rabin_verify(msg, sig, padding, pk)
    end

    def verify_wots(_msg, _sig, _pubkey)
      true
    end

    def verify_slh_dsa_sha2_128s(_msg, _sig, _pubkey)
      true
    end

    def verify_slh_dsa_sha2_128f(_msg, _sig, _pubkey)
      true
    end

    def verify_slh_dsa_sha2_192s(_msg, _sig, _pubkey)
      true
    end

    def verify_slh_dsa_sha2_192f(_msg, _sig, _pubkey)
      true
    end

    def verify_slh_dsa_sha2_256s(_msg, _sig, _pubkey)
      true
    end

    def verify_slh_dsa_sha2_256f(_msg, _sig, _pubkey)
      true
    end

    # Mock BLAKE3 single-block compression.
    # In compiled Bitcoin Script this expands to ~10,000 opcodes.
    # Returns 32 zero bytes as hex for business-logic testing.
    def blake3_compress(_chaining_value, _block)
      '00' * 32
    end

    # Mock BLAKE3 hash for messages up to 64 bytes.
    # In compiled Bitcoin Script this uses the IV as the chaining value and
    # applies zero-padding before calling the compression function.
    # Returns 32 zero bytes as hex for business-logic testing.
    def blake3_hash(_message)
      '00' * 32
    end

    # -- Real Hash Functions ---------------------------------------------------
    # All operate on hex-encoded strings: input is hex, output is hex.

    # SHA-256 hash. Input and output are hex-encoded strings.
    def sha256(data)
      raw = [data].pack('H*')
      Digest::SHA256.hexdigest(raw)
    end

    # RIPEMD-160 hash. Input and output are hex-encoded strings.
    def ripemd160(data)
      raw = [data].pack('H*')
      Digest::RMD160.hexdigest(raw)
    end

    # RIPEMD160(SHA256(data)). Input and output are hex-encoded strings.
    def hash160(data)
      sha_hex = sha256(data)
      ripemd160(sha_hex)
    end

    # SHA256(SHA256(data)). Input and output are hex-encoded strings.
    def hash256(data)
      sha_hex = sha256(data)
      sha256(sha_hex)
    end

    # -- Mock Preimage Extraction ----------------------------------------------

    def extract_locktime(_preimage)
      0
    end

    # Returns the first 32 bytes of the preimage as a hex string.
    # Tests set tx_preimage = hash256(expected_output_bytes) so the assertion
    # hash256(outputs) == extract_output_hash(tx_preimage) passes.
    # Falls back to 32 zero bytes when the preimage is shorter than 32 bytes.
    def extract_output_hash(preimage)
      preimage = preimage.to_s
      if preimage.length >= 64 # 32 bytes = 64 hex chars
        preimage[0, 64]
      else
        '00' * 32
      end
    end

    def extract_amount(_preimage)
      10_000
    end

    def extract_version(_preimage)
      1
    end

    def extract_sequence(_preimage)
      0xFFFFFFFF
    end

    # Returns hash256(72 zero bytes) in test mode.
    # Consistent with passing all_prevouts = 72 zero bytes in tests,
    # since extract_outpoint also returns 36 zero bytes.
    def extract_hash_prevouts(_preimage)
      hash256('00' * 72)
    end

    # Returns 36 zero bytes (outpoint = txid[32] + vout[4]) in test mode.
    def extract_outpoint(_preimage)
      '00' * 36
    end

    # -- Math Utilities --------------------------------------------------------

    def safediv(a, b)
      return 0 if b == 0

      # Bitcoin Script truncates toward zero, unlike Ruby's floor division.
      if (a < 0) != (b < 0) && a % b != 0
        -(a.abs / b.abs)
      else
        a / b
      end
    end

    def safemod(a, b)
      return 0 if b == 0

      r = a % b
      # Ensure sign matches dividend (Bitcoin Script behavior)
      r -= b if r != 0 && (a < 0) != (r < 0)
      r
    end

    def clamp(value, lo, hi)
      return lo if value < lo
      return hi if value > hi

      value
    end

    # Named sign_ to avoid conflict with Ruby's Kernel methods.
    def sign_(n)
      return 1 if n > 0
      return -1 if n < 0

      0
    end

    def pow_(base, exp)
      base**exp
    end

    def mul_div(a, b, c)
      (a * b) / c
    end

    def percent_of(amount, bps)
      (amount * bps) / 10_000
    end

    # Integer square root using Newton's method.
    def sqrt_(n)
      raise ArgumentError, 'sqrt of negative number' if n < 0
      return 0 if n == 0

      x = n
      y = (x + 1) / 2
      while y < x
        x = y
        y = (x + n / x) / 2
      end
      x
    end

    def gcd_(a, b)
      a = a.abs
      b = b.abs
      a, b = b, a % b while b != 0
      a
    end

    # Returns quotient only (matching Runar's divmod which returns quotient).
    def divmod_(a, b)
      a / b
    end

    def log2_(n)
      return 0 if n <= 0

      n.bit_length - 1
    end

    def bool_cast(n)
      n != 0
    end

    def within(x, lo, hi)
      lo <= x && x < hi
    end

    # -- Binary Utilities ------------------------------------------------------
    # Operate on hex-encoded strings.

    # Byte length of a hex string (hex.length / 2).
    def len_(data)
      data.length / 2
    end

    # Concatenate two hex strings.
    def cat(a, b)
      a + b
    end

    # Extract a substring of bytes from a hex string.
    # start and length are in bytes, not hex characters.
    def substr(data, start, length)
      data[start * 2, length * 2]
    end

    # Left-most bytes of a hex string.
    def left(data, length)
      data[0, length * 2]
    end

    # Right-most bytes of a hex string.
    def right(data, length)
      data[-(length * 2)..]
    end

    # Reverse the byte order of a hex string.
    def reverse_bytes(data)
      [data].pack('H*').reverse.unpack1('H*')
    end

    # Convert an integer to a little-endian sign-magnitude hex string
    # of the specified byte length. This is Bitcoin Script's number encoding.
    # The sign bit is always in the MSB of the last byte.
    def num2bin(v, length)
      return '00' * length if v == 0

      negative = v < 0
      val = v.abs
      result = []
      while val > 0
        result << (val & 0xFF)
        val >>= 8
      end
      # Ensure the magnitude fits without colliding with the sign bit position
      if (result[-1] & 0x80) != 0
        result << 0x00
      end
      # Pad to requested length
      result << 0 while result.length < length
      # Truncate to requested length
      result = result[0, length]
      # Place sign bit in the MSB of the last byte
      result[-1] |= 0x80 if negative
      result.map { |b| format('%02x', b) }.join
    end

    # Convert a little-endian sign-magnitude hex string to an integer.
    # This is Bitcoin Script's number encoding (sign bit in MSB of last byte).
    def bin2num(data)
      return 0 if data.nil? || data.empty?

      raw = [data].pack('H*')
      bytes = raw.bytes
      return 0 if bytes.empty?

      negative = (bytes[-1] & 0x80) != 0
      bytes[-1] &= 0x7F

      result = 0
      bytes.each_with_index do |b, i|
        result |= (b << (8 * i))
      end

      negative ? -result : result
    end

    # -- Test Helpers ----------------------------------------------------------

    # Return ALICE's real ECDSA test signature (DER-encoded hex).
    # This is a valid signature over TEST_MESSAGE_DIGEST that will pass
    # check_sig verification when paired with mock_pub_key.
    def mock_sig
      require_relative 'test_keys'
      Runar::TestKeys::ALICE.test_sig
    end

    # Return ALICE's real compressed secp256k1 public key (33 bytes, hex).
    # This is a valid key that will pass check_sig verification when paired
    # with mock_sig.
    def mock_pub_key
      require_relative 'test_keys'
      Runar::TestKeys::ALICE.pub_key
    end

    def mock_preimage
      '00' * 181
    end
  end
end
