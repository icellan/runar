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

    # -- SHA-256 Compression (real implementation, FIPS 180-4) ----------------

    # SHA-256 round constants (first 32 bits of the fractional parts of the
    # cube roots of the first 64 primes).
    SHA256_K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ].freeze

    # Right-rotate a 32-bit unsigned integer by n bits.
    def _sha256_rotr(x, n)
      ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    end
    private :_sha256_rotr

    # SHA-256 single-block compression function (FIPS 180-4 Section 6.2.2).
    #
    # Performs one round of SHA-256 block compression: message schedule
    # expansion (W[0..63]), 64 compression rounds with Sigma/Ch/Maj functions
    # and the K constants, then addition back to the initial state.
    #
    # Both state and block are hex-encoded strings. State is 32 bytes (64 hex
    # chars); block is 64 bytes (128 hex chars). Returns a 32-byte hex string.
    #
    # Use the SHA-256 IV as state for the first block:
    #   6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19
    def sha256_compress(state, block)
      state_bytes = [state].pack('H*')
      block_bytes = [block].pack('H*')

      raise ArgumentError, "state must be 32 bytes, got #{state_bytes.bytesize}" unless state_bytes.bytesize == 32
      raise ArgumentError, "block must be 64 bytes, got #{block_bytes.bytesize}" unless block_bytes.bytesize == 64

      # Parse state as 8 big-endian uint32 words
      h = state_bytes.unpack('N8')

      # Parse block as 16 big-endian uint32 words and expand to message schedule
      w = block_bytes.unpack('N16')
      (16..63).each do |t|
        s0 = (_sha256_rotr(w[t - 15], 7) ^ _sha256_rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)) & 0xFFFFFFFF
        s1 = (_sha256_rotr(w[t - 2], 17) ^ _sha256_rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)) & 0xFFFFFFFF
        w << ((s1 + w[t - 7] + s0 + w[t - 16]) & 0xFFFFFFFF)
      end

      # Initialize working variables
      a, b, c, d, e, f, g, hh = h

      # 64 compression rounds
      64.times do |t|
        s1   = (_sha256_rotr(e, 6) ^ _sha256_rotr(e, 11) ^ _sha256_rotr(e, 25)) & 0xFFFFFFFF
        ch   = ((e & f) ^ (~e & g)) & 0xFFFFFFFF
        temp1 = (hh + s1 + ch + SHA256_K[t] + w[t]) & 0xFFFFFFFF
        s0   = (_sha256_rotr(a, 2) ^ _sha256_rotr(a, 13) ^ _sha256_rotr(a, 22)) & 0xFFFFFFFF
        maj  = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
        temp2 = (s0 + maj) & 0xFFFFFFFF

        hh = g
        g  = f
        f  = e
        e  = (d + temp1) & 0xFFFFFFFF
        d  = c
        c  = b
        b  = a
        a  = (temp1 + temp2) & 0xFFFFFFFF
      end

      # Add compressed chunk back to state
      new_state = [
        (h[0] + a) & 0xFFFFFFFF,
        (h[1] + b) & 0xFFFFFFFF,
        (h[2] + c) & 0xFFFFFFFF,
        (h[3] + d) & 0xFFFFFFFF,
        (h[4] + e) & 0xFFFFFFFF,
        (h[5] + f) & 0xFFFFFFFF,
        (h[6] + g) & 0xFFFFFFFF,
        (h[7] + hh) & 0xFFFFFFFF
      ]
      new_state.pack('N8').unpack1('H*')
    end

    # SHA-256 finalization with FIPS 180-4 padding.
    #
    # Applies SHA-256 padding (append 0x80 byte, zero-pad, append 8-byte
    # big-endian bit length) and runs the final 1-2 compression rounds:
    #
    # - Single-block path (remaining <= 55 bytes): pads to one 64-byte block
    #   and compresses once.
    # - Two-block path (56-119 bytes): pads to two 64-byte blocks and
    #   compresses twice.
    #
    # state is a 32-byte hex string (SHA-256 IV for first call, or output of
    # a prior sha256_compress for multi-block). remaining is a hex string of
    # unprocessed trailing message bytes (0-119 bytes). msg_bit_len is the
    # total message length in bits across all blocks. Returns a 32-byte hex string.
    def sha256_finalize(state, remaining, msg_bit_len)
      remaining_bytes = [remaining].pack('H*')

      # Append the 0x80 padding byte
      padded = remaining_bytes + "\x80".b

      if padded.bytesize + 8 <= 64
        # Single-block path: pad to 56 bytes, then append 8-byte BE bit length
        padded = padded.ljust(56, "\x00".b)
        padded += [msg_bit_len].pack('Q>')
        sha256_compress(state, padded.unpack1('H*'))
      else
        # Two-block path: pad to 120 bytes, then append 8-byte BE bit length
        padded = padded.ljust(120, "\x00".b)
        padded += [msg_bit_len].pack('Q>')
        intermediate = sha256_compress(state, padded[0, 64].unpack1('H*'))
        sha256_compress(intermediate, padded[64, 64].unpack1('H*'))
      end
    end

    # -- Mock BLAKE3 Functions -------------------------------------------------

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

    def sign(n)
      return 1 if n > 0
      return -1 if n < 0

      0
    end

    def pow(base, exp)
      base**exp
    end

    def mul_div(a, b, c)
      (a * b) / c
    end

    def percent_of(amount, bps)
      (amount * bps) / 10_000
    end

    # Integer square root using Newton's method.
    def sqrt(n)
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

    def gcd(a, b)
      a = a.abs
      b = b.abs
      a, b = b, a % b while b != 0
      a
    end

    # Returns quotient only (matching Runar's divmod which returns quotient).
    def divmod(a, b)
      a / b
    end

    def log2(n)
      return 0 if n <= 0

      n.bit_length - 1
    end

    def bool(n)
      n != 0
    end

    def within(x, lo, hi)
      lo <= x && x < hi
    end

    # -- Binary Utilities ------------------------------------------------------
    # Operate on hex-encoded strings.

    # Byte length of a hex string (hex.length / 2).
    def len(data)
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
