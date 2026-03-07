# frozen_string_literal: true

# Runar built-in functions.
#
# Mock crypto functions always return true for business logic testing.
# Real hash functions use Ruby's Digest stdlib (no external dependencies).
# All byte data is represented as hex-encoded strings.

require 'digest'

module Runar
  module Builtins
    # -- Assertion -------------------------------------------------------------

    # Runar assertion. Raises RuntimeError if condition is falsey.
    def assert(condition)
      raise 'runar: assertion failed' unless condition
    end

    # -- Mock Crypto (always true for business logic testing) ------------------

    def check_sig(_sig, _pk)
      true
    end

    def check_multi_sig(_sigs, _pks)
      true
    end

    def check_preimage(_preimage)
      true
    end

    def verify_rabin_sig(_msg, _sig, _padding, _pk)
      true
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

    def extract_output_hash(_preimage)
      '00' * 32
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
      # Ensure sign matches dividend (Bitcoin Script behaviour)
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

    def mock_sig
      '00' * 72
    end

    def mock_pub_key
      '02' + ('00' * 32)
    end

    def mock_preimage
      '00' * 181
    end
  end
end
