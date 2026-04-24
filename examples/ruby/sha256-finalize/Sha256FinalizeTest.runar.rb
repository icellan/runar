require 'runar'

# Sha256FinalizeTest -- A stateless contract demonstrating the built-in SHA-256
# finalization primitive available in Runar.
#
# What is SHA-256 finalization?
#
# sha256_finalize handles the final step of SHA-256 hashing: applying FIPS
# 180-4 padding to the remaining bytes and running one or two compression
# rounds depending on how much data remains.
#
# Padding scheme (FIPS 180-4 Section 5.1.1):
#   1. Append a 0x80 byte immediately after the message data
#   2. Zero-pad until 8 bytes short of a 64-byte block boundary
#   3. Append the 8-byte big-endian total message length in bits
#
# Two paths:
#   - Single-block path (remaining <= 55 bytes): the padding fits in one
#     64-byte block, so one compression round is performed (~74 KB script).
#   - Two-block path (56-119 bytes): padding spans two 64-byte blocks, so
#     two compression rounds are performed (~148 KB script).
#
# Parameters:
#   - state:       32-byte SHA-256 state (use SHA-256 IV for a single call,
#                  or pass the output of prior sha256_compress calls for
#                  multi-block hashing)
#   - remaining:   hex-encoded trailing message bytes not yet compressed
#                  (0-119 bytes)
#   - msg_bit_len: total message length in bits across ALL blocks including
#                  remaining (used in the 64-bit length suffix)
#
# For standalone SHA-256 of a short message (<= 55 bytes), pass:
#   - state  = SHA-256 IV
#   - remaining = the full message (hex-encoded)
#   - msg_bit_len = message byte count * 8
#
# The SHA-256 IV (big-endian hex):
#   6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
#
# For multi-block messages, process full 64-byte blocks with sha256_compress
# and pass the last partial block to sha256_finalize.
#
# Use cases:
#   - On-chain SHA-256 hash verification with automatic padding
#   - Final step in multi-block incremental SHA-256 hashing
#   - Hash-locked payments where the preimage is up to 55 bytes
#   - Commitment schemes with automatic padding

class Sha256FinalizeTest < Runar::SmartContract
  # The expected 32-byte SHA-256 digest. Set at deployment time as part of
  # the locking script. The spending method computes sha256_finalize and
  # asserts the result matches this value.
  prop :expected, ByteString, readonly: true

  def initialize(expected)
    super(expected)
    @expected = expected
  end

  # Verify a SHA-256 finalization invocation.
  #
  # Computes sha256_finalize(state, remaining, msg_bit_len) and asserts the
  # 32-byte result matches @expected.
  #
  # To verify SHA-256(short_message) where short_message fits in one block:
  #   - state       = SHA-256 IV
  #   - remaining   = short_message (hex-encoded, 0-55 bytes)
  #   - msg_bit_len = short_message.bytesize * 8
  #   - expected    = SHA-256(short_message)
  runar_public state: ByteString, remaining: ByteString, msg_bit_len: Bigint
  def verify(state, remaining, msg_bit_len)
    result = sha256_finalize(state, remaining, msg_bit_len)
    assert result == @expected
  end
end
