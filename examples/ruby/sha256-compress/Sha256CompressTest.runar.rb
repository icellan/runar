require 'runar'

# Sha256CompressTest -- A stateless contract demonstrating the built-in SHA-256
# compression primitive available in Runar.
#
# What is SHA-256 compression?
#
# SHA-256 (FIPS 180-4) processes messages in 512-bit (64-byte) blocks. The
# core operation is the compression function, which takes:
#   - A 32-byte state (8 x 32-bit big-endian words)
#   - A 64-byte message block (16 x 32-bit big-endian words)
#
# It expands the block into a 64-word message schedule, then runs 64 rounds
# using the SHA-256 round constants (K), Sigma, Ch, and Maj functions. The
# working variables are added back to the input state to produce the new state.
#
# For a single-block message (<=55 bytes of content after padding), the
# standard SHA-256 hash is produced by:
#   1. Appending 0x80 to the message
#   2. Zero-padding to 56 bytes
#   3. Appending the 8-byte big-endian bit length
#   4. Passing the SHA-256 IV as state and the 64-byte padded block to
#      sha256_compress
#
# The SHA-256 IV (big-endian hex):
#   6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
#
# For multi-block messages, chain multiple sha256_compress calls: each call
# produces an intermediate state for the next block. Use sha256_finalize for
# the final (possibly partial) block to apply padding automatically.
#
# The compiled Bitcoin Script for sha256_compress is approximately 74 KB
# (64 rounds of bit manipulation using OP_LSHIFT, OP_RSHIFT, OP_AND, OP_XOR).
#
# Use cases:
#   - On-chain proof that some data hashes to a known SHA-256 digest
#   - Incremental hashing: split a large message across multiple transactions
#   - Hash-locked payments: lock funds to a SHA-256 preimage
#   - Commitment schemes: commit to a value with SHA-256, reveal later

class Sha256CompressTest < Runar::SmartContract
  # The expected 32-byte SHA-256 state output. Set at deployment time as part
  # of the locking script. The spending method computes sha256_compress from
  # the unlocking arguments and asserts the result matches this value.
  prop :expected, ByteString, readonly: true

  def initialize(expected)
    super(expected)
    @expected = expected
  end

  # Verify a SHA-256 compression function invocation.
  #
  # Computes sha256_compress(state, block) and asserts the 32-byte result
  # matches @expected. The caller provides both the 32-byte initial state and
  # the full 64-byte message block.
  #
  # To verify a standard SHA-256 hash of a short message (<=55 bytes):
  #   - state  = SHA-256 IV (32 bytes)
  #   - block  = message padded per FIPS 180-4 Section 5.1.1 to 64 bytes
  #   - expected = the SHA-256 digest you want to verify against
  runar_public state: ByteString, block: ByteString
  def verify(state, block)
    result = sha256_compress(state, block)
    assert result == @expected
  end
end
