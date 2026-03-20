"""Sha256FinalizeTest -- verifies SHA-256 finalize correctness on-chain.

The sha256_finalize intrinsic handles FIPS 180-4 padding internally: it
appends the 0x80 byte, zero-pads, and appends the 8-byte big-endian bit
length, then compresses one or two blocks depending on the remaining length:

- remaining <= 55 bytes: single-block path (one compression, ~74KB script)
- 56-119 bytes: two-block path (two compressions, ~148KB script)

The msg_bit_len parameter is the TOTAL message bit length across all prior
sha256_compress calls plus the remaining bytes. This value is used in the
64-bit length suffix of the SHA-256 padding.

For standalone hashing, pass SHA-256 IV as state and the full message as
remaining. For multi-block hashing, use sha256_compress for the first N
full blocks and sha256_finalize for the trailing bytes.
"""

from runar import SmartContract, ByteString, Bigint, public, assert_, sha256_finalize


class Sha256FinalizeTest(SmartContract):
    """Verifies SHA-256 finalize output matches expected digest."""

    expected: ByteString

    def __init__(self, expected: ByteString):
        super().__init__(expected)
        self.expected = expected

    @public
    def verify(self, state: ByteString, remaining: ByteString, msg_bit_len: Bigint):
        """Verify sha256_finalize(state, remaining, msg_bit_len) matches expected."""
        result = sha256_finalize(state, remaining, msg_bit_len)
        assert_(result == self.expected)
