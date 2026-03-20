"""Sha256CompressTest -- verifies SHA-256 compression correctness on-chain.

The sha256_compress intrinsic performs one round of SHA-256 block compression
(FIPS 180-4 Section 6.2.2): takes a 32-byte state and a 64-byte block,
producing a new 32-byte state. The compiled script is ~74KB (64 rounds of
bit manipulation using OP_LSHIFT, OP_RSHIFT, OP_AND, OP_XOR).

For a single-block message (<=55 bytes), the caller pads per FIPS 180-4
Section 5.1.1 (append 0x80, zero-pad to 56 bytes, append 8-byte big-endian
bit length) and passes SHA-256 IV as the initial state. The result matches
the OP_SHA256 opcode.

For multi-block messages, chain multiple sha256_compress calls -- each
producing an intermediate state for the next block.
"""

from runar import SmartContract, ByteString, public, assert_, sha256_compress


class Sha256CompressTest(SmartContract):
    """Verifies SHA-256 compression output matches expected digest."""

    expected: ByteString

    def __init__(self, expected: ByteString):
        super().__init__(expected)
        self.expected = expected

    @public
    def verify(self, state: ByteString, block: ByteString):
        """Verify sha256_compress(state, block) matches expected."""
        result = sha256_compress(state, block)
        assert_(result == self.expected)
