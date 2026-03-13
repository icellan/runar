"""SHA-256 compression utility for inductive contracts.

Provides a pure SHA-256 compression function and a helper that computes
partial SHA-256 state for inductive contract parent-tx verification.
The on-chain script receives only the last 3 blocks and the intermediate
hash state, avoiding the need to push the full raw parent tx.
"""

from __future__ import annotations

# SHA-256 round constants (FIPS 180-4 Section 4.2.2).
# 64 values derived from the fractional parts of the cube roots of
# the first 64 primes.
SHA256_K: tuple[int, ...] = (
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)

# SHA-256 initial hash values (FIPS 180-4 Section 5.3.3).
# Derived from the fractional parts of the square roots of
# the first 8 primes.
SHA256_INIT: tuple[int, ...] = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)

_MASK32 = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    """32-bit right rotate."""
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _add32(a: int, b: int) -> int:
    """32-bit wrapping addition."""
    return (a + b) & _MASK32


def sha256_compress_block(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    """Pure SHA-256 compression function for one 64-byte block.

    Takes an 8-word intermediate hash state and a 64-byte message block,
    applies the 64 rounds of SHA-256 compression, and returns the
    updated 8-word state.

    Args:
        state: 8-element tuple of 32-bit ints (current hash state, 32 bytes).
        block: 64-byte message block.

    Returns:
        New 8-element tuple with the updated hash state.
    """
    if len(state) != 8:
        raise ValueError(f"sha256_compress_block: state must be 8 words, got {len(state)}")
    if len(block) != 64:
        raise ValueError(f"sha256_compress_block: block must be 64 bytes, got {len(block)}")

    # Expand 16 message words to 64
    W = [0] * 64
    for i in range(16):
        W[i] = int.from_bytes(block[i * 4:(i + 1) * 4], 'big')
    for t in range(16, 64):
        s0 = (_rotr(W[t - 15], 7) ^ _rotr(W[t - 15], 18) ^ (W[t - 15] >> 3)) & _MASK32
        s1 = (_rotr(W[t - 2], 17) ^ _rotr(W[t - 2], 19) ^ (W[t - 2] >> 10)) & _MASK32
        W[t] = _add32(_add32(_add32(s1, W[t - 7]), s0), W[t - 16])

    # Initialize working variables
    a, b, c, d, e, f, g, h = state

    # 64 rounds of compression
    for t in range(64):
        S1 = (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) & _MASK32
        ch = ((e & f) ^ (~e & _MASK32 & g)) & _MASK32
        T1 = _add32(_add32(_add32(_add32(h, S1), ch), SHA256_K[t]), W[t])
        S0 = (_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) & _MASK32
        maj = ((a & b) ^ (a & c) ^ (b & c)) & _MASK32
        T2 = _add32(S0, maj)
        h = g
        g = f
        f = e
        e = _add32(d, T1)
        d = c
        c = b
        b = a
        a = _add32(T1, T2)

    # Add compressed chunk to current hash state
    return (
        _add32(a, state[0]),
        _add32(b, state[1]),
        _add32(c, state[2]),
        _add32(d, state[3]),
        _add32(e, state[4]),
        _add32(f, state[5]),
        _add32(g, state[6]),
        _add32(h, state[7]),
    )


def _state_to_hex(state: tuple[int, ...]) -> str:
    """Convert an 8-word state to 64-char hex string."""
    return ''.join(f'{w:08x}' for w in state)


def _sha256_pad(message: bytes) -> bytes:
    """Apply SHA-256 padding (FIPS 180-4 Section 5.1.1).

    Appends:
      1. A single 0x80 byte
      2. Zero bytes until (length mod 64) == 56
      3. 8-byte big-endian bit length of the original message
    """
    msg_len = len(message)
    bit_len = msg_len * 8

    # Calculate padded length
    padded_len = msg_len + 1  # +1 for the 0x80 byte
    while padded_len % 64 != 56:
        padded_len += 1
    padded_len += 8  # 8-byte big-endian bit length

    padded = bytearray(padded_len)
    padded[:msg_len] = message
    padded[msg_len] = 0x80

    # Append 8-byte big-endian bit length
    len_offset = padded_len - 8
    padded[len_offset:len_offset + 8] = bit_len.to_bytes(8, 'big')

    return bytes(padded)


def compute_partial_sha256_for_inductive(raw_tx_hex: str) -> dict:
    """Compute partial SHA-256 for an inductive contract's parent transaction.

    Instead of pushing the full raw parent tx on-chain, we pre-compute the
    SHA-256 state up to (but not including) the last 3 blocks. The on-chain
    script receives:
      - The intermediate hash state (32 bytes)
      - The three tail blocks (64 bytes each)
      - The raw tail length (to locate fields within the tail)

    It then completes the double-SHA256 to derive the parent txid and
    verifies it against the outpoint in the sighash preimage.

    Args:
        raw_tx_hex: Full raw transaction hex.

    Returns:
        Dict with keys: parent_hash_state, parent_tail_block1,
        parent_tail_block2, parent_tail_block3, parent_raw_tail_len.
    """
    raw_bytes = bytes.fromhex(raw_tx_hex)
    padded = _sha256_pad(raw_bytes)
    total_blocks = len(padded) // 64

    if total_blocks < 3:
        raise ValueError(
            f"compute_partial_sha256_for_inductive: padded message has only "
            f"{total_blocks} blocks, need at least 3. Raw tx length: {len(raw_bytes)}"
        )

    # Compress all blocks except the last 3 to get intermediate state
    state: tuple[int, ...] = SHA256_INIT
    pre_hashed_blocks = total_blocks - 3
    for i in range(pre_hashed_blocks):
        block = padded[i * 64:(i + 1) * 64]
        state = sha256_compress_block(state, block)

    tail_block1 = padded[pre_hashed_blocks * 64:(pre_hashed_blocks + 1) * 64]
    tail_block2 = padded[(pre_hashed_blocks + 1) * 64:(pre_hashed_blocks + 2) * 64]
    tail_block3 = padded[(pre_hashed_blocks + 2) * 64:(pre_hashed_blocks + 3) * 64]

    # Raw tail length = total raw bytes minus the bytes already compressed
    raw_tail_len = len(raw_bytes) - pre_hashed_blocks * 64

    if raw_tail_len < 115:
        raise ValueError(
            f"compute_partial_sha256_for_inductive: raw_tail_len is {raw_tail_len}, "
            f"need at least 115 bytes to contain the internal fields"
        )

    return {
        'parent_hash_state': _state_to_hex(state),
        'parent_tail_block1': tail_block1.hex(),
        'parent_tail_block2': tail_block2.hex(),
        'parent_tail_block3': tail_block3.hex(),
        'parent_raw_tail_len': raw_tail_len,
    }
