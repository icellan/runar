"""Real Rabin signature verification for Runar contract testing.

Rabin verification equation:
  (sig^2 + padding) mod n === SHA256(msg) mod n

where n is the Rabin public key (modulus), sig is the Rabin signature,
and padding is a small adjustment value.

The SHA256 hash and padding are interpreted as unsigned little-endian
integers to match Bitcoin Script's OP_MOD / OP_ADD behavior.
"""

import hashlib

# Mirrors the on-chain OP_WITHIN bound (0 <= padding < 65536) enforced by the
# Rabin codegen. Without it the off-chain verifier accepts the universal
# forgery sig=0, padding=SHA256(msg), since (0^2 + SHA256(msg)) mod n ==
# SHA256(msg) mod n trivially holds.
RABIN_PADDING_LIMIT = 65536


def _bytes_to_unsigned_le(b: bytes) -> int:
    """Interpret bytes as an unsigned little-endian integer."""
    return int.from_bytes(b, 'little')


def rabin_verify(msg: bytes, sig: bytes, padding: bytes, pubkey: bytes) -> bool:
    """Verify a Rabin signature.

    All parameters are bytes. sig and pubkey are interpreted as unsigned
    little-endian integers. padding is also interpreted as unsigned LE.

    Equation: (sig^2 + padding) mod n === SHA256(msg) mod n

    Args:
        msg: Message bytes
        sig: Signature bytes (unsigned LE integer)
        padding: Padding bytes (unsigned LE integer)
        pubkey: Public key / modulus bytes (unsigned LE integer)

    Returns:
        True if the signature is valid.
    """
    n = _bytes_to_unsigned_le(pubkey)
    if n <= 0:
        return False

    sig_int = _bytes_to_unsigned_le(sig)
    pad_int = _bytes_to_unsigned_le(padding)

    # Enforce the same bound the deployed script checks via OP_WITHIN.
    if pad_int < 0 or pad_int >= RABIN_PADDING_LIMIT:
        return False

    # Enforce sig < n, mirroring the on-chain F-368 gate: sig + k*n squares to
    # the same residue but the deployed script aborts on it.
    if sig_int >= n:
        return False

    hash_bytes = hashlib.sha256(msg).digest()
    hash_int = _bytes_to_unsigned_le(hash_bytes)

    lhs = (sig_int * sig_int + pad_int) % n
    rhs = hash_int % n
    return lhs == rhs
