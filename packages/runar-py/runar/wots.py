"""WOTS+ (Winternitz One-Time Signature) implementation.

RFC 8391 compatible with tweakable hash function F(pubSeed, ADRS, M).

Parameters: w=16, n=32 (SHA-256).
  len1 = 64  (message digits: 256 bits / 4 bits per digit)
  len2 = 3   (checksum digits)
  len  = 67  (total hash chains)

Signature: 67 x 32 bytes = 2,144 bytes.
Public key: 64 bytes (pubSeed(32) || pkRoot(32)).
"""

import hashlib
import os

WOTS_W = 16
WOTS_N = 32
WOTS_LOG_W = 4
WOTS_LEN1 = 64  # ceil(8*N / LOG_W) = 256/4
WOTS_LEN2 = 3   # floor(log2(LEN1*(W-1)) / LOG_W) + 1
WOTS_LEN = WOTS_LEN1 + WOTS_LEN2  # 67


def _wots_f(pub_seed: bytes, chain_idx: int, step_idx: int, msg: bytes) -> bytes:
    """Tweakable hash F(pubSeed, chainIdx, stepIdx, msg)."""
    inp = pub_seed + bytes([chain_idx, step_idx]) + msg
    return hashlib.sha256(inp).digest()


def _wots_chain(x: bytes, start_step: int, steps: int, pub_seed: bytes, chain_idx: int) -> bytes:
    """Iterate the tweakable hash function."""
    current = x
    for j in range(start_step, start_step + steps):
        current = _wots_f(pub_seed, chain_idx, j, current)
    return current


def _extract_digits(hash_bytes: bytes) -> list[int]:
    """Extract base-16 digits from a 32-byte hash."""
    digits = []
    for b in hash_bytes:
        digits.append((b >> 4) & 0x0F)
        digits.append(b & 0x0F)
    return digits


def _checksum_digits(msg_digits: list[int]) -> list[int]:
    """Compute WOTS+ checksum digits."""
    total = sum((WOTS_W - 1) - d for d in msg_digits)
    digits = [0] * WOTS_LEN2
    remaining = total
    for i in range(WOTS_LEN2 - 1, -1, -1):
        digits[i] = remaining % WOTS_W
        remaining //= WOTS_W
    return digits


def _all_digits(msg_hash: bytes) -> list[int]:
    """Return all 67 digits: 64 message + 3 checksum."""
    msg = _extract_digits(msg_hash)
    csum = _checksum_digits(msg)
    return msg + csum


class WOTSKeyPair:
    """WOTS+ keypair."""

    def __init__(self, sk: list[bytes], pk: bytes, pub_seed: bytes):
        self.sk = sk          # 67 secret key elements, each 32 bytes
        self.pk = pk          # 64-byte public key: pubSeed(32) || pkRoot(32)
        self.pub_seed = pub_seed  # 32-byte public seed


def wots_keygen(seed: bytes | None = None, pub_seed: bytes | None = None) -> WOTSKeyPair:
    """Generate a WOTS+ keypair.

    If seed is None, random keys are generated.
    If pub_seed is None, a random one is used.
    """
    ps = pub_seed if pub_seed is not None else os.urandom(WOTS_N)

    sk = []
    for i in range(WOTS_LEN):
        if seed is not None:
            buf = seed + i.to_bytes(4, 'big')
            sk.append(hashlib.sha256(buf).digest())
        else:
            sk.append(os.urandom(WOTS_N))

    # Compute chain endpoints
    endpoints = bytearray()
    for i in range(WOTS_LEN):
        endpoint = _wots_chain(sk[i], 0, WOTS_W - 1, ps, i)
        endpoints.extend(endpoint)

    pk_root = hashlib.sha256(bytes(endpoints)).digest()
    pk = ps + pk_root

    return WOTSKeyPair(sk=sk, pk=pk, pub_seed=ps)


def wots_sign(msg: bytes, sk: list[bytes], pub_seed: bytes) -> bytes:
    """Sign a message with WOTS+."""
    msg_hash = hashlib.sha256(msg).digest()
    digits = _all_digits(msg_hash)

    sig = bytearray()
    for i in range(WOTS_LEN):
        element = _wots_chain(sk[i], 0, digits[i], pub_seed, i)
        sig.extend(element)
    return bytes(sig)


def wots_verify(msg: bytes, sig: bytes, pk: bytes) -> bool:
    """Verify a WOTS+ signature."""
    if len(sig) != WOTS_LEN * WOTS_N:
        return False
    if len(pk) != 2 * WOTS_N:
        return False

    pub_seed = pk[:WOTS_N]
    pk_root = pk[WOTS_N:]

    msg_hash = hashlib.sha256(msg).digest()
    digits = _all_digits(msg_hash)

    endpoints = bytearray()
    for i in range(WOTS_LEN):
        sig_element = sig[i * WOTS_N:(i + 1) * WOTS_N]
        remaining = (WOTS_W - 1) - digits[i]
        endpoint = _wots_chain(sig_element, digits[i], remaining, pub_seed, i)
        endpoints.extend(endpoint)

    computed_root = hashlib.sha256(bytes(endpoints)).digest()
    return computed_root == pk_root
