"""P-256 (NIST P-256 / secp256r1) off-chain helpers for testing Rúnar contracts.

These functions use Python's standard library (hashlib, secrets) with a pure-Python
P-256 implementation. They are not compiled into Bitcoin Script — they exist so
Python contract tests can generate keys, sign messages, and verify signatures
using the P-256 curve.

P256Point is a 64-byte bytes: x[32] || y[32], big-endian, zero-padded.
This matches the Point convention used for secp256k1.
"""
import hashlib
import secrets

# P-256 curve parameters (NIST FIPS 186-4)
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_A = -3 % _P  # = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _modinv(a: int, m: int) -> int:
    """Modular inverse using extended Euclidean algorithm."""
    g, x, _ = _ext_gcd(a % m, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m


def _ext_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _ext_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _point_add(x1, y1, x2, y2):
    """Add two P-256 points. None represents the point at infinity."""
    if x1 is None:
        return x2, y2
    if x2 is None:
        return x1, y1
    if x1 == x2:
        if y1 != y2:
            return None, None  # Point at infinity
        # Doubling
        lam = (3 * x1 * x1 + _A) * _modinv(2 * y1, _P) % _P
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return x3, y3


def _point_mul(x, y, k: int):
    """Scalar multiplication on P-256."""
    k = k % _N
    if k == 0:
        return None, None
    rx, ry = None, None
    qx, qy = x, y
    while k > 0:
        if k & 1:
            rx, ry = _point_add(rx, ry, qx, qy)
        qx, qy = _point_add(qx, qy, qx, qy)
        k >>= 1
    return rx, ry


def _encode_point(x: int, y: int) -> bytes:
    """Encode P-256 (x, y) as 64-byte x[32] || y[32]."""
    return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def _decode_compressed(pub: bytes):
    """Decode 33-byte compressed P-256 public key to (x, y) ints."""
    if len(pub) != 33 or pub[0] not in (0x02, 0x03):
        raise ValueError("Invalid compressed P-256 public key")
    x = int.from_bytes(pub[1:], 'big')
    y2 = (pow(x, 3, _P) + _A * x + _B) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y2:
        raise ValueError("Point not on P-256 curve")
    if (y % 2) != (pub[0] % 2):
        y = _P - y
    return x, y


class P256KeyPair:
    """A P-256 key pair."""
    def __init__(self, sk: int, pk_x: int, pk_y: int):
        self._sk = sk
        self._pk_x = pk_x
        self._pk_y = pk_y

    @property
    def sk(self) -> int:
        """The private key scalar."""
        return self._sk

    @property
    def pk(self) -> bytes:
        """64-byte uncompressed public key: x[32] || y[32]."""
        return _encode_point(self._pk_x, self._pk_y)

    @property
    def pk_compressed(self) -> bytes:
        """33-byte compressed public key: (02/03) || x[32]."""
        prefix = 0x02 if self._pk_y % 2 == 0 else 0x03
        return bytes([prefix]) + self._pk_x.to_bytes(32, 'big')


def p256_keygen() -> P256KeyPair:
    """Generate a random P-256 key pair."""
    sk = secrets.randbelow(_N - 1) + 1
    pk_x, pk_y = _point_mul(_GX, _GY, sk)
    return P256KeyPair(sk, pk_x, pk_y)


def p256_sign(msg: bytes, sk: int) -> bytes:
    """Sign msg with P-256 ECDSA.

    The message is SHA-256 hashed internally before signing.
    Returns a 64-byte raw signature: r[32] || s[32].
    """
    digest = hashlib.sha256(msg).digest()
    z = int.from_bytes(digest, 'big')
    while True:
        k = secrets.randbelow(_N - 1) + 1
        rx, _ = _point_mul(_GX, _GY, k)
        r = rx % _N
        if r == 0:
            continue
        s = _modinv(k, _N) * (z + r * sk) % _N
        if s == 0:
            continue
        sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        return sig
