"""P-384 (NIST P-384 / secp384r1) off-chain helpers for testing Rúnar contracts.

These functions use Python's standard library (hashlib, secrets) with a pure-Python
P-384 implementation. They are not compiled into Bitcoin Script — they exist so
Python contract tests can generate keys, sign messages, and verify signatures
using the P-384 curve.

P384Point is a 96-byte bytes: x[48] || y[48], big-endian, zero-padded.
Coordinates are 48 bytes each (384 bits).
"""
import hashlib
import secrets

# P-384 curve parameters (NIST FIPS 186-4)
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
_A = -3 % _P
_B = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
_GX = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
_GY = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F


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
    """Add two P-384 points. None represents the point at infinity."""
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
    """Scalar multiplication on P-384."""
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
    """Encode P-384 (x, y) as 96-byte x[48] || y[48]."""
    return x.to_bytes(48, 'big') + y.to_bytes(48, 'big')


def _decode_compressed(pub: bytes):
    """Decode 49-byte compressed P-384 public key to (x, y) ints."""
    if len(pub) != 49 or pub[0] not in (0x02, 0x03):
        raise ValueError("Invalid compressed P-384 public key")
    x = int.from_bytes(pub[1:], 'big')
    y2 = (pow(x, 3, _P) + _A * x + _B) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y2:
        raise ValueError("Point not on P-384 curve")
    if (y % 2) != (pub[0] % 2):
        y = _P - y
    return x, y


class P384KeyPair:
    """A P-384 key pair."""
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
        """96-byte uncompressed public key: x[48] || y[48]."""
        return _encode_point(self._pk_x, self._pk_y)

    @property
    def pk_compressed(self) -> bytes:
        """49-byte compressed public key: (02/03) || x[48]."""
        prefix = 0x02 if self._pk_y % 2 == 0 else 0x03
        return bytes([prefix]) + self._pk_x.to_bytes(48, 'big')


def p384_keygen() -> P384KeyPair:
    """Generate a random P-384 key pair."""
    sk = secrets.randbelow(_N - 1) + 1
    pk_x, pk_y = _point_mul(_GX, _GY, sk)
    return P384KeyPair(sk, pk_x, pk_y)


def p384_sign(msg: bytes, sk: int) -> bytes:
    """Sign msg with P-384 ECDSA.

    The message is SHA-256 hashed internally before signing (matching the
    on-chain codegen which uses OP_SHA256 for both P-256 and P-384).
    Returns a 96-byte raw signature: r[48] || s[48].
    """
    digest = hashlib.sha256(msg).digest()
    # P-384's n is 384 bits; SHA-256 produces 256 bits, left-shift/zero-extend
    # the digest to 384 bits by reading as a big-endian integer (no adjustment
    # needed — ECDSA simply uses the integer value of the digest mod n).
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
        sig = r.to_bytes(48, 'big') + s.to_bytes(48, 'big')
        return sig
