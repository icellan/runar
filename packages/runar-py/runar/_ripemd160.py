"""RIPEMD-160 with a pure-Python fallback.

OpenSSL 3 disables RIPEMD-160 in its default provider, so on many Linux
distributions ``hashlib.new('ripemd160')`` raises ``ValueError``. Every
RIPEMD-160 call in runar-py goes through :func:`ripemd160_digest`, which uses
hashlib when it can and the pure-Python implementation below otherwise. The
package stays free of required dependencies.

The module is named ``_ripemd160`` (not ``ripemd160``) so importing it never
shadows the ``runar.ripemd160`` builtin re-exported from ``runar.builtins``.
"""

import hashlib
import struct


def _hashlib_has_ripemd160() -> bool:
    try:
        hashlib.new('ripemd160')
        return True
    except ValueError:
        return False


_HAS_HASHLIB_RIPEMD160 = _hashlib_has_ripemd160()


def ripemd160_digest(data: bytes) -> bytes:
    """Return the 20-byte RIPEMD-160 digest of ``data``."""
    if _HAS_HASHLIB_RIPEMD160:
        return hashlib.new('ripemd160', data).digest()
    return _ripemd160_pure(data)


# -- Pure-Python RIPEMD-160 (Dobbertin, Bosselaers, Preneel 1996) ------------

_MASK = 0xFFFFFFFF

_R_LEFT = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)
_R_RIGHT = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)
_S_LEFT = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)
_S_RIGHT = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)
_K_LEFT = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_K_RIGHT = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | (~y & _MASK)) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | (~z & _MASK))


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK


def _compress(h: list, block: bytes) -> None:
    x = struct.unpack('<16I', block)
    al, bl, cl, dl, el = h
    ar, br, cr, dr, er = h
    for j in range(80):
        rnd = j >> 4
        t = _rol((al + _f(j, bl, cl, dl) + x[_R_LEFT[j]] + _K_LEFT[rnd]) & _MASK,
                 _S_LEFT[j])
        t = (t + el) & _MASK
        al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t
        t = _rol((ar + _f(79 - j, br, cr, dr) + x[_R_RIGHT[j]] + _K_RIGHT[rnd]) & _MASK,
                 _S_RIGHT[j])
        t = (t + er) & _MASK
        ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t
    t = (h[1] + cl + dr) & _MASK
    h[1] = (h[2] + dl + er) & _MASK
    h[2] = (h[3] + el + ar) & _MASK
    h[3] = (h[4] + al + br) & _MASK
    h[4] = (h[0] + bl + cr) & _MASK
    h[0] = t


def _ripemd160_pure(data: bytes) -> bytes:
    """Pure-Python RIPEMD-160. Used only when hashlib lacks the algorithm."""
    data = bytes(data)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = data + b'\x80' + b'\x00' * ((55 - len(data)) % 64)
    msg += struct.pack('<Q', (len(data) * 8) & 0xFFFFFFFFFFFFFFFF)
    for i in range(0, len(msg), 64):
        _compress(h, msg[i:i + 64])
    return struct.pack('<5I', *h)
