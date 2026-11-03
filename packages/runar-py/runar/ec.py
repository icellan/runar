"""Real secp256k1 elliptic curve operations.

Pure Python implementation using int arithmetic with the secp256k1 curve
parameters. No external dependencies required.
"""

# secp256k1 curve parameters
EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
EC_G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
EC_G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
EC_G = EC_G_X.to_bytes(32, 'big') + EC_G_Y.to_bytes(32, 'big')


def _decode_point(p: bytes) -> tuple[int, int]:
    """Decode 64-byte Point to (x, y) integers."""
    if len(p) != 64:
        raise ValueError(f"Point must be 64 bytes, got {len(p)}")
    x = int.from_bytes(p[:32], 'big')
    y = int.from_bytes(p[32:], 'big')
    return x, y


def _encode_point(x: int, y: int) -> bytes:
    """Encode (x, y) integers to 64-byte Point."""
    return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def _modinv(a: int, m: int) -> int:
    """Modular inverse using extended Euclidean algorithm.

    inv(0) = 0, as the compiled script's Fermat inverse gives (N-111). An
    off-curve (x, 0) doubling no longer reaches it: the script aborts (N-110).
    """
    a = a % m
    if a == 0:
        return 0
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _point_add(x1: int, y1: int, x2: int, y2: int) -> tuple[int, int]:
    """Add two points on secp256k1."""
    if x1 == 0 and y1 == 0:
        return x2, y2
    if x2 == 0 and y2 == 0:
        return x1, y1

    if x1 == x2:
        if y1 != y2:
            return 0, 0  # Point at infinity
        # N-110: the compiled tangent OP_VERIFYs py != 0 (O + O returned above).
        if y1 == 0:
            raise ValueError('ec_add: cannot double a point with y = 0 (the tangent is vertical)')
        # Point doubling
        lam = (3 * x1 * x1 * _modinv(2 * y1, EC_P)) % EC_P
    else:
        lam = ((y2 - y1) * _modinv(x2 - x1, EC_P)) % EC_P

    x3 = (lam * lam - x1 - x2) % EC_P
    y3 = (lam * (x1 - x3) - y1) % EC_P
    return x3, y3


def _point_mul(x: int, y: int, k: int) -> tuple[int, int]:
    """Scalar multiplication using double-and-add."""
    k = k % EC_N
    if k == 0:
        return 0, 0

    rx, ry = 0, 0
    qx, qy = x, y

    while k > 0:
        if k & 1:
            rx, ry = _point_add(rx, ry, qx, qy)
        qx, qy = _point_add(qx, qy, qx, qy)
        k >>= 1

    return rx, ry


# -- Public API --------------------------------------------------------------

def ec_point_x(p: bytes) -> int:
    """Extract x-coordinate from Point."""
    x, _ = _decode_point(p)
    return x


def ec_point_y(p: bytes) -> int:
    """Extract y-coordinate from Point."""
    _, y = _decode_point(p)
    return y


def ec_on_curve(p: bytes) -> bool:
    """Check if point is on secp256k1 curve."""
    # N-184: a predicate over untrusted bytes must stay total. The compiled
    # emitPointLengthGate ANDs a width flag into the result instead of
    # aborting, so a 63- or 65-byte blob is False, not a raise -- matching
    # the `if ec_on_curve(p): ... else: ...` idiom this module tells
    # contract authors to write. _decode_point raises on the wrong width,
    # which is correct for ec_add/ec_mul/ec_negate (the script aborts there
    # too) but wrong here, so this check must run before it.
    if len(p) != 64:
        return False
    x, y = _decode_point(p)
    # The all-zero blob is this codegen's encoding of the point at infinity,
    # and it is NOT on the curve: the emitted ecOnCurve is exactly
    # x < p AND y < p AND y^2 == x^3 + 7, and 0 != 7. Returning True here
    # (the projective convention) made this mock disagree with the script it
    # stands in for, so `assert(ec_on_curve(r))` passed off-chain and failed
    # on-chain for r = O -- an unspendable output found only after deploy.
    # O is now reachable from ec_add(P, -P), so this matters in practice.
    #
    # CL-BUG-161 / F-243: coordinate canonicity. _decode_point parses each
    # half as an unsigned big-endian int with no range check, so a
    # coordinate written as x0 + EC_P (still exactly 32 bytes) reaches the
    # field arithmetic below, which reduces it mod EC_P and accepts it as if
    # it were x0. The compiled script range-checks x < p AND y < p BEFORE the
    # curve-equation check (GAP-301), so this mock must reject what the
    # script rejects.
    if x >= EC_P or y >= EC_P:
        return False
    lhs = (y * y) % EC_P
    rhs = (x * x * x + 7) % EC_P
    return lhs == rhs


def _require_canonical(fn: str, x: int, y: int) -> None:
    """R-117 (N-111): the compiled ec_add / ec_negate OP_VERIFY x < p and
    y < p before any field arithmetic, so a non-canonical coordinate aborts."""
    if x >= EC_P or y >= EC_P:
        raise ValueError(
            f"{fn}: point coordinate is not a canonical field element (x and y must be < p)")


def ec_negate(p: bytes) -> bytes:
    """Negate a point (reflect over x-axis)."""
    x, y = _decode_point(p)
    _require_canonical('ec_negate', x, y)
    return _encode_point(x, (EC_P - y) % EC_P)


def ec_mod_reduce(value: int, m: int) -> int:
    """Modular reduction."""
    return value % m


def ec_add(a: bytes, b: bytes) -> bytes:
    """Add two points."""
    x1, y1 = _decode_point(a)
    x2, y2 = _decode_point(b)
    _require_canonical('ec_add', x1, y1)
    _require_canonical('ec_add', x2, y2)
    rx, ry = _point_add(x1, y1, x2, y2)
    return _encode_point(rx, ry)


def ec_mul(p: bytes, k: int) -> bytes:
    """Scalar multiplication."""
    x, y = _decode_point(p)
    # R-157 (N-111): the compiled ec_mul OP_VERIFYs `on_curve(P) or P == O`
    # before its ladder, whose +3n trick is sound only for points of order n.
    if not (x == 0 and y == 0) and not ec_on_curve(p):
        raise ValueError("ec_mul: point is neither on secp256k1 nor the point at infinity")
    rx, ry = _point_mul(x, y, k)
    return _encode_point(rx, ry)


def ec_mul_gen(k: int) -> bytes:
    """Scalar multiplication with generator point."""
    rx, ry = _point_mul(EC_G_X, EC_G_Y, k)
    return _encode_point(rx, ry)


def ec_make_point(x: int, y: int) -> bytes:
    """Create a Point from x, y coordinates.

    N-183 / R-156: the script requires 0 <= v < p for each coordinate.
    """
    if not (0 <= x < EC_P and 0 <= y < EC_P):
        raise ValueError(
            "ec_make_point: coordinate is not a field element (0 <= v < p)")
    return _encode_point(x, y)


def ec_encode_compressed(p: bytes) -> bytes:
    """Encode point in compressed format (33 bytes)."""
    x, y = _decode_point(p)
    prefix = 0x02 if y % 2 == 0 else 0x03
    return bytes([prefix]) + x.to_bytes(32, 'big')
