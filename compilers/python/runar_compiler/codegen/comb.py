"""Fixed-base comb: compile-time table, and the soundness check that decides
where the cheap incomplete addition may be used.

Port of ``packages/runar-compiler/src/passes/comb.ts``. The binary ladders in
``ec.py`` / ``p256_p384.py`` use the cheap mixed add at every step but the last,
justified by an interval argument over ``c_i mod n``. That comment is emphatic
that the argument must be RE-DERIVED, not assumed, by anything which changes
the offset, the iteration count, or the reduce -- and a comb changes all three.
``comb_safe_rounds`` below is that re-derivation, written as executable interval
arithmetic rather than prose, so a round only gets the cheap add when the
exception is proved unreachable. Rounds it cannot prove fall back to the
complete add-or-double form.

Nothing here emits Script. It is pure integer arithmetic, run once per
compilation, and unit-tested against published curve vectors.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CombPoint:
    """An affine point. ``None`` (not an instance) is the point at infinity."""

    x: int
    y: int


@dataclass(frozen=True)
class CombCurve:
    """A short-Weierstrass curve, for the compile-time table."""

    p: int
    """Field prime."""
    a: int
    """Curve coefficient a: -3 on the NIST curves, 0 on secp256k1."""
    b: int
    """Curve coefficient b."""
    n: int
    """Group order."""
    g: CombPoint
    """Base point."""


@dataclass(frozen=True)
class CombParams:
    """Comb geometry for one window width, chosen so the top digit is never zero.

    The binary ladder hardcodes ``k + 3n``, which puts the scalar's top bit at a
    fixed position and so keeps the accumulator off the point at infinity. A
    comb needs the same guarantee, but its first round reads bit ``w*d - 1``, so
    the offset has to be chosen against ``w*d`` rather than assumed.
    ``offset_multiple`` is the smallest ``m`` for which every ``k + m*n`` has bit
    ``w*d - 1`` set::

        m*n >= 2^(w*d - 1)   and   (m+1)*n - 1 < 2^(w*d)

    ``m*n == 0 (mod n)`` so the result is unchanged. For P-256 at w=3 the search
    returns m=3, d=86 -- i.e. exactly the ``+3n`` the binary ladder already uses.
    For P-384 at w=3 it returns m=5, d=129; assuming ``+3n`` there would have
    left the top digit free to be zero.
    """

    w: int
    d: int
    """Rounds, and the block width. Digit ``i`` reads bits i, i+d, ..., i+(w-1)d."""
    offset_multiple: int
    lo: int
    """Inclusive scalar domain after the offset."""
    hi: int


# secp256k1 is NOT built from the NIST template: it is y^2 = x^3 + 7, so a = 0.
# Getting `a` wrong here does not produce an obviously broken table -- it
# produces a table of points on a DIFFERENT curve, which that other curve's
# on-curve check would happily accept. Hence the published 2G vectors pinned in
# the tests.
P256_COMB_CURVE = CombCurve(
    p=int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
    a=-3,
    b=int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
    n=int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
    g=CombPoint(
        x=int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        y=int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
    ),
)

P384_COMB_CURVE = CombCurve(
    p=int(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
        "ffffffff0000000000000000ffffffff", 16),
    a=-3,
    b=int(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
        "c656398d8a2ed19d2a85c8edd3ec2aef", 16),
    n=int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
        "581a0db248b0a77aecec196accc52973", 16),
    g=CombPoint(
        x=int(
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
            "5502f25dbf55296c3a545e3872760ab7", 16),
        y=int(
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
            "0a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
    ),
)

SECP256K1_COMB_CURVE = CombCurve(
    p=int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
    a=0,
    b=7,
    n=int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
    g=CombPoint(
        x=int("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
        y=int("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
    ),
)


def comb_geometry(w: int, c: CombCurve) -> CombParams | None:
    """Geometry for window width *w*, or ``None`` if no offset in the search
    range puts a guaranteed set bit at the top of the first digit.

    Returning ``None`` rather than guessing keeps the caller from silently
    combing a scalar whose leading digit can vanish.
    """
    base = -(-c.n.bit_length() // w)  # ceil
    for d in range(base, base + 3):
        bits = w * d
        top = 1 << (bits - 1)
        cap = 1 << bits
        for m in range(1, 17):
            lo = m * c.n
            hi = (m + 1) * c.n - 1
            if lo >= top and hi < cap:
                return CombParams(w=w, d=d, offset_multiple=m, lo=lo, hi=hi)
    return None


# ---------------------------------------------------------------------------
# Affine arithmetic (compile time only)
# ---------------------------------------------------------------------------

def comb_affine_add(p: CombPoint | None, q: CombPoint | None, c: CombCurve) -> CombPoint | None:
    """Affine addition. ``None`` is the point at infinity."""
    if p is None:
        return q
    if q is None:
        return p
    if p.x == q.x:
        if (p.y + q.y) % c.p == 0:
            return None  # P == -Q
        # Tangent.
        num = (3 * p.x * p.x + c.a) % c.p
        lam = (num * pow(2 * p.y % c.p, -1, c.p)) % c.p
        x = (lam * lam - 2 * p.x) % c.p
        return CombPoint(x=x, y=(lam * (p.x - x) - p.y) % c.p)
    lam = ((q.y - p.y) % c.p * pow((q.x - p.x) % c.p, -1, c.p)) % c.p
    x = (lam * lam - p.x - q.x) % c.p
    return CombPoint(x=x, y=(lam * (p.x - x) - p.y) % c.p)


def comb_scalar_mul(k: int, p: CombPoint, c: CombCurve) -> CombPoint | None:
    """Compile-time double-and-add. ``None`` is the point at infinity."""
    r: CombPoint | None = None
    base: CombPoint | None = p
    e = k % c.n
    while e > 0:
        if e & 1:
            r = comb_affine_add(r, base, c)
        base = comb_affine_add(base, base, c)
        e >>= 1
    return r


# ---------------------------------------------------------------------------
# Comb table
# ---------------------------------------------------------------------------

def comb_value(j: int, d: int) -> int:
    """The multiple of G that table entry *j* represents.

    Comb round ``i`` consumes bits ``{i, i+d, i+2d, ...}`` of the scalar -- one
    from each block -- so entry ``j`` stands for the sum of ``2^(t*d)`` over the
    set bits ``t`` of ``j``.
    """
    v = 0
    t = 0
    while (j >> t) != 0:
        if (j >> t) & 1:
            v += 1 << (t * d)
        t += 1
    return v


def comb_table(w: int, d: int, c: CombCurve) -> list[CombPoint | None]:
    """``T[j] = comb_value(j)*G``. Index 0 is infinity and is never added."""
    return [None if j == 0 else comb_scalar_mul(comb_value(j, d), c.g, c)
            for j in range(1 << w)]


# ---------------------------------------------------------------------------
# Soundness: where may the cheap incomplete addition be used?
# ---------------------------------------------------------------------------

def _accumulator_interval(i: int, params: CombParams) -> tuple[int, int]:
    """Bounds on the comb accumulator's multiplier before round *i*'s doubling.

    After processing rounds ``d-1 .. i``, the accumulator is ``c_i*G`` with::

        c_i = sum_m 2^(m*d) * floor(K_m / 2^i)

    where ``K_m`` is the m-th ``d``-bit block of the expanded scalar. Each floor
    discards less than one unit of its block, so::

        k/2^i - sum_m 2^(m*d)  <  c_i  <=  k/2^i

    and with ``k`` confined to ``[lo, hi]`` that gives a contiguous interval. The
    slack term is bounded by ``2^(w*d)/(2^d - 1)``, far below ``n``, which is why
    the interval stays narrower than the group order for all but the last few
    rounds -- exactly the property the binary ladder's argument relies on.
    """
    slack = sum(1 << (m * params.d) for m in range(params.w))
    hi = params.hi >> i
    lo = (params.lo >> i) - slack
    return (max(lo, 0), hi)


def _interval_hits_residue(lo: int, hi: int, target: int, n: int) -> bool:
    """Does ``[lo, hi]`` contain an integer congruent to *target* modulo *n*?"""
    if hi < lo:
        return False
    if hi - lo + 1 >= n:
        return True  # wraps a full residue class
    t = target % n
    # Smallest value >= lo that is congruent to t (mod n).
    first = lo + (t - lo) % n
    return first <= hi


def comb_safe_rounds(params: CombParams, c: CombCurve) -> list[bool]:
    """Per-round verdict: may round *i* use the cheap incomplete mixed add?

    The exception the cheap formula cannot represent is a pre-add accumulator
    equal to the addend, its negation, or the point at infinity. After round
    ``i``'s doubling the accumulator is ``2*c_{i+1}*G``, and the addend is
    ``comb_value(j)*G`` for whichever digit ``j`` the scalar selects -- so the
    round is safe exactly when, for every ``j``::

        2*c_{i+1} != 0, +comb_value(j), -comb_value(j)   (mod n)

    over the whole interval of ``c_{i+1}``. Both ``G`` and every table entry are
    compile-time constants and the curves have cofactor 1, so ``ord(G) = n`` and
    this is decidable here. Anything the checker cannot prove gets the complete
    add-or-double form instead; ``True`` is never assumed.

    Index ``d-1`` is ``False`` by construction: that round initialises the
    accumulator from the table and performs no addition at all.
    """
    values = [comb_value(j, params.d) for j in range(1, 1 << params.w)]

    safe = [False] * params.d
    for i in range(params.d):
        if i == params.d - 1:
            continue
        lo, hi = _accumulator_interval(i + 1, params)
        d_lo, d_hi = 2 * lo, 2 * hi
        ok = not _interval_hits_residue(d_lo, d_hi, 0, c.n)
        for v in values:
            if not ok:
                break
            ok = (not _interval_hits_residue(d_lo, d_hi, v, c.n)
                  and not _interval_hits_residue(d_lo, d_hi, -v, c.n))
        safe[i] = ok
    return safe
