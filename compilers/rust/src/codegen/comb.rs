//! Fixed-base comb: compile-time table, and the soundness check that decides
//! where the cheap incomplete addition may be used.
//!
//! Port of `packages/runar-compiler/src/passes/comb.ts`. The binary ladders in
//! `ec.rs` / `p256_p384.rs` use the cheap mixed add at every step but the last,
//! justified by an interval argument over `c_i mod n`. That comment is emphatic
//! that the argument must be RE-DERIVED, not assumed, by anything which changes
//! the offset, the iteration count, or the reduce — and a comb changes all
//! three. `comb_safe_rounds` below is that re-derivation, written as executable
//! interval arithmetic rather than prose, so a round only gets the cheap add
//! when the exception is proved unreachable. Rounds it cannot prove fall back to
//! the complete add-or-double form.
//!
//! Nothing here emits Script. It is pure arithmetic over `BigInt`, run once per
//! compilation, and unit-tested against published curve vectors.

use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};
use std::sync::LazyLock;

/// An affine point. `None` is the point at infinity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombPoint {
    pub x: BigInt,
    pub y: BigInt,
}

/// A short-Weierstrass curve, for the compile-time table.
#[derive(Debug, Clone)]
pub struct CombCurve {
    /// Field prime.
    pub p: BigInt,
    /// Curve coefficient a: -3 on the NIST curves, 0 on secp256k1.
    pub a: BigInt,
    /// Curve coefficient b.
    pub b: BigInt,
    /// Group order.
    pub n: BigInt,
    /// Base point.
    pub g: CombPoint,
}

/// Comb geometry for one window width, chosen so the top digit is never zero.
///
/// The binary ladder hardcodes `k + 3n`, which puts the scalar's top bit at a
/// fixed position and so keeps the accumulator off the point at infinity. A comb
/// needs the same guarantee, but its first round reads bit `w*d - 1`, so the
/// offset has to be chosen against `w*d` rather than assumed. `offset_multiple`
/// is the smallest `m` for which every `k + m*n` has bit `w*d - 1` set:
///
/// ```text
/// m*n >= 2^(w*d - 1)   and   (m+1)*n - 1 < 2^(w*d)
/// ```
///
/// `m*n ≡ 0 (mod n)` so the result is unchanged. For P-256 at w=3 the search
/// returns m=3, d=86 — i.e. exactly the `+3n` the binary ladder already uses.
/// For P-384 at w=3 it returns m=5, d=129; assuming `+3n` there would have left
/// the top digit free to be zero.
#[derive(Debug, Clone)]
pub struct CombParams {
    pub w: usize,
    /// Rounds, and the block width. Digit `i` reads bits `i, i+d, ..., i+(w-1)d`.
    pub d: usize,
    pub offset_multiple: BigInt,
    /// Inclusive scalar domain after the offset.
    pub lo: BigInt,
    pub hi: BigInt,
}

fn hex_big(s: &str) -> BigInt {
    BigInt::parse_bytes(s.as_bytes(), 16).expect("comb: bad hex constant")
}

/// P-256, P-384 and secp256k1 — the three curves the comb is wired for.
///
/// secp256k1 is NOT built from the NIST template: it is `y² = x³ + 7`, so
/// `a = 0`. Getting `a` wrong here does not produce an obviously broken table —
/// it produces a table of points on a DIFFERENT curve, which that other curve's
/// on-curve check would happily accept. Hence the published 2G vectors pinned in
/// `comb_tests.rs`.
pub static P256_COMB_CURVE: LazyLock<CombCurve> = LazyLock::new(|| CombCurve {
    p: hex_big("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
    a: BigInt::from(-3),
    b: hex_big("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    n: hex_big("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
    g: CombPoint {
        x: hex_big("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        y: hex_big("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    },
});

pub static P384_COMB_CURVE: LazyLock<CombCurve> = LazyLock::new(|| CombCurve {
    p: hex_big("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
    a: BigInt::from(-3),
    b: hex_big("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
    n: hex_big("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
    g: CombPoint {
        x: hex_big("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
        y: hex_big("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
    },
});

pub static SECP256K1_COMB_CURVE: LazyLock<CombCurve> = LazyLock::new(|| CombCurve {
    p: hex_big("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
    a: BigInt::zero(),
    b: BigInt::from(7),
    n: hex_big("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
    g: CombPoint {
        x: hex_big("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        y: hex_big("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
    },
});

/// Geometry for window width `w`, or `None` if no offset in the search range
/// puts a guaranteed set bit at the top of the first digit. Returning `None`
/// rather than guessing keeps the caller from silently combing a scalar whose
/// leading digit can vanish.
pub fn comb_geometry(w: usize, c: &CombCurve) -> Option<CombParams> {
    let base = (c.n.bits() as usize).div_ceil(w);
    for d in base..=base + 2 {
        let bits = (w * d) as u64;
        let top = BigInt::one() << (bits - 1);
        let cap = BigInt::one() << bits;
        for m in 1i64..=16 {
            let mm = BigInt::from(m);
            let lo = &mm * &c.n;
            let hi = (&mm + BigInt::one()) * &c.n - BigInt::one();
            if lo >= top && hi < cap {
                return Some(CombParams { w, d, offset_multiple: mm, lo, hi });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Affine arithmetic (compile time only)
// ---------------------------------------------------------------------------

fn comb_mod(v: &BigInt, m: &BigInt) -> BigInt {
    let r = v % m;
    if r.is_negative() { r + m } else { r }
}

/// Modular inverse by extended Euclid. `v` is never 0 on the paths below.
fn inv(v: &BigInt, m: &BigInt) -> BigInt {
    let (mut old_r, mut r) = (comb_mod(v, m), m.clone());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    while !r.is_zero() {
        let q = &old_r / &r;
        let nr = &old_r - &q * &r;
        old_r = r;
        r = nr;
        let ns = &old_s - &q * &s;
        old_s = s;
        s = ns;
    }
    comb_mod(&old_s, m)
}

/// Affine addition. `None` is the point at infinity.
pub fn comb_affine_add(
    p: Option<&CombPoint>,
    q: Option<&CombPoint>,
    c: &CombCurve,
) -> Option<CombPoint> {
    let (p, q) = match (p, q) {
        (None, _) => return q.cloned(),
        (_, None) => return p.cloned(),
        (Some(p), Some(q)) => (p, q),
    };
    if p.x == q.x {
        if comb_mod(&(&p.y + &q.y), &c.p).is_zero() {
            return None; // P == -Q
        }
        // Tangent.
        let num = comb_mod(&(BigInt::from(3) * &p.x * &p.x + &c.a), &c.p);
        let den = inv(&comb_mod(&(&p.y * 2), &c.p), &c.p);
        let lam = comb_mod(&(num * den), &c.p);
        let x = comb_mod(&(&lam * &lam - &p.x * 2), &c.p);
        let y = comb_mod(&(&lam * (&p.x - &x) - &p.y), &c.p);
        return Some(CombPoint { x, y });
    }
    let den = inv(&comb_mod(&(&q.x - &p.x), &c.p), &c.p);
    let lam = comb_mod(&(comb_mod(&(&q.y - &p.y), &c.p) * den), &c.p);
    let x = comb_mod(&(&lam * &lam - &p.x - &q.x), &c.p);
    let y = comb_mod(&(&lam * (&p.x - &x) - &p.y), &c.p);
    Some(CombPoint { x, y })
}

/// Compile-time double-and-add. `None` is the point at infinity.
pub fn comb_scalar_mul(k: &BigInt, p: &CombPoint, c: &CombCurve) -> Option<CombPoint> {
    let mut r: Option<CombPoint> = None;
    let mut base = Some(p.clone());
    let mut e = comb_mod(k, &c.n);
    while e.is_positive() {
        if e.bit(0) {
            r = comb_affine_add(r.as_ref(), base.as_ref(), c);
        }
        base = comb_affine_add(base.as_ref(), base.as_ref(), c);
        e >>= 1;
    }
    r
}

// ---------------------------------------------------------------------------
// Comb table
// ---------------------------------------------------------------------------

/// The multiple of G that table entry `j` represents.
///
/// Comb round `i` consumes bits `{i, i+d, i+2d, ...}` of the scalar — one from
/// each block — so entry `j` stands for the sum of `2^(t*d)` over the set bits
/// `t` of `j`.
pub fn comb_value(j: usize, d: usize) -> BigInt {
    let mut v = BigInt::zero();
    let mut t = 0usize;
    while (j >> t) != 0 {
        if (j >> t) & 1 == 1 {
            v += BigInt::one() << (t * d) as u64;
        }
        t += 1;
    }
    v
}

/// `T[j] = comb_value(j)·G`. Index 0 is the point at infinity and is never added.
pub fn comb_table(w: usize, d: usize, c: &CombCurve) -> Vec<Option<CombPoint>> {
    (0..(1usize << w))
        .map(|j| if j == 0 { None } else { comb_scalar_mul(&comb_value(j, d), &c.g, c) })
        .collect()
}

// ---------------------------------------------------------------------------
// Soundness: where may the cheap incomplete addition be used?
// ---------------------------------------------------------------------------

/// Bounds on the comb accumulator's multiplier before round `i`'s doubling.
///
/// After processing rounds `d-1 .. i`, the accumulator is `c_i·G` with
///
/// ```text
/// c_i = Σ_m 2^(m·d) · floor(K_m / 2^i)
/// ```
///
/// where `K_m` is the m-th `d`-bit block of the expanded scalar. Each floor
/// discards less than one unit of its block, so
///
/// ```text
/// k/2^i - Σ_m 2^(m·d)  <  c_i  <=  k/2^i
/// ```
///
/// and with `k` confined to `[lo, hi]` that gives a contiguous interval. The
/// slack term is bounded by `2^(w·d)/(2^d - 1)`, far below `n`, which is why the
/// interval stays narrower than the group order for all but the last few rounds
/// — exactly the property the binary ladder's argument relies on.
fn accumulator_interval(i: usize, params: &CombParams) -> (BigInt, BigInt) {
    let mut slack = BigInt::zero();
    for m in 0..params.w {
        slack += BigInt::one() << (m * params.d) as u64;
    }
    let hi = &params.hi >> i as u64;
    let lo = (&params.lo >> i as u64) - slack;
    (if lo.is_negative() { BigInt::zero() } else { lo }, hi)
}

/// Does `[lo, hi]` contain an integer congruent to `target` modulo `n`?
fn interval_hits_residue(lo: &BigInt, hi: &BigInt, target: &BigInt, n: &BigInt) -> bool {
    if hi < lo {
        return false;
    }
    if hi - lo + BigInt::one() >= *n {
        return true; // wraps a full residue class
    }
    let t = comb_mod(target, n);
    // Smallest value >= lo that is congruent to t (mod n).
    let first = lo + comb_mod(&(t - lo), n);
    first <= *hi
}

/// Per-round verdict: may round `i` use the cheap incomplete mixed add?
///
/// The exception the cheap formula cannot represent is a pre-add accumulator
/// equal to the addend, its negation, or the point at infinity. After round
/// `i`'s doubling the accumulator is `2·c_{i+1}·G`, and the addend is
/// `comb_value(j)·G` for whichever digit `j` the scalar selects — so the round
/// is safe exactly when, for every `j`,
///
/// ```text
/// 2·c_{i+1} ≢ 0, +comb_value(j), -comb_value(j)   (mod n)
/// ```
///
/// over the whole interval of `c_{i+1}`. Both `G` and every table entry are
/// compile-time constants and the curves have cofactor 1, so `ord(G) = n` and
/// this is decidable here. Anything the checker cannot prove gets the complete
/// add-or-double form instead; `true` is never assumed.
///
/// Index `d-1` is `false` by construction: that round initialises the
/// accumulator from the table and performs no addition at all.
pub fn comb_safe_rounds(params: &CombParams, c: &CombCurve) -> Vec<bool> {
    let values: Vec<BigInt> = (1..(1usize << params.w))
        .map(|j| comb_value(j, params.d))
        .collect();

    let mut safe = vec![false; params.d];
    for i in 0..params.d {
        if i == params.d - 1 {
            continue;
        }
        let (lo, hi) = accumulator_interval(i + 1, params);
        let d_lo = lo << 1u32;
        let d_hi = hi << 1u32;
        let mut ok = !interval_hits_residue(&d_lo, &d_hi, &BigInt::zero(), &c.n);
        for v in &values {
            if !ok {
                break;
            }
            ok = !interval_hits_residue(&d_lo, &d_hi, v, &c.n)
                && !interval_hits_residue(&d_lo, &d_hi, &(-v), &c.n);
        }
        safe[i] = ok;
    }
    safe
}
