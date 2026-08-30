//! Fixed-base comb: compile-time table, and the soundness check that decides
//! where the cheap incomplete addition may be used.
//!
//! Port of `packages/runar-compiler/src/passes/comb.ts`. The binary ladders in
//! `ec_emitters.zig` / `nist_ec_emitters.zig` use the cheap mixed add at every
//! step but the last, justified by an interval argument over `c_i mod n`. That
//! comment is emphatic that the argument must be RE-DERIVED, not assumed, by
//! anything which changes the offset, the iteration count, or the reduce — and a
//! comb changes all three. `combSafeRounds` below is that re-derivation, written
//! as executable interval arithmetic rather than prose, so a round only gets the
//! cheap add when the exception is proved unreachable. Rounds it cannot prove
//! fall back to the complete add-or-double form.
//!
//! Nothing here emits Script. It is pure integer arithmetic, run once per
//! compilation, and unit-tested against published curve vectors.
//!
//! Arithmetic uses a fixed-width signed `Big` rather than `std.math.big.int`:
//! the widest value that occurs is a product of two P-384 field elements
//! (768 bits) and the widest bound is `2^(w*d)` with `w*d = 387`, so a single
//! wide type covers every curve with no allocator and no aliasing hazards.

const std = @import("std");

/// Wide enough for a product of two P-384 field elements (768 bits) with slack.
pub const Big = i1024;

/// An affine point. `null` is the point at infinity.
pub const Point = struct {
    x: Big,
    y: Big,
};

/// A short-Weierstrass curve, for the compile-time table.
pub const Curve = struct {
    /// Field prime.
    p: Big,
    /// Curve coefficient a: -3 on the NIST curves, 0 on secp256k1.
    a: Big,
    /// Curve coefficient b.
    b: Big,
    /// Group order.
    n: Big,
    /// Base point.
    g: Point,
};

/// Comb geometry for one window width, chosen so the top digit is never zero.
///
/// The binary ladder hardcodes `k + 3n`, which puts the scalar's top bit at a
/// fixed position and so keeps the accumulator off the point at infinity. A comb
/// needs the same guarantee, but its first round reads bit `w*d - 1`, so the
/// offset has to be chosen against `w*d` rather than assumed. `offset_multiple`
/// is the smallest `m` for which every `k + m*n` has bit `w*d - 1` set:
///
///     m*n >= 2^(w*d - 1)   and   (m+1)*n - 1 < 2^(w*d)
///
/// `m*n == 0 (mod n)` so the result is unchanged. For P-256 at w=3 the search
/// returns m=3, d=86 — i.e. exactly the `+3n` the binary ladder already uses.
/// For P-384 at w=3 it returns m=5, d=129; assuming `+3n` there would have left
/// the top digit free to be zero.
pub const Params = struct {
    w: usize,
    /// Rounds, and the block width. Digit `i` reads bits `i, i+d, ..., i+(w-1)d`.
    d: usize,
    offset_multiple: usize,
    /// Inclusive scalar domain after the offset.
    lo: Big,
    hi: Big,
};

fn hex(comptime s: []const u8) Big {
    var v: Big = 0;
    for (s) |ch| {
        const digit: Big = switch (ch) {
            '0'...'9' => ch - '0',
            'a'...'f' => ch - 'a' + 10,
            'A'...'F' => ch - 'A' + 10,
            else => unreachable,
        };
        v = v * 16 + digit;
    }
    return v;
}

pub const P256_COMB_CURVE = Curve{
    .p = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
    .a = -3,
    .b = hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    .n = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
    .g = .{
        .x = hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        .y = hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    },
};

pub const P384_COMB_CURVE = Curve{
    .p = hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
    .a = -3,
    .b = hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
    .n = hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
    .g = .{
        .x = hex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
        .y = hex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
    },
};

/// secp256k1. NOT built from the NIST template: it is `y^2 = x^3 + 7`, so
/// `a = 0`. Getting `a` wrong here does not produce an obviously broken table —
/// it produces a table of points on a DIFFERENT curve, which that other curve's
/// on-curve check would happily accept. Hence the published 2G vectors pinned in
/// the tests.
pub const SECP256K1_COMB_CURVE = Curve{
    .p = hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
    .a = 0,
    .b = 7,
    .n = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
    .g = .{
        .x = hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        .y = hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
    },
};

fn bitLength(v: Big) usize {
    if (v == 0) return 0;
    var n: usize = 0;
    var x = v;
    while (x != 0) : (x >>= 1) n += 1;
    return n;
}

/// Geometry for window width `w`, or null if no offset in the search range puts
/// a guaranteed set bit at the top of the first digit. Returning null rather
/// than guessing keeps the caller from silently combing a scalar whose leading
/// digit can vanish.
pub fn combGeometry(w: usize, c: Curve) ?Params {
    const base = (bitLength(c.n) + w - 1) / w;
    var d = base;
    while (d <= base + 2) : (d += 1) {
        const bits: u10 = @intCast(w * d);
        const top: Big = @as(Big, 1) << (bits - 1);
        const cap: Big = @as(Big, 1) << bits;
        var m: usize = 1;
        while (m <= 16) : (m += 1) {
            const lo = @as(Big, @intCast(m)) * c.n;
            const hi = (@as(Big, @intCast(m)) + 1) * c.n - 1;
            if (lo >= top and hi < cap) {
                return Params{ .w = w, .d = d, .offset_multiple = m, .lo = lo, .hi = hi };
            }
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Affine arithmetic (compile time only)
// ---------------------------------------------------------------------------

fn mod(v: Big, m: Big) Big {
    return @mod(v, m);
}

/// Modular inverse by extended Euclid. `v` is never 0 on the paths below.
fn modInverse(v: Big, m: Big) Big {
    var old_r: Big = mod(v, m);
    var r: Big = m;
    var old_s: Big = 1;
    var s: Big = 0;
    while (r != 0) {
        const q = @divTrunc(old_r, r);
        const nr = old_r - q * r;
        old_r = r;
        r = nr;
        const ns = old_s - q * s;
        old_s = s;
        s = ns;
    }
    return mod(old_s, m);
}

/// Affine addition. `null` is the point at infinity.
pub fn combAffineAdd(p: ?Point, q: ?Point, c: Curve) ?Point {
    const pp = p orelse return q;
    const qq = q orelse return p;

    if (pp.x == qq.x) {
        if (mod(pp.y + qq.y, c.p) == 0) return null; // P == -Q
        // Tangent.
        const num = mod(3 * mod(pp.x * pp.x, c.p) + c.a, c.p);
        const den = modInverse(mod(2 * pp.y, c.p), c.p);
        const lam = mod(mod(num * den, c.p), c.p);
        const x = mod(mod(lam * lam, c.p) - 2 * pp.x, c.p);
        return Point{ .x = x, .y = mod(mod(lam * mod(pp.x - x, c.p), c.p) - pp.y, c.p) };
    }
    const den = modInverse(mod(qq.x - pp.x, c.p), c.p);
    const lam = mod(mod(mod(qq.y - pp.y, c.p) * den, c.p), c.p);
    const x = mod(mod(lam * lam, c.p) - pp.x - qq.x, c.p);
    return Point{ .x = x, .y = mod(mod(lam * mod(pp.x - x, c.p), c.p) - pp.y, c.p) };
}

/// Compile-time double-and-add. `null` is the point at infinity.
pub fn combScalarMul(k: Big, p: Point, c: Curve) ?Point {
    var r: ?Point = null;
    var base: ?Point = p;
    var e = mod(k, c.n);
    while (e > 0) {
        if (@mod(e, 2) == 1) r = combAffineAdd(r, base, c);
        base = combAffineAdd(base, base, c);
        e >>= 1;
    }
    return r;
}

// ---------------------------------------------------------------------------
// Comb table
// ---------------------------------------------------------------------------

/// The multiple of G that table entry `j` represents.
///
/// Comb round `i` consumes bits `{i, i+d, i+2d, ...}` of the scalar — one from
/// each block — so entry `j` stands for the sum of `2^(t*d)` over the set bits
/// `t` of `j`.
pub fn combValue(j: usize, d: usize) Big {
    var v: Big = 0;
    var t: usize = 0;
    while ((j >> @intCast(t)) != 0) : (t += 1) {
        if (((j >> @intCast(t)) & 1) == 1) {
            v += @as(Big, 1) << @intCast(t * d);
        }
    }
    return v;
}

/// The maximum window width the table buffer below can hold.
pub const MAX_W: usize = 4;

/// `out[j] = combValue(j)*G`. Index 0 is the point at infinity and is never
/// added, so it is left null.
pub fn combTable(w: usize, d: usize, c: Curve, out: *[1 << MAX_W]?Point) void {
    var j: usize = 0;
    while (j < (@as(usize, 1) << @intCast(w))) : (j += 1) {
        out[j] = if (j == 0) null else combScalarMul(combValue(j, d), c.g, c);
    }
}

// ---------------------------------------------------------------------------
// Soundness: where may the cheap incomplete addition be used?
// ---------------------------------------------------------------------------

/// Bounds on the comb accumulator's multiplier before round `i`'s doubling.
///
/// After processing rounds `d-1 .. i`, the accumulator is `c_i*G` with
///
///     c_i = sum_m 2^(m*d) * floor(K_m / 2^i)
///
/// where `K_m` is the m-th `d`-bit block of the expanded scalar. Each floor
/// discards less than one unit of its block, so
///
///     k/2^i - sum_m 2^(m*d)  <  c_i  <=  k/2^i
///
/// and with `k` confined to `[lo, hi]` that gives a contiguous interval. The
/// slack term is bounded by `2^(w*d)/(2^d - 1)`, far below `n`, which is why the
/// interval stays narrower than the group order for all but the last few rounds
/// — exactly the property the binary ladder's argument relies on.
fn accumulatorInterval(i: usize, params: Params) struct { lo: Big, hi: Big } {
    var slack: Big = 0;
    var m: usize = 0;
    while (m < params.w) : (m += 1) slack += @as(Big, 1) << @intCast(m * params.d);
    const hi = params.hi >> @intCast(i);
    const lo = (params.lo >> @intCast(i)) - slack;
    return .{ .lo = if (lo < 0) 0 else lo, .hi = hi };
}

/// Does `[lo, hi]` contain an integer congruent to `target` modulo `n`?
fn intervalHitsResidue(lo: Big, hi: Big, target: Big, n: Big) bool {
    if (hi < lo) return false;
    if (hi - lo + 1 >= n) return true; // wraps a full residue class
    const t = mod(target, n);
    // Smallest value >= lo that is congruent to t (mod n).
    const first = lo + mod(t - lo, n);
    return first <= hi;
}

/// The maximum round count the verdict buffer below can hold (P-384 at w=2).
pub const MAX_D: usize = 200;

/// Per-round verdict: may round `i` use the cheap incomplete mixed add?
///
/// The exception the cheap formula cannot represent is a pre-add accumulator
/// equal to the addend, its negation, or the point at infinity. After round
/// `i`'s doubling the accumulator is `2*c_{i+1}*G`, and the addend is
/// `combValue(j)*G` for whichever digit `j` the scalar selects — so the round is
/// safe exactly when, for every `j`,
///
///     2*c_{i+1} != 0, +combValue(j), -combValue(j)   (mod n)
///
/// over the whole interval of `c_{i+1}`. Both `G` and every table entry are
/// compile-time constants and the curves have cofactor 1, so `ord(G) = n` and
/// this is decidable here. Anything the checker cannot prove gets the complete
/// add-or-double form instead; `true` is never assumed.
///
/// Index `d-1` is `false` by construction: that round initialises the
/// accumulator from the table and performs no addition at all.
pub fn combSafeRounds(params: Params, c: Curve, out: *[MAX_D]bool) void {
    var values: [1 << MAX_W]Big = undefined;
    const count = (@as(usize, 1) << @intCast(params.w)) - 1;
    var j: usize = 1;
    while (j <= count) : (j += 1) values[j - 1] = combValue(j, params.d);

    var i: usize = 0;
    while (i < params.d) : (i += 1) {
        if (i == params.d - 1) {
            out[i] = false;
            continue;
        }
        const iv = accumulatorInterval(i + 1, params);
        const d_lo = 2 * iv.lo;
        const d_hi = 2 * iv.hi;
        var ok = !intervalHitsResidue(d_lo, d_hi, 0, c.n);
        var k: usize = 0;
        while (k < count and ok) : (k += 1) {
            ok = !intervalHitsResidue(d_lo, d_hi, values[k], c.n) and
                !intervalHitsResidue(d_lo, d_hi, -values[k], c.n);
        }
        out[i] = ok;
    }
}
