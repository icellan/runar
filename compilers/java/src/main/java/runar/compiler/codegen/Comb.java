package runar.compiler.codegen;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Fixed-base comb: compile-time table, and the soundness check that decides where the cheap
 * incomplete addition may be used.
 *
 * <p>Port of {@code packages/runar-compiler/src/passes/comb.ts}. The binary ladders in {@code
 * Ec.java} / {@code P256P384.java} use the cheap mixed add at every step but the last, justified by
 * an interval argument over {@code c_i mod n}. That comment is emphatic that the argument must be
 * RE-DERIVED, not assumed, by anything which changes the offset, the iteration count, or the reduce
 * — and a comb changes all three. {@link #combSafeRounds} below is that re-derivation, written as
 * executable interval arithmetic rather than prose, so a round only gets the cheap add when the
 * exception is proved unreachable. Rounds it cannot prove fall back to the complete add-or-double
 * form.
 *
 * <p>Nothing here emits Script. It is pure {@link BigInteger} arithmetic, run once per compilation,
 * and unit-tested against published curve vectors.
 */
public final class Comb {

    private Comb() {}

    /** An affine point. A {@code null} reference is the point at infinity. */
    public record Point(BigInteger x, BigInteger y) {}

    /**
     * A short-Weierstrass curve, for the compile-time table.
     *
     * @param p field prime
     * @param a curve coefficient: -3 on the NIST curves, 0 on secp256k1
     * @param b curve coefficient
     * @param n group order
     * @param g base point
     */
    public record Curve(BigInteger p, BigInteger a, BigInteger b, BigInteger n, Point g) {}

    /**
     * Comb geometry for one window width, chosen so the top digit is never zero.
     *
     * <p>The binary ladder hardcodes {@code k + 3n}, which puts the scalar's top bit at a fixed
     * position and so keeps the accumulator off the point at infinity. A comb needs the same
     * guarantee, but its first round reads bit {@code w*d - 1}, so the offset has to be chosen
     * against {@code w*d} rather than assumed. {@code offsetMultiple} is the smallest {@code m} for
     * which every {@code k + m*n} has bit {@code w*d - 1} set:
     *
     * <pre>{@code
     * m*n >= 2^(w*d - 1)   and   (m+1)*n - 1 < 2^(w*d)
     * }</pre>
     *
     * <p>{@code m*n == 0 (mod n)} so the result is unchanged. For P-256 at w=3 the search returns
     * m=3, d=86 — i.e. exactly the {@code +3n} the binary ladder already uses. For P-384 at w=3 it
     * returns m=5, d=129; assuming {@code +3n} there would have left the top digit free to be zero.
     *
     * @param d rounds, and the block width: digit {@code i} reads bits {@code i, i+d, ..., i+(w-1)d}
     * @param lo inclusive lower bound of the scalar domain after the offset
     * @param hi inclusive upper bound of the scalar domain after the offset
     */
    public record Params(int w, int d, int offsetMultiple, BigInteger lo, BigInteger hi) {}

    private static BigInteger hex(String s) {
        return new BigInteger(s, 16);
    }

    public static final Curve P256_COMB_CURVE =
            new Curve(
                    hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
                    BigInteger.valueOf(-3),
                    hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
                    hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
                    new Point(
                            hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
                            hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")));

    public static final Curve P384_COMB_CURVE =
            new Curve(
                    hex(
                            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
                                    + "ffffffff0000000000000000ffffffff"),
                    BigInteger.valueOf(-3),
                    hex(
                            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
                                    + "c656398d8a2ed19d2a85c8edd3ec2aef"),
                    hex(
                            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
                                    + "581a0db248b0a77aecec196accc52973"),
                    new Point(
                            hex(
                                    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
                                            + "5502f25dbf55296c3a545e3872760ab7"),
                            hex(
                                    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
                                            + "0a60b1ce1d7e819d7a431d7c90ea0e5f")));

    /**
     * secp256k1. NOT built from the NIST template: it is {@code y^2 = x^3 + 7}, so {@code a = 0}.
     * Getting {@code a} wrong here does not produce an obviously broken table — it produces a table
     * of points on a DIFFERENT curve, which that other curve's on-curve check would happily accept.
     * Hence the published 2G vectors pinned in the tests.
     */
    public static final Curve SECP256K1_COMB_CURVE =
            new Curve(
                    hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
                    BigInteger.ZERO,
                    BigInteger.valueOf(7),
                    hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
                    new Point(
                            hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
                            hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")));

    /**
     * Geometry for window width {@code w}, or {@code null} if no offset in the search range puts a
     * guaranteed set bit at the top of the first digit.
     *
     * <p>Returning {@code null} rather than guessing keeps the caller from silently combing a scalar
     * whose leading digit can vanish.
     */
    public static Params combGeometry(int w, Curve c) {
        int base = (c.n().bitLength() + w - 1) / w;
        for (int d = base; d <= base + 2; d++) {
            int bits = w * d;
            BigInteger top = BigInteger.ONE.shiftLeft(bits - 1);
            BigInteger cap = BigInteger.ONE.shiftLeft(bits);
            for (int m = 1; m <= 16; m++) {
                BigInteger mm = BigInteger.valueOf(m);
                BigInteger lo = mm.multiply(c.n());
                BigInteger hi = mm.add(BigInteger.ONE).multiply(c.n()).subtract(BigInteger.ONE);
                if (lo.compareTo(top) >= 0 && hi.compareTo(cap) < 0) {
                    return new Params(w, d, m, lo, hi);
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Affine arithmetic (compile time only)
    // ------------------------------------------------------------------

    private static BigInteger mod(BigInteger v, BigInteger m) {
        return v.mod(m);
    }

    /** Affine addition. {@code null} is the point at infinity. */
    public static Point combAffineAdd(Point p, Point q, Curve c) {
        if (p == null) {
            return q;
        }
        if (q == null) {
            return p;
        }
        if (p.x().equals(q.x())) {
            if (mod(p.y().add(q.y()), c.p()).signum() == 0) {
                return null; // P == -Q
            }
            // Tangent.
            BigInteger num =
                    mod(BigInteger.valueOf(3).multiply(p.x()).multiply(p.x()).add(c.a()), c.p());
            BigInteger den = mod(p.y().shiftLeft(1), c.p()).modInverse(c.p());
            BigInteger lam = mod(num.multiply(den), c.p());
            BigInteger x = mod(lam.multiply(lam).subtract(p.x().shiftLeft(1)), c.p());
            return new Point(x, mod(lam.multiply(p.x().subtract(x)).subtract(p.y()), c.p()));
        }
        BigInteger den = mod(q.x().subtract(p.x()), c.p()).modInverse(c.p());
        BigInteger lam = mod(mod(q.y().subtract(p.y()), c.p()).multiply(den), c.p());
        BigInteger x = mod(lam.multiply(lam).subtract(p.x()).subtract(q.x()), c.p());
        return new Point(x, mod(lam.multiply(p.x().subtract(x)).subtract(p.y()), c.p()));
    }

    /** Compile-time double-and-add. {@code null} is the point at infinity. */
    public static Point combScalarMul(BigInteger k, Point p, Curve c) {
        Point r = null;
        Point base = p;
        BigInteger e = mod(k, c.n());
        while (e.signum() > 0) {
            if (e.testBit(0)) {
                r = combAffineAdd(r, base, c);
            }
            base = combAffineAdd(base, base, c);
            e = e.shiftRight(1);
        }
        return r;
    }

    // ------------------------------------------------------------------
    // Comb table
    // ------------------------------------------------------------------

    /**
     * The multiple of G that table entry {@code j} represents.
     *
     * <p>Comb round {@code i} consumes bits {@code {i, i+d, i+2d, ...}} of the scalar — one from each
     * block — so entry {@code j} stands for the sum of {@code 2^(t*d)} over the set bits {@code t} of
     * {@code j}.
     */
    public static BigInteger combValue(int j, int d) {
        BigInteger v = BigInteger.ZERO;
        for (int t = 0; (j >> t) != 0; t++) {
            if (((j >> t) & 1) == 1) {
                v = v.add(BigInteger.ONE.shiftLeft(t * d));
            }
        }
        return v;
    }

    /** {@code T[j] = combValue(j)*G}. Index 0 is the point at infinity and is never added. */
    public static List<Point> combTable(int w, int d, Curve c) {
        List<Point> table = new ArrayList<>();
        for (int j = 0; j < (1 << w); j++) {
            table.add(j == 0 ? null : combScalarMul(combValue(j, d), c.g(), c));
        }
        return table;
    }

    // ------------------------------------------------------------------
    // Soundness: where may the cheap incomplete addition be used?
    // ------------------------------------------------------------------

    /**
     * Bounds on the comb accumulator's multiplier before round {@code i}'s doubling.
     *
     * <p>After processing rounds {@code d-1 .. i}, the accumulator is {@code c_i*G} with
     *
     * <pre>{@code
     * c_i = sum_m 2^(m*d) * floor(K_m / 2^i)
     * }</pre>
     *
     * where {@code K_m} is the m-th {@code d}-bit block of the expanded scalar. Each floor discards
     * less than one unit of its block, so
     *
     * <pre>{@code
     * k/2^i - sum_m 2^(m*d)  <  c_i  <=  k/2^i
     * }</pre>
     *
     * and with {@code k} confined to {@code [lo, hi]} that gives a contiguous interval. The slack
     * term is bounded by {@code 2^(w*d)/(2^d - 1)}, far below {@code n}, which is why the interval
     * stays narrower than the group order for all but the last few rounds — exactly the property the
     * binary ladder's argument relies on.
     */
    private static BigInteger[] accumulatorInterval(int i, Params params) {
        BigInteger slack = BigInteger.ZERO;
        for (int m = 0; m < params.w(); m++) {
            slack = slack.add(BigInteger.ONE.shiftLeft(m * params.d()));
        }
        BigInteger hi = params.hi().shiftRight(i);
        BigInteger lo = params.lo().shiftRight(i).subtract(slack);
        return new BigInteger[] {lo.signum() < 0 ? BigInteger.ZERO : lo, hi};
    }

    /** Does {@code [lo, hi]} contain an integer congruent to {@code target} modulo {@code n}? */
    private static boolean intervalHitsResidue(
            BigInteger lo, BigInteger hi, BigInteger target, BigInteger n) {
        if (hi.compareTo(lo) < 0) {
            return false;
        }
        if (hi.subtract(lo).add(BigInteger.ONE).compareTo(n) >= 0) {
            return true; // wraps a full residue class
        }
        BigInteger t = mod(target, n);
        // Smallest value >= lo that is congruent to t (mod n).
        BigInteger first = lo.add(mod(t.subtract(lo), n));
        return first.compareTo(hi) <= 0;
    }

    /**
     * Per-round verdict: may round {@code i} use the cheap incomplete mixed add?
     *
     * <p>The exception the cheap formula cannot represent is a pre-add accumulator equal to the
     * addend, its negation, or the point at infinity. After round {@code i}'s doubling the
     * accumulator is {@code 2*c_{i+1}*G}, and the addend is {@code combValue(j)*G} for whichever
     * digit {@code j} the scalar selects — so the round is safe exactly when, for every {@code j},
     *
     * <pre>{@code
     * 2*c_{i+1} != 0, +combValue(j), -combValue(j)   (mod n)
     * }</pre>
     *
     * over the whole interval of {@code c_{i+1}}. Both {@code G} and every table entry are
     * compile-time constants and the curves have cofactor 1, so {@code ord(G) = n} and this is
     * decidable here. Anything the checker cannot prove gets the complete add-or-double form
     * instead; {@code true} is never assumed.
     *
     * <p>Index {@code d-1} is {@code false} by construction: that round initialises the accumulator
     * from the table and performs no addition at all.
     */
    public static boolean[] combSafeRounds(Params params, Curve c) {
        List<BigInteger> values = new ArrayList<>();
        for (int j = 1; j < (1 << params.w()); j++) {
            values.add(combValue(j, params.d()));
        }

        boolean[] safe = new boolean[params.d()];
        for (int i = 0; i < params.d(); i++) {
            if (i == params.d() - 1) {
                continue;
            }
            BigInteger[] iv = accumulatorInterval(i + 1, params);
            BigInteger dLo = iv[0].shiftLeft(1);
            BigInteger dHi = iv[1].shiftLeft(1);
            boolean ok = !intervalHitsResidue(dLo, dHi, BigInteger.ZERO, c.n());
            for (BigInteger v : values) {
                if (!ok) {
                    break;
                }
                ok =
                        !intervalHitsResidue(dLo, dHi, v, c.n())
                                && !intervalHitsResidue(dLo, dHi, v.negate(), c.n());
            }
            safe[i] = ok;
        }
        return safe;
    }
}
