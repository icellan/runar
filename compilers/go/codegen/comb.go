package codegen

import "math/big"

// Fixed-base comb: compile-time table, and the soundness check that decides
// where the cheap incomplete addition may be used.
//
// Port of packages/runar-compiler/src/passes/comb.ts. The binary ladders in
// ec.go / p256_p384.go use the cheap mixed add at every step but the last,
// justified by an interval argument over c_i mod n. That comment is emphatic
// that the argument must be RE-DERIVED, not assumed, by anything which changes
// the offset, the iteration count, or the reduce — and a comb changes all
// three. combSafeRounds below is that re-derivation, written as executable
// interval arithmetic rather than prose, so a round only gets the cheap add
// when the exception is proved unreachable. Rounds it cannot prove fall back to
// the complete add-or-double form.
//
// Nothing here emits Script. It is pure arithmetic over big.Ints, run once per
// compilation, and unit-tested against published curve vectors.

// CombPoint is an affine point. A nil *CombPoint is the point at infinity.
type CombPoint struct {
	X *big.Int
	Y *big.Int
}

// CombCurve describes a short-Weierstrass curve for the compile-time table.
type CombCurve struct {
	P *big.Int // field prime
	A *big.Int // curve coefficient a: -3 on the NIST curves, 0 on secp256k1
	B *big.Int // curve coefficient b
	N *big.Int // group order
	G *CombPoint
}

// CombParams is the comb geometry for one window width, chosen so the top
// digit is never zero.
//
// The binary ladder hardcodes k + 3n, which puts the scalar's top bit at a
// fixed position and so keeps the accumulator off the point at infinity. A comb
// needs the same guarantee, but its first round reads bit w*d - 1, so the
// offset has to be chosen against w*d rather than assumed. OffsetMultiple is
// the smallest m for which every k + m*n has bit w*d - 1 set:
//
//	m*n >= 2^(w*d - 1)   and   (m+1)*n - 1 < 2^(w*d)
//
// m*n == 0 (mod n) so the result is unchanged. For P-256 at w=3 the search
// returns m=3, d=86 — i.e. exactly the +3n the binary ladder already uses. For
// P-384 at w=3 it returns m=5, d=129; assuming +3n there would have left the
// top digit free to be zero.
type CombParams struct {
	W int
	// D is the round count, and the block width. Digit i reads bits
	// i, i+d, ..., i+(w-1)d.
	D              int
	OffsetMultiple *big.Int
	// Lo and Hi are the inclusive scalar domain after the offset.
	Lo *big.Int
	Hi *big.Int
}

func hexBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("comb: bad hex constant " + s)
	}
	return v
}

// P256CombCurve, P384CombCurve and Secp256k1CombCurve are the three curves the
// comb is wired for. secp256k1 is NOT built from the NIST template: it is
// y² = x³ + 7, so a = 0. Getting a wrong here does not produce an obviously
// broken table — it produces a table of points on a DIFFERENT curve, which that
// other curve's on-curve check would happily accept. Hence the published 2G
// vectors pinned in comb_test.go.
// Declared as direct var initializers, NOT assigned in an init() func: Go runs
// package-level var initialization BEFORE init(), so a var in another file that
// referenced these would capture nil. Dependency-ordered initialization makes
// that impossible.
var P256CombCurve = &CombCurve{
	P: hexBig("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
	A: big.NewInt(-3),
	B: hexBig("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
	N: hexBig("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
	G: &CombPoint{
		X: hexBig("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
		Y: hexBig("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
	},
}

var P384CombCurve = &CombCurve{
	P: hexBig("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
	A: big.NewInt(-3),
	B: hexBig("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
	N: hexBig("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
	G: &CombPoint{
		X: hexBig("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
		Y: hexBig("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
	},
}

var Secp256k1CombCurve = &CombCurve{
	P: hexBig("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
	A: big.NewInt(0),
	B: big.NewInt(7),
	N: hexBig("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
	G: &CombPoint{
		X: hexBig("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
		Y: hexBig("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
	},
}

// CombGeometry returns the geometry for window width w, or nil if no offset in
// the search range puts a guaranteed set bit at the top of the first digit.
// Returning nil rather than guessing keeps the caller from silently combing a
// scalar whose leading digit can vanish.
func CombGeometry(w int, c *CombCurve) *CombParams {
	base := (c.N.BitLen() + w - 1) / w
	for d := base; d <= base+2; d++ {
		bits := uint(w * d)
		top := new(big.Int).Lsh(big.NewInt(1), bits-1)
		cap_ := new(big.Int).Lsh(big.NewInt(1), bits)
		for m := int64(1); m <= 16; m++ {
			mm := big.NewInt(m)
			lo := new(big.Int).Mul(mm, c.N)
			hi := new(big.Int).Mul(new(big.Int).Add(mm, big.NewInt(1)), c.N)
			hi.Sub(hi, big.NewInt(1))
			if lo.Cmp(top) >= 0 && hi.Cmp(cap_) < 0 {
				return &CombParams{W: w, D: d, OffsetMultiple: mm, Lo: lo, Hi: hi}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Affine arithmetic (compile time only)
// ---------------------------------------------------------------------------

func combMod(v, m *big.Int) *big.Int {
	r := new(big.Int).Mod(v, m)
	if r.Sign() < 0 {
		r.Add(r, m)
	}
	return r
}

// CombAffineAdd is affine addition. A nil operand or result is the point at
// infinity.
func CombAffineAdd(p, q *CombPoint, c *CombCurve) *CombPoint {
	if p == nil {
		return q
	}
	if q == nil {
		return p
	}
	if p.X.Cmp(q.X) == 0 {
		if combMod(new(big.Int).Add(p.Y, q.Y), c.P).Sign() == 0 {
			return nil // P == -Q
		}
		// Tangent.
		num := combMod(new(big.Int).Add(
			new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p.X, p.X)), c.A), c.P)
		den := new(big.Int).ModInverse(combMod(new(big.Int).Lsh(p.Y, 1), c.P), c.P)
		lam := combMod(new(big.Int).Mul(num, den), c.P)
		x := combMod(new(big.Int).Sub(new(big.Int).Mul(lam, lam),
			new(big.Int).Lsh(p.X, 1)), c.P)
		y := combMod(new(big.Int).Sub(
			new(big.Int).Mul(lam, new(big.Int).Sub(p.X, x)), p.Y), c.P)
		return &CombPoint{X: x, Y: y}
	}
	den := new(big.Int).ModInverse(combMod(new(big.Int).Sub(q.X, p.X), c.P), c.P)
	lam := combMod(new(big.Int).Mul(combMod(new(big.Int).Sub(q.Y, p.Y), c.P), den), c.P)
	x := combMod(new(big.Int).Sub(new(big.Int).Sub(
		new(big.Int).Mul(lam, lam), p.X), q.X), c.P)
	y := combMod(new(big.Int).Sub(
		new(big.Int).Mul(lam, new(big.Int).Sub(p.X, x)), p.Y), c.P)
	return &CombPoint{X: x, Y: y}
}

// CombScalarMul is compile-time double-and-add. A nil result is infinity.
func CombScalarMul(k *big.Int, p *CombPoint, c *CombCurve) *CombPoint {
	var r *CombPoint
	base := p
	e := combMod(k, c.N)
	for e.Sign() > 0 {
		if e.Bit(0) == 1 {
			r = CombAffineAdd(r, base, c)
		}
		base = CombAffineAdd(base, base, c)
		e = new(big.Int).Rsh(e, 1)
	}
	return r
}

// ---------------------------------------------------------------------------
// Comb table
// ---------------------------------------------------------------------------

// CombValue is the multiple of G that table entry j represents.
//
// Comb round i consumes bits {i, i+d, i+2d, ...} of the scalar — one from each
// block — so entry j stands for the sum of 2^(t*d) over the set bits t of j.
func CombValue(j, d int) *big.Int {
	v := big.NewInt(0)
	for t := 0; (j >> t) != 0; t++ {
		if (j>>t)&1 == 1 {
			v.Add(v, new(big.Int).Lsh(big.NewInt(1), uint(t*d)))
		}
	}
	return v
}

// CombTable returns T[j] = CombValue(j)·G. Index 0 is the point at infinity and
// is never added.
func CombTable(w, d int, c *CombCurve) []*CombPoint {
	table := make([]*CombPoint, 1<<w)
	for j := 1; j < (1 << w); j++ {
		table[j] = CombScalarMul(CombValue(j, d), c.G, c)
	}
	return table
}

// ---------------------------------------------------------------------------
// Soundness: where may the cheap incomplete addition be used?
// ---------------------------------------------------------------------------

// accumulatorInterval bounds the comb accumulator's multiplier before round i's
// doubling.
//
// After processing rounds d-1 .. i, the accumulator is c_i·G with
//
//	c_i = Σ_m 2^(m·d) · floor(K_m / 2^i)
//
// where K_m is the m-th d-bit block of the expanded scalar. Each floor discards
// less than one unit of its block, so
//
//	k/2^i - Σ_m 2^(m·d)  <  c_i  <=  k/2^i
//
// and with k confined to [Lo, Hi] that gives a contiguous interval. The slack
// term is bounded by 2^(w·d)/(2^d - 1), far below n, which is why the interval
// stays narrower than the group order for all but the last few rounds — exactly
// the property the binary ladder's argument relies on.
func accumulatorInterval(i int, params *CombParams) (lo, hi *big.Int) {
	slack := big.NewInt(0)
	for m := 0; m < params.W; m++ {
		slack.Add(slack, new(big.Int).Lsh(big.NewInt(1), uint(m*params.D)))
	}
	hi = new(big.Int).Rsh(params.Hi, uint(i))
	lo = new(big.Int).Sub(new(big.Int).Rsh(params.Lo, uint(i)), slack)
	if lo.Sign() < 0 {
		lo = big.NewInt(0)
	}
	return lo, hi
}

// intervalHitsResidue reports whether [lo, hi] contains an integer congruent to
// target modulo n.
func intervalHitsResidue(lo, hi, target, n *big.Int) bool {
	if hi.Cmp(lo) < 0 {
		return false
	}
	span := new(big.Int).Add(new(big.Int).Sub(hi, lo), big.NewInt(1))
	if span.Cmp(n) >= 0 {
		return true // wraps a full residue class
	}
	t := combMod(target, n)
	// Smallest value >= lo that is congruent to t (mod n).
	first := new(big.Int).Add(lo, combMod(new(big.Int).Sub(t, lo), n))
	return first.Cmp(hi) <= 0
}

// CombSafeRounds gives the per-round verdict: may round i use the cheap
// incomplete mixed add?
//
// The exception the cheap formula cannot represent is a pre-add accumulator
// equal to the addend, its negation, or the point at infinity. After round i's
// doubling the accumulator is 2·c_{i+1}·G, and the addend is CombValue(j)·G for
// whichever digit j the scalar selects — so the round is safe exactly when, for
// every j,
//
//	2·c_{i+1} != 0, +CombValue(j), -CombValue(j)   (mod n)
//
// over the whole interval of c_{i+1}. Both G and every table entry are
// compile-time constants and the curves have cofactor 1, so ord(G) = n and this
// is decidable here. Anything the checker cannot prove gets the complete
// add-or-double form instead; true is never assumed.
//
// Index d-1 is false by construction: that round initialises the accumulator
// from the table and performs no addition at all.
func CombSafeRounds(params *CombParams, c *CombCurve) []bool {
	values := make([]*big.Int, 0, (1<<params.W)-1)
	for j := 1; j < (1 << params.W); j++ {
		values = append(values, CombValue(j, params.D))
	}

	safe := make([]bool, params.D)
	for i := 0; i < params.D; i++ {
		if i == params.D-1 {
			safe[i] = false
			continue
		}
		lo, hi := accumulatorInterval(i+1, params)
		dLo := new(big.Int).Lsh(lo, 1)
		dHi := new(big.Int).Lsh(hi, 1)
		ok := !intervalHitsResidue(dLo, dHi, big.NewInt(0), c.N)
		for _, v := range values {
			if !ok {
				break
			}
			ok = !intervalHitsResidue(dLo, dHi, v, c.N) &&
				!intervalHitsResidue(dLo, dHi, new(big.Int).Neg(v), c.N)
		}
		safe[i] = ok
	}
	return safe
}
