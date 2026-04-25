package sp1fri

// Canonical-form KoalaBear field arithmetic and the BinomialExtensionField<KB,4>
// (X^4 - 3) used as the SP1 v6.0.2 challenge field.
//
// All values are *canonical* uint32 in [0, p). The decoder produces Plonky3
// Montgomery values; the verifier converts at the boundary via
// `KbElement.Canonical()` and `KbFromCanonical`. This file never touches
// Montgomery form.
//
// References:
//   - Plonky3 monty-31/src/monty_31.rs (KoalaBear specialisation)
//   - Plonky3 koala-bear/src/lib.rs                 (TWO_ADICITY = 24, GENERATOR = 3)
//   - Plonky3 field/src/extension/binomial_extension.rs (X^4 - W with W = 3 here)

import "math/big"

// kbModU64 reduces a uint64 mod p (KbPrime).
func kbModU64(x uint64) uint32 { return uint32(x % uint64(KbPrime)) }

// KbAdd returns (a + b) mod p.
func KbAdd(a, b uint32) uint32 {
	s := uint64(a) + uint64(b)
	if s >= uint64(KbPrime) {
		s -= uint64(KbPrime)
	}
	return uint32(s)
}

// KbSub returns (a - b) mod p.
func KbSub(a, b uint32) uint32 {
	if a >= b {
		return a - b
	}
	return a + KbPrime - b
}

// KbNeg returns (-a) mod p.
func KbNeg(a uint32) uint32 {
	if a == 0 {
		return 0
	}
	return KbPrime - a
}

// KbMul returns (a * b) mod p.
func KbMul(a, b uint32) uint32 { return kbModU64(uint64(a) * uint64(b)) }

// KbPow returns (base^exp) mod p.
func KbPow(base uint32, exp uint64) uint32 {
	result := uint32(1)
	b := base
	e := exp
	for e > 0 {
		if e&1 == 1 {
			result = KbMul(result, b)
		}
		b = KbMul(b, b)
		e >>= 1
	}
	return result
}

// KbInv returns a^{-1} mod p via Fermat. Panics on a == 0.
func KbInv(a uint32) uint32 {
	if a == 0 {
		panic("KbInv: zero")
	}
	return KbPow(a, uint64(KbPrime)-2)
}

// KbHalve returns a / 2 mod p.
func KbHalve(a uint32) uint32 {
	if a&1 == 0 {
		return a >> 1
	}
	return (a + KbPrime) >> 1
}

// KbFromU64 reduces a uint64 to canonical KoalaBear.
func KbFromU64(x uint64) uint32 { return kbModU64(x) }

// KbFromCanonicalSlice converts canonical-form ints into KbElement (Montgomery).
// Inverse of CanonicalSlice.
func KbToCanonical(x KbElement) uint32 { return x.Canonical() }

// ----------------------------------------------------------------------------
// Two-adic / generator constants
// ----------------------------------------------------------------------------

// kbTwoAdicity = 24. p - 1 = 2^24 * (2^7 - 1).
const KbTwoAdicity = 24

// KbGenerator = 3, a multiplicative generator of F^*. From Plonky3
// koala-bear/src/lib.rs `KoalaBearParameters::GENERATOR`.
const KbGenerator uint32 = 3

// kbTwoAdicGenerators[k] = a primitive 2^k-th root of unity in KoalaBear.
// Computed lazily on first use; populated for k in [0, 24].
var kbTwoAdicGenerators [KbTwoAdicity + 1]uint32

func init() {
	// Plonky3 derives these via: `g = GENERATOR^((p-1)/2^TWO_ADICITY)` is a
	// primitive 2^TWO_ADICITY-th root, then squaring walks down to lower orders.
	// In KoalaBear: (p-1) = 2^24 * 127, so g_24 = 3^127 mod p.
	g24 := KbPow(KbGenerator, 127)
	kbTwoAdicGenerators[KbTwoAdicity] = g24
	for k := KbTwoAdicity - 1; k >= 0; k-- {
		kbTwoAdicGenerators[k] = KbMul(kbTwoAdicGenerators[k+1], kbTwoAdicGenerators[k+1])
	}
	// k == 0 → 1
}

// KbTwoAdicGenerator returns a primitive 2^k-th root of unity in KoalaBear.
func KbTwoAdicGenerator(k int) uint32 {
	if k < 0 || k > KbTwoAdicity {
		panic("KbTwoAdicGenerator: out of range")
	}
	return kbTwoAdicGenerators[k]
}

// ----------------------------------------------------------------------------
// Ext4 = KoalaBear[X] / (X^4 - 3) — the BinomialExtensionField<KB, 4>
// ----------------------------------------------------------------------------

// Ext4 is a KbExt4 stored canonically. We use plain [4]uint32 (canonical) for
// internal arithmetic to avoid repeated Montgomery conversions.
type Ext4 [4]uint32

// kbExt4W is the binomial coefficient W: X^4 = W = 3 in canonical form.
const kbExt4W uint32 = 3

// Ext4Zero returns 0.
func Ext4Zero() Ext4 { return Ext4{} }

// Ext4One returns 1.
func Ext4One() Ext4 { return Ext4{1, 0, 0, 0} }

// Ext4FromBase wraps a base-field element as a degree-0 Ext4.
func Ext4FromBase(a uint32) Ext4 { return Ext4{a, 0, 0, 0} }

// FromKbExt4 converts a Plonky3 Montgomery-form KbExt4 into a canonical Ext4.
func FromKbExt4(e KbExt4) Ext4 {
	var out Ext4
	for i := range out {
		out[i] = e[i].Canonical()
	}
	return out
}

// Ext4Add returns a + b.
func Ext4Add(a, b Ext4) Ext4 {
	return Ext4{KbAdd(a[0], b[0]), KbAdd(a[1], b[1]), KbAdd(a[2], b[2]), KbAdd(a[3], b[3])}
}

// Ext4Sub returns a - b.
func Ext4Sub(a, b Ext4) Ext4 {
	return Ext4{KbSub(a[0], b[0]), KbSub(a[1], b[1]), KbSub(a[2], b[2]), KbSub(a[3], b[3])}
}

// Ext4Neg returns -a.
func Ext4Neg(a Ext4) Ext4 {
	return Ext4{KbNeg(a[0]), KbNeg(a[1]), KbNeg(a[2]), KbNeg(a[3])}
}

// Ext4Mul returns a * b in F[X]/(X^4 - W).
//
// (a0 + a1 x + a2 x^2 + a3 x^3) * (b0 + b1 x + b2 x^2 + b3 x^3)
//
// Schoolbook multiplication, then reduce using x^4 = W.
//
// Out coefficients:
//
//	c0 = a0 b0 + W (a1 b3 + a2 b2 + a3 b1)
//	c1 = a0 b1 + a1 b0 + W (a2 b3 + a3 b2)
//	c2 = a0 b2 + a1 b1 + a2 b0 + W (a3 b3)
//	c3 = a0 b3 + a1 b2 + a2 b1 + a3 b0
func Ext4Mul(a, b Ext4) Ext4 {
	w := uint64(kbExt4W)
	p := uint64(KbPrime)

	a0, a1, a2, a3 := uint64(a[0]), uint64(a[1]), uint64(a[2]), uint64(a[3])
	b0, b1, b2, b3 := uint64(b[0]), uint64(b[1]), uint64(b[2]), uint64(b[3])

	// Reduce intermediate products mod p before summing to stay below 2^64.
	mod := func(x uint64) uint64 { return x % p }
	c0 := mod(a0*b0) + w*(mod(a1*b3)+mod(a2*b2)+mod(a3*b1))
	c1 := mod(a0*b1) + mod(a1*b0) + w*(mod(a2*b3)+mod(a3*b2))
	c2 := mod(a0*b2) + mod(a1*b1) + mod(a2*b0) + w*mod(a3*b3)
	c3 := mod(a0*b3) + mod(a1*b2) + mod(a2*b1) + mod(a3*b0)

	return Ext4{uint32(c0 % p), uint32(c1 % p), uint32(c2 % p), uint32(c3 % p)}
}

// Ext4ScalarMul returns a * b where b is in the base field.
func Ext4ScalarMul(a Ext4, s uint32) Ext4 {
	return Ext4{KbMul(a[0], s), KbMul(a[1], s), KbMul(a[2], s), KbMul(a[3], s)}
}

// Ext4Square returns a * a.
func Ext4Square(a Ext4) Ext4 { return Ext4Mul(a, a) }

// Ext4Pow returns a^exp.
func Ext4Pow(a Ext4, exp uint64) Ext4 {
	result := Ext4One()
	base := a
	for e := exp; e > 0; e >>= 1 {
		if e&1 == 1 {
			result = Ext4Mul(result, base)
		}
		base = Ext4Square(base)
	}
	return result
}

// Ext4PowPow2 returns a^(2^k).
func Ext4PowPow2(a Ext4, k uint32) Ext4 {
	r := a
	for i := uint32(0); i < k; i++ {
		r = Ext4Square(r)
	}
	return r
}

// Ext4Inv returns a^{-1} via Fermat over the extension field.
//
// |Ext4*| = p^4 - 1, so a^{p^4 - 2} = a^{-1}. We compute via a fast exponent
// using big.Int once. (Simpler than the Itoh-Tsujii / norm-based formulas;
// the verifier only calls this O(num_queries × num_quotient_chunks) times.)
//
// Panics on a = 0.
func Ext4Inv(a Ext4) Ext4 {
	if a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 {
		panic("Ext4Inv: zero")
	}
	// Build exponent e = p^4 - 2.
	pBig := new(big.Int).SetUint64(uint64(KbPrime))
	p2 := new(big.Int).Mul(pBig, pBig)
	p4 := new(big.Int).Mul(p2, p2)
	e := new(big.Int).Sub(p4, big.NewInt(2))

	// Square-and-multiply, walking the bits of e.
	result := Ext4One()
	base := a
	for i := 0; i < e.BitLen(); i++ {
		if e.Bit(i) == 1 {
			result = Ext4Mul(result, base)
		}
		base = Ext4Square(base)
	}
	return result
}

// Ext4Div returns a / b.
func Ext4Div(a, b Ext4) Ext4 { return Ext4Mul(a, Ext4Inv(b)) }

// Ext4Equal reports element equality.
func Ext4Equal(a, b Ext4) bool {
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}
