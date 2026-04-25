package sp1fri

// KoalaBear Montgomery / canonical-form conversion.
//
// Plonky3 serialises KoalaBear elements in Montgomery form for speed:
// the wire byte stream carries `monty(x) = x · R mod p` where
// R = 2^32 mod p. The on-chain Bitcoin Script verifier and the Go
// reference verifier both operate on canonical values (0..p-1).
//
// Constants pinned at compile time so callers do not pay an
// initialisation cost. Verified against Plonky3
// `monty-31/src/monty_31.rs` for the KoalaBear instantiation.

import "math/big"

// kbR is R = 2^32 mod p for KoalaBear (used in Montgomery form).
//
//	2^32 = 4_294_967_296
//	p    = 2_130_706_433
//	R    = 2^32 mod p = 33_554_430
const kbR uint32 = 33_554_430

// kbRInv is R^{-1} mod p, precomputed via Fermat: R^{-1} = R^(p-2) mod p.
//
// Computed once at package init via big.Int; cached here as a literal
// after verification so consumers can grep the constant.
var kbRInv uint32 = computeKbRInv()

// kbPrimeBig is the KoalaBear prime as a big.Int for one-shot init helpers.
var kbPrimeBig = new(big.Int).SetUint64(uint64(KbPrime))

// computeKbRInv computes R^{-1} mod p once at package load.
func computeKbRInv() uint32 {
	r := new(big.Int).SetUint64(uint64(kbR))
	pMinus2 := new(big.Int).Sub(kbPrimeBig, big.NewInt(2))
	rInv := new(big.Int).Exp(r, pMinus2, kbPrimeBig)
	return uint32(rInv.Uint64())
}

// Canonical converts a Montgomery-form KoalaBear element to its canonical
// representation in [0, p).
func (x KbElement) Canonical() uint32 {
	// canonical = monty · R^{-1} mod p
	v := uint64(x) * uint64(kbRInv) % uint64(KbPrime)
	return uint32(v)
}

// KbFromCanonical converts a canonical value (0..p-1) into Montgomery form.
func KbFromCanonical(v uint32) KbElement {
	if v >= KbPrime {
		v %= KbPrime
	}
	m := uint64(v) * uint64(kbR) % uint64(KbPrime)
	return KbElement(m)
}

// CanonicalSlice converts a slice of Montgomery-form base elements into
// canonical form. Used at the boundary between proof bytes and the Go
// reference verifier.
func CanonicalSlice(xs []KbElement) []uint32 {
	out := make([]uint32, len(xs))
	for i, x := range xs {
		out[i] = x.Canonical()
	}
	return out
}

// CanonicalDigest converts an 8-element digest from Montgomery to canonical.
func CanonicalDigest(d KbDigest) [8]uint32 {
	var out [8]uint32
	for i, x := range d {
		out[i] = x.Canonical()
	}
	return out
}

// CanonicalExt4 converts a quartic-extension element from Montgomery to
// canonical, returning the 4 coefficients in the same coefficient order.
func CanonicalExt4(e KbExt4) [4]uint32 {
	var out [4]uint32
	for i, x := range e {
		out[i] = x.Canonical()
	}
	return out
}
