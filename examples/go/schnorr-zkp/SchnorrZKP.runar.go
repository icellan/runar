//go:build ignore

// EXCLUDED FROM THE GO BUILD — the secp256k1 group order does not fit an int64.
//
//	cannot use 115792089237316195423570985008687907852837564279074904382605163141518161494337
//	(untyped int constant) as int64 value in argument to runar.Within (overflows)
//
// The malleability gate `runar.Within(s, 1, <secp256k1-n>)` needs the group
// order as its third argument, inlined as a bare decimal literal so all nine
// formats lower it to the same bigint_literal node. That value is 256 bits, and
// Go has no spelling for such a literal: constants are exact and must fit their
// type, and `runar.BigintBig` is *big.Int, which no constant converts to. The
// Rúnar conformance suite consumes this file as text through the frontend,
// where `bigint` is arbitrary precision and the literal is ordinary.
//
// The response `s` and the Fiat-Shamir challenge `e` are 256-bit too, and the
// body computes `e*k mod n` on them, so even a wide `s` parameter would not be
// enough: the arithmetic would have to go through runar.BigintBig* helpers
// while the bound stays unspellable.
//
// Shares a root cause with integer-boundary and go-dsl-bytestring-literal.
// (This note used to add "and the two NIST primitive ports". Those were a
// different problem — a scalar that only had to REACH a *big.Int parameter —
// and both build now. An earlier version of the note also claimed kinship with
// `ec-primitives`, whose exclusion turned out to be a dead `import "runar"`
// path.)

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// SchnorrZKP verifies a Schnorr zero-knowledge proof (non-interactive, Fiat-Shamir).
//
// Proves knowledge of a private key k such that P = k*G without revealing k.
// Uses the Schnorr identification protocol with the Fiat-Shamir heuristic
// to derive the challenge on-chain:
//
//	Prover: picks random r, computes R = r*G
//	Challenge: e = Bin2Num(Hash256(R || P))  (derived on-chain)
//	Prover: sends s = r + e*k (mod n)
//	Verifier: checks s*G === R + e*P
//
// The challenge is derived deterministically from the commitment and
// public key, preventing the prover from choosing a convenient e.
type SchnorrZKP struct {
	runar.SmartContract
	// PubKey is the verifier's public key P = k*G (64-byte uncompressed Point).
	PubKey runar.Point `runar:"readonly"`
}

// Verify checks a Schnorr ZKP proof.
//
// rPoint is the commitment R = r*G (prover's nonce point).
// s is the response s = r + e*k (mod n).
func (c *SchnorrZKP) Verify(rPoint runar.Point, s runar.Bigint) {
	// Bound s to the canonical range [1, n) where n is the secp256k1 group
	// order (malleability gate). Inlined as a decimal literal so every
	// frontend lowers it to the same bigint_literal ANF node (sol/move/go/
	// rust/zig all lex 0x... as a ByteString literal).
	// Value: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	runar.Assert(runar.Within(s, 1, 115792089237316195423570985008687907852837564279074904382605163141518161494337))

	// Verify R is on the curve
	runar.Assert(runar.EcOnCurve(rPoint))

	// Derive challenge via Fiat-Shamir: e = Bin2Num(Hash256(R || P))
	e := runar.Bin2Num(runar.Hash256(runar.Cat(rPoint, c.PubKey)))

	// Left side: s*G
	sG := runar.EcMulGen(s)

	// Right side: R + e*P
	eP := runar.EcMul(c.PubKey, e)
	rhs := runar.EcAdd(rPoint, eP)

	// Verify equality
	runar.Assert(runar.EcPointX(sG) == runar.EcPointX(rhs))
	runar.Assert(runar.EcPointY(sG) == runar.EcPointY(rhs))
}
