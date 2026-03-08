package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ECDemo is a stateless contract demonstrating every built-in elliptic curve
// primitive available in Runar.
//
// Runar provides 10 built-in functions for secp256k1 elliptic curve arithmetic.
// These compile into Bitcoin Script opcodes that perform real EC math on-chain,
// enabling advanced cryptographic protocols like Schnorr signatures, zero-knowledge
// proofs, and key derivation — all enforced by the Bitcoin network.
//
// Curve: secp256k1
//   - Field prime p = 2^256 - 2^32 - 977
//   - Group order n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//   - Generator point G is a fixed curve point; ecMulGen(k) computes k*G
//   - Points are 64 bytes: x[32] || y[32], big-endian unsigned, no prefix byte
//
// How EC operations compile to Bitcoin Script:
//
// Each EC function expands into a sequence of stack operations during compilation.
// For example, ecMul compiles to a 256-iteration double-and-add loop using
// Jacobian coordinates — roughly 1,500 bytes of Script. ecAdd uses affine
// addition with modular inverses — roughly 800 bytes. The compiler handles all
// coordinate math automatically; the developer works with high-level point
// operations.
//
// The 10 EC primitives:
//  1. ecPointX(p)            — Extract x-coordinate from a point
//  2. ecPointY(p)            — Extract y-coordinate from a point
//  3. ecMakePoint(x, y)      — Construct a point from coordinates
//  4. ecOnCurve(p)           — Check if a point lies on the curve
//  5. ecAdd(a, b)            — Add two curve points
//  6. ecMul(p, k)            — Scalar multiplication: k * P
//  7. ecMulGen(k)            — Generator multiplication: k * G (optimized)
//  8. ecNegate(p)            — Negate a point: (x, p - y)
//  9. ecModReduce(v, m)      — Modular reduction for group arithmetic
//  10. ecEncodeCompressed(p) — Compress to 33-byte public key format
//
// This contract is stateless (SmartContract), so each method is an independent
// spending condition. No signature checks are performed — the focus is purely on
// demonstrating EC operations.
type ECDemo struct {
	runar.SmartContract
	Pt runar.Point `runar:"readonly"`
}

// CheckX extracts the x-coordinate from the stored point and verifies it
// matches the expected value.
//
// EcPointX splits a 64-byte Point into its first 32 bytes (big-endian
// unsigned x-coordinate) and converts to a script number.
//
// Use cases: comparing public key x-coordinates, Schnorr signature
// verification (which only uses the x-coordinate).
func (c *ECDemo) CheckX(expectedX runar.Bigint) {
	runar.Assert(runar.EcPointX(c.Pt) == expectedX)
}

// CheckY extracts the y-coordinate from the stored point and verifies it
// matches the expected value.
//
// EcPointY splits a 64-byte Point into its last 32 bytes (big-endian
// unsigned y-coordinate) and converts to a script number.
//
// Use cases: full point comparison, parity checks for compressed encoding.
func (c *ECDemo) CheckY(expectedY runar.Bigint) {
	runar.Assert(runar.EcPointY(c.Pt) == expectedY)
}

// CheckMakePoint constructs a point from x and y coordinates, then verifies
// the result matches the expected coordinates.
//
// EcMakePoint(x, y) encodes each coordinate as a 32-byte big-endian
// unsigned integer and concatenates them into a 64-byte Point.
//
// Use cases: reconstructing points from stored coordinates, building
// points from external data.
func (c *ECDemo) CheckMakePoint(x, y, expectedX, expectedY runar.Bigint) {
	p := runar.EcMakePoint(x, y)
	runar.Assert(runar.EcPointX(p) == expectedX)
	runar.Assert(runar.EcPointY(p) == expectedY)
}

// CheckOnCurve verifies the stored point lies on the secp256k1 curve.
//
// EcOnCurve(p) checks the curve equation: y^2 === x^3 + 7 (mod p).
// Returns true if the point satisfies the equation, false otherwise.
//
// Use cases: validating untrusted points from transaction inputs before
// performing EC arithmetic (prevents invalid-curve attacks).
func (c *ECDemo) CheckOnCurve() {
	runar.Assert(runar.EcOnCurve(c.Pt))
}

// CheckAdd adds two curve points and verifies the result.
//
// EcAdd(a, b) performs elliptic curve point addition using the affine
// addition formula:
//
//	lambda = (y2 - y1) / (x2 - x1) mod p
//	x3 = lambda^2 - x1 - x2 mod p
//	y3 = lambda(x1 - x3) - y1 mod p
//
// This compiles to ~800 bytes of Bitcoin Script including a modular
// inverse computation.
//
// Use cases: combining public keys (key aggregation), Schnorr multi-sig,
// Pedersen commitments (C = v*G + r*H).
func (c *ECDemo) CheckAdd(other runar.Point, expectedX, expectedY runar.Bigint) {
	result := runar.EcAdd(c.Pt, other)
	runar.Assert(runar.EcPointX(result) == expectedX)
	runar.Assert(runar.EcPointY(result) == expectedY)
}

// CheckMul multiplies the stored point by a scalar and verifies the result.
//
// EcMul(p, k) computes k * P using a 256-bit double-and-add algorithm
// in Jacobian coordinates (to avoid per-step modular inverses). The final
// result is converted back to affine coordinates.
//
// This is the most expensive EC operation: ~1,500 bytes of Bitcoin Script
// with a 256-iteration loop.
//
// Use cases: public key derivation (P = k*G), Diffie-Hellman shared
// secrets, BIP-32 child key derivation.
func (c *ECDemo) CheckMul(scalar, expectedX, expectedY runar.Bigint) {
	result := runar.EcMul(c.Pt, scalar)
	runar.Assert(runar.EcPointX(result) == expectedX)
	runar.Assert(runar.EcPointY(result) == expectedY)
}

// CheckMulGen multiplies the generator point G by a scalar and verifies
// the result.
//
// EcMulGen(k) is equivalent to EcMul(EC_G, k) but the generator
// point is hardcoded into the compiled script, saving the overhead of
// pushing 64 bytes of point data.
//
// Use cases: deriving a public key from a private key (the fundamental
// operation in elliptic curve cryptography), generating nonce points
// for Schnorr proofs (R = r*G).
func (c *ECDemo) CheckMulGen(scalar, expectedX, expectedY runar.Bigint) {
	result := runar.EcMulGen(scalar)
	runar.Assert(runar.EcPointX(result) == expectedX)
	runar.Assert(runar.EcPointY(result) == expectedY)
}

// CheckNegate negates the stored point and verifies the result's
// y-coordinate.
//
// EcNegate(p) returns the point (x, field_prime - y). This is the
// additive inverse: P + (-P) = point at infinity.
//
// Use cases: subtraction of points (A - B = A + (-B)), cancellation
// checks in zero-knowledge proofs.
func (c *ECDemo) CheckNegate(expectedNegY runar.Bigint) {
	neg := runar.EcNegate(c.Pt)
	runar.Assert(runar.EcPointY(neg) == expectedNegY)
}

// CheckNegateRoundtrip verifies that negating a point twice returns
// the original point.
//
// This demonstrates the involution property: -(-P) = P. Double negation
// is a no-op, which the compiler can optimize away at the ANF level.
func (c *ECDemo) CheckNegateRoundtrip() {
	neg1 := runar.EcNegate(c.Pt)
	neg2 := runar.EcNegate(neg1)
	runar.Assert(runar.EcPointX(neg2) == runar.EcPointX(c.Pt))
	runar.Assert(runar.EcPointY(neg2) == runar.EcPointY(c.Pt))
}

// CheckModReduce performs modular reduction and verifies the result.
//
// EcModReduce(value, mod) computes ((value % mod) + mod) % mod,
// ensuring the result is always non-negative. This is essential for
// EC group arithmetic where scalars must be in [0, n-1].
//
// Use cases: reducing Schnorr response values mod n, ensuring private
// key scalars are in the valid range, hash-to-scalar conversion.
func (c *ECDemo) CheckModReduce(value, modulus, expected runar.Bigint) {
	runar.Assert(runar.EcModReduce(value, modulus) == expected)
}

// CheckEncodeCompressed compresses the stored point to 33-byte public
// key format and verifies the result.
//
// EcEncodeCompressed(p) produces a 33-byte encoding: a prefix byte
// (0x02 if y is even, 0x03 if y is odd) followed by the 32-byte
// x-coordinate. This is the standard Bitcoin compressed public key format.
//
// Use cases: generating public key hashes for P2PKH addresses, comparing
// computed keys against stored key hashes, interoperating with standard
// Bitcoin tooling.
func (c *ECDemo) CheckEncodeCompressed(expected runar.ByteString) {
	compressed := runar.EcEncodeCompressed(c.Pt)
	runar.Assert(compressed == expected)
}

// CheckMulIdentity verifies that scalar multiplication by 1 is the
// identity operation.
//
// For any point P: 1 * P = P. This is a fundamental algebraic property
// and a useful sanity check that EcMul handles the identity scalar.
func (c *ECDemo) CheckMulIdentity() {
	result := runar.EcMul(c.Pt, 1)
	runar.Assert(runar.EcPointX(result) == runar.EcPointX(c.Pt))
	runar.Assert(runar.EcPointY(result) == runar.EcPointY(c.Pt))
}

// CheckAddOnCurve verifies that the result of EcAdd lies on the curve.
//
// Closure property: if A and B are on the curve, then A + B is also on
// the curve. This is guaranteed by the group law but serves as a
// correctness check for the EC addition implementation.
func (c *ECDemo) CheckAddOnCurve(other runar.Point) {
	result := runar.EcAdd(c.Pt, other)
	runar.Assert(runar.EcOnCurve(result))
}

// CheckMulGenOnCurve verifies that a generator multiplication result
// lies on the curve.
//
// For any scalar k, k * G must be a valid curve point. This tests the
// EcMulGen implementation produces points satisfying the curve equation.
func (c *ECDemo) CheckMulGenOnCurve(scalar runar.Bigint) {
	result := runar.EcMulGen(scalar)
	runar.Assert(runar.EcOnCurve(result))
}
