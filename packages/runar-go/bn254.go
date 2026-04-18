package runar

import (
	"math/big"
)

// BN254 field prime: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
var bn254P, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

// Bn254FieldAdd returns (a + b) mod p.
func Bn254FieldAdd(a, b *big.Int) *big.Int {
	r := new(big.Int).Add(a, b)
	r.Mod(r, bn254P)
	return r
}

// Bn254FieldSub returns (a - b) mod p (non-negative).
// Go's big.Int.Mod always returns a non-negative result (Euclidean modulus).
func Bn254FieldSub(a, b *big.Int) *big.Int {
	r := new(big.Int).Sub(a, b)
	r.Mod(r, bn254P)
	return r
}

// Bn254FieldMul returns (a * b) mod p.
func Bn254FieldMul(a, b *big.Int) *big.Int {
	r := new(big.Int).Mul(a, b)
	r.Mod(r, bn254P)
	return r
}

// Bn254FieldInv returns the multiplicative inverse of a mod p via Fermat's little theorem.
// Returns 0 for a == 0 (mathematically undefined; 0^(p-2) mod p == 0).
func Bn254FieldInv(a *big.Int) *big.Int {
	exp := new(big.Int).Sub(bn254P, big.NewInt(2))
	return new(big.Int).Exp(a, exp, bn254P)
}

// Bn254FieldNeg returns (p - a) mod p.
// Go's big.Int.Mod always returns a non-negative result (Euclidean modulus).
func Bn254FieldNeg(a *big.Int) *big.Int {
	r := new(big.Int).Sub(bn254P, a)
	r.Mod(r, bn254P)
	return r
}

// BN254 curve: y^2 = x^3 + 3 (mod p)
// Generator G1 = (1, 2)
var bn254B = big.NewInt(3)

// Bn254G1Add performs affine point addition on BN254 G1.
// Points are represented as 64-byte ByteStrings (x[32] || y[32], big-endian).
// Returns the sum P + Q. Handles identity (zero-point) and doubling cases.
// The returned slice is always freshly allocated — never aliases p1 or p2.
func Bn254G1Add(p1, p2 []byte) []byte {
	x1, y1 := bn254DecodePoint(p1)
	x2, y2 := bn254DecodePoint(p2)

	// Handle identity points (both coordinates zero). Always return a fresh
	// allocation so callers can mutate the result without touching the input.
	if x1.Sign() == 0 && y1.Sign() == 0 {
		out := make([]byte, 64)
		copy(out, p2)
		return out
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		out := make([]byte, 64)
		copy(out, p1)
		return out
	}

	// If x1 == x2
	if x1.Cmp(x2) == 0 {
		// If y1 == y2 -> point doubling
		if y1.Cmp(y2) == 0 {
			return bn254G1Double(x1, y1)
		}
		// y1 == -y2 -> result is identity
		return make([]byte, 64)
	}

	// General case: s = (y2 - y1) / (x2 - x1)
	num := new(big.Int).Sub(y2, y1)
	num.Mod(num, bn254P)
	den := new(big.Int).Sub(x2, x1)
	den.Mod(den, bn254P)
	s := new(big.Int).Mul(num, new(big.Int).ModInverse(den, bn254P))
	s.Mod(s, bn254P)

	// x3 = s^2 - x1 - x2
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, bn254P)

	// y3 = s * (x1 - x3) - y1
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, y1)
	y3.Mod(y3, bn254P)

	return bn254EncodePoint(x3, y3)
}

// bn254G1Double performs point doubling on BN254 G1.
func bn254G1Double(x, y *big.Int) []byte {
	// s = (3*x^2) / (2*y)
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, bn254P)
	num := new(big.Int).Mul(big.NewInt(3), x2)
	num.Mod(num, bn254P)
	den := new(big.Int).Mul(big.NewInt(2), y)
	den.Mod(den, bn254P)
	s := new(big.Int).Mul(num, new(big.Int).ModInverse(den, bn254P))
	s.Mod(s, bn254P)

	// x3 = s^2 - 2*x
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, new(big.Int).Mul(big.NewInt(2), x))
	x3.Mod(x3, bn254P)

	// y3 = s * (x - x3) - y
	y3 := new(big.Int).Sub(x, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, y)
	y3.Mod(y3, bn254P)

	return bn254EncodePoint(x3, y3)
}

// Bn254G1ScalarMul performs scalar multiplication on BN254 G1 using double-and-add.
// Point is a 64-byte ByteString, scalar is a big.Int.
func Bn254G1ScalarMul(p []byte, s *big.Int) []byte {
	if s.Sign() == 0 {
		return make([]byte, 64)
	}

	// Reduce scalar mod curve order (not strictly needed for mock but correct)
	k := new(big.Int).Set(s)
	if k.Sign() < 0 {
		// Negate the point and use |k|
		p = Bn254G1Negate(p)
		k.Neg(k)
	}

	result := make([]byte, 64) // identity
	addend := make([]byte, 64)
	copy(addend, p)

	for k.Sign() > 0 {
		if k.Bit(0) == 1 {
			result = Bn254G1Add(result, addend)
		}
		addend = Bn254G1Add(addend, addend)
		k.Rsh(k, 1)
	}

	return result
}

// Bn254G1Negate returns the negation of a BN254 G1 point: (x, p - y).
// The returned slice is always freshly allocated — never aliases p.
func Bn254G1Negate(p []byte) []byte {
	x, y := bn254DecodePoint(p)
	if y.Sign() == 0 {
		out := make([]byte, 64)
		copy(out, p)
		return out
	}
	yNeg := new(big.Int).Sub(bn254P, y)
	yNeg.Mod(yNeg, bn254P)
	return bn254EncodePoint(x, yNeg)
}

// Bn254G1OnCurve checks if a point is on the BN254 G1 curve: y^2 == x^3 + 3 mod p.
// The identity point (0, 0) is REJECTED here to match the compiled Script
// codegen in compilers/go/codegen/bn254.go (EmitBN254G1OnCurve), which evaluates
// y² == x³ + 3 directly and fails for (0, 0) since 0 ≠ 3.
func Bn254G1OnCurve(p []byte) bool {
	x, y := bn254DecodePoint(p)
	// y^2 mod p
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, bn254P)
	// x^3 + 3 mod p
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, bn254B)
	rhs.Mod(rhs, bn254P)
	return lhs.Cmp(rhs) == 0
}

// bn254DecodePoint decodes a 64-byte big-endian point into (x, y) big.Ints.
func bn254DecodePoint(p []byte) (*big.Int, *big.Int) {
	if len(p) != 64 {
		return new(big.Int), new(big.Int)
	}
	x := new(big.Int).SetBytes(p[:32])
	y := new(big.Int).SetBytes(p[32:])
	return x, y
}

// bn254EncodePoint encodes (x, y) as a 64-byte big-endian point.
func bn254EncodePoint(x, y *big.Int) []byte {
	buf := make([]byte, 64)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(buf[32-len(xBytes):32], xBytes)
	copy(buf[64-len(yBytes):64], yBytes)
	return buf
}

// ---------------------------------------------------------------------------
// Contract-compatible BN254 functions (Point/Bigint types)
// ---------------------------------------------------------------------------
//
// These wrap the *big.Int implementations above using the Rúnar type system
// (Point = string, Bigint = int64). BN254 field elements are 254 bits and
// don't fit in int64 — the mock implementations provide type-correct stubs
// that allow Go tests to compile and run. The compiled Bitcoin Script uses
// the real 254-bit codegen from bn254.go / bn254_ext.go.

// bn254PointToBytes converts a Rúnar Point (string) to []byte for the
// *big.Int implementations.
func bn254PointToBytes(p Point) []byte { return []byte(p) }

// bn254BytesToPoint converts []byte back to a Rúnar Point.
func bn254BytesToPoint(b []byte) Point { return Point(b) }

// Bn254G1AddP performs BN254 G1 affine addition using Point types.
func Bn254G1AddP(a, b Point) Point {
	return bn254BytesToPoint(Bn254G1Add(bn254PointToBytes(a), bn254PointToBytes(b)))
}

// Bn254G1ScalarMulP performs BN254 G1 scalar multiplication using Point/Bigint.
// The scalar is TRUNCATED to int64 in the mock; any real-world BN254 scalar
// (254 bits) is silently wrapped. Use Bn254G1ScalarMulBigP with BigintBig for
// wide scalars. The compiled Bitcoin Script uses the real 254-bit codegen
// from compilers/go/codegen/bn254.go regardless.
func Bn254G1ScalarMulP(p Point, k Bigint) Point {
	return bn254BytesToPoint(Bn254G1ScalarMul(bn254PointToBytes(p), big.NewInt(k)))
}

// Bn254G1NegateP negates a BN254 G1 point: (x, p - y).
func Bn254G1NegateP(p Point) Point {
	return bn254BytesToPoint(Bn254G1Negate(bn254PointToBytes(p)))
}

// Bn254G1OnCurveP checks if a point is on BN254 G1: y^2 == x^3 + 3 (mod p).
func Bn254G1OnCurveP(p Point) bool {
	return Bn254G1OnCurve(bn254PointToBytes(p))
}

// Bn254FieldNegP returns (p - a) mod p. In the mock, truncates to int64.
func Bn254FieldNegP(a Bigint) Bigint {
	r := Bn254FieldNeg(big.NewInt(a))
	return r.Int64()
}

// Bn254MultiPairing4 checks whether the product of 4 pairings equals the
// identity in GT: e(p1,q1) * e(p2,q2) * e(p3,q3) * e(p4,q4) == 1.
//
// Each G2 point is represented by 4 bigint coordinates (x0, x1, y0, y1)
// from the Fp2 decomposition: x = x0 + x1*u, y = y0 + y1*u.
//
// Mock: always returns true. BN254 Fp elements are 254 bits and cannot fit
// in int64, so any "real" implementation accepting Bigint coords would
// unconditionally fail on real-world fixtures. Use Bn254MultiPairing4Big
// (*big.Int coords) for tests that consume gnark-generated proofs.
// The compiled Bitcoin Script performs the real pairing check via the
// codegen in bn254_pairing.go and bn254_groth16.go regardless.
func Bn254MultiPairing4(
	p1 Point, q1x0, q1x1, q1y0, q1y1 Bigint,
	p2 Point, q2x0, q2x1, q2y0, q2y1 Bigint,
	p3 Point, q3x0, q3x1, q3y0, q3y1 Bigint,
	p4 Point, q4x0, q4x1, q4y0, q4y1 Bigint,
) bool {
	return true
}

// AssertGroth16WitnessAssisted is a DSL marker that requests the
// witness-assisted BN254 Groth16 verifier be inlined as a method-entry
// preamble in the compiled Bitcoin Script. The verifying key is supplied
// at compile time via CompileOptions.Groth16WAVKey, and the prover-supplied
// witness bundle (Miller-loop gradients, final-exponentiation witnesses,
// MSM points, proof points) is pushed onto the stack at spend time by the
// SDK helper before the regular ABI argument pushes — so the verifier
// preamble consumes them before the method body sees its arguments.
//
// Constraints (enforced by the codegen):
//
//   - The call must appear as the first statement of a method body.
//   - The compile must specify CompileOptions.Groth16WAVKey, otherwise
//     the call is rejected with an "unknown function" error.
//   - At most one method per contract may use the preamble (the verifier
//     ops are large; multi-method use is unsupported in the initial
//     implementation).
//
// Mock: no-op (no Go-side verification — same strategy as CheckSig and
// the rest of the BN254 builtins). The compiled Bitcoin Script does the
// real verification.
func AssertGroth16WitnessAssisted() {}

// AssertGroth16WitnessAssistedWithMSM is the MSM-binding counterpart to
// AssertGroth16WitnessAssisted. It triggers the stronger codegen path
// (EmitGroth16VerifierWitnessAssistedWithMSM) that recomputes the
// prepared-inputs multi-scalar multiplication on-chain and binds the
// result against 5 SP1 public-input scalars pushed in the witness
// bundle.
//
// Use this variant when the contract must be sound against a hostile
// prover that bypasses the Rúnar SDK. The raw AssertGroth16WitnessAssisted
// trusts the prover to supply a consistent prepared_inputs point; the
// MSM variant derives the expected point from config.IC (baked at compile
// time) and the 5 witness-pushed scalars (verified at spend time).
//
// After the preamble runs the 5 public-input scalars remain on the stack
// under the tracker names _pub_0 .. _pub_4 and can be consumed via the
// Groth16PublicInput(i) DSL intrinsic.
//
// Mock: no-op. The compiled Bitcoin Script does the real verification.
func AssertGroth16WitnessAssistedWithMSM() {}

// Groth16PublicInput returns the i-th SP1 public-input scalar pushed as
// part of the MSM-binding witness bundle. Valid only inside a method body
// that opens with AssertGroth16WitnessAssistedWithMSM(); calling it from
// any other context is rejected at compile time.
//
// i must be a constant in [0, 4].
//
// Mock: always returns 0. The compiled Bitcoin Script reads the named
// _pub_i tracker slot directly.
func Groth16PublicInput(i int64) Bigint {
	_ = i
	return 0
}

// Bn254MultiPairing3 checks whether the product of 3 pairings (with
// pre-computed e(alpha, beta) as Fp12 element) equals the identity.
// The last 12 bigint args are the pre-computed Fp12 value.
//
// Mock: always returns true. Use Bn254MultiPairing3Big with BigintBig
// coords for a real pairing check.
func Bn254MultiPairing3(
	p1 Point, q1x0, q1x1, q1y0, q1y1 Bigint,
	p2 Point, q2x0, q2x1, q2y0, q2y1 Bigint,
	p3 Point, q3x0, q3x1, q3y0, q3y1 Bigint,
	alphaBeta0, alphaBeta1, alphaBeta2, alphaBeta3, alphaBeta4, alphaBeta5 Bigint,
	alphaBeta6, alphaBeta7, alphaBeta8, alphaBeta9, alphaBeta10, alphaBeta11 Bigint,
) bool {
	return true
}

// ---------------------------------------------------------------------------
// Gnark/Solidity ↔ Rúnar convention converters
// ---------------------------------------------------------------------------
//
// Gnark (gnark-crypto) and the EVM BN254 precompile (EIP-197) serialize G2
// points with Fp2 components in REVERSE order compared to Rúnar:
//
//   Gnark/Solidity G2 point:  [x.A1, x.A0, y.A1, y.A0]  (imaginary first)
//   Rúnar G2 point:           [x0,   x1,   y0,   y1  ]   (real first)
//
// where A0 = real part, A1 = imaginary part, x = x0 + x1*u, y = y0 + y1*u.
//
// Gnark's Go API (e.g. gnark-crypto/ecc/bn254) uses E2{A0, A1} where A0 is
// the real part. But serialized formats (Solidity ABI, proof bytes, VK exports)
// put A1 (imaginary) first. SP1's Groth16 proof and verification key follow
// the Solidity convention.
//
// If you read G2 coordinates from Gnark's serialized output, SP1 proof bytes,
// or a Solidity verifier contract, you MUST swap each Fp2 pair before passing
// them to Rúnar's BN254 functions or the Groth16Config.

// Bn254G2FromGnark converts a G2 point from Gnark/Solidity serialized order
// to Rúnar's convention by swapping each Fp2 coordinate pair.
//
// Input:  [x_imaginary, x_real, y_imaginary, y_real]  (Gnark/Solidity)
// Output: [x_real, x_imaginary, y_real, y_imaginary]  (Rúnar)
func Bn254G2FromGnark(gnarkX1, gnarkX0, gnarkY1, gnarkY0 *big.Int) [4]*big.Int {
	return [4]*big.Int{gnarkX0, gnarkX1, gnarkY0, gnarkY1}
}

// Bn254Fp12FromGnark converts an Fp12 element from Gnark's coefficient order
// to Rúnar's convention.
//
// Both Gnark and Rúnar use the same Fp12 tower:
//
//	Fp12 = Fp6[w]/(w² - v),  Fp6 = Fp2[v]/(v³ - ξ),  Fp2 = Fp[u]/(u² + 1)
//
// And the same flat coefficient order:
//
//	[C0.B0.A0, C0.B0.A1, C0.B1.A0, C0.B1.A1, C0.B2.A0, C0.B2.A1,
//	 C1.B0.A0, C1.B0.A1, C1.B1.A0, C1.B1.A1, C1.B2.A0, C1.B2.A1]
//
// mapped to Rúnar's naming:
//
//	[a_0_0, a_0_1, a_1_0, a_1_1, a_2_0, a_2_1,
//	 b_0_0, b_0_1, b_1_0, b_1_1, b_2_0, b_2_1]
//
// This function is the identity mapping (no reordering needed), but is
// provided for documentation and to make the convention explicit.
func Bn254Fp12FromGnark(coeffs [12]*big.Int) [12]*big.Int {
	return coeffs
}
