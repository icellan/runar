import {
  SmartContract, assert,
  ecAdd, ecMul, ecMulGen, ecNegate, ecOnCurve, ecModReduce,
  ecEncodeCompressed, ecMakePoint, ecPointX, ecPointY,
  EC_N,
} from 'runar-lang';
import type { Point, ByteString } from 'runar-lang';

/**
 * ECDemo — A stateless contract demonstrating every built-in elliptic curve
 * primitive available in Runar.
 *
 * Runar provides 10 built-in functions for secp256k1 elliptic curve arithmetic.
 * These compile into Bitcoin Script opcodes that perform real EC math on-chain,
 * enabling advanced cryptographic protocols like Schnorr signatures, zero-knowledge
 * proofs, and key derivation — all enforced by the Bitcoin network.
 *
 * **Curve: secp256k1**
 * - Field prime p = 2^256 - 2^32 - 977
 * - Group order n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 * - Generator point G is a fixed curve point; `ecMulGen(k)` computes k*G
 * - Points are 64 bytes: x[32] || y[32], big-endian unsigned, no prefix byte
 *
 * **How EC operations compile to Bitcoin Script:**
 * Each EC function expands into a sequence of stack operations during compilation.
 * For example, `ecMul` compiles to a 256-iteration double-and-add loop using
 * Jacobian coordinates — roughly 1,500 bytes of Script. `ecAdd` uses affine
 * addition with modular inverses — roughly 800 bytes. The compiler handles all
 * coordinate math automatically; the developer works with high-level point
 * operations.
 *
 * **The 10 EC primitives:**
 * 1. `ecPointX(p)` — Extract x-coordinate from a point
 * 2. `ecPointY(p)` — Extract y-coordinate from a point
 * 3. `ecMakePoint(x, y)` — Construct a point from coordinates
 * 4. `ecOnCurve(p)` — Check if a point lies on the curve
 * 5. `ecAdd(a, b)` — Add two curve points
 * 6. `ecMul(p, k)` — Scalar multiplication: k * P
 * 7. `ecMulGen(k)` — Generator multiplication: k * G (optimized)
 * 8. `ecNegate(p)` — Negate a point: (x, p - y)
 * 9. `ecModReduce(v, m)` — Modular reduction for group arithmetic
 * 10. `ecEncodeCompressed(p)` — Compress to 33-byte public key format
 *
 * This contract is stateless (`SmartContract`), so each method is an independent
 * spending condition. No signature checks are performed — the focus is purely on
 * demonstrating EC operations.
 */
class ECDemo extends SmartContract {
  /** A curve point stored as a contract property. Used as input to most methods. */
  readonly pt: Point;

  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }

  // -------------------------------------------------------------------
  // Coordinate extraction and construction
  // -------------------------------------------------------------------

  /**
   * Extract the x-coordinate from the stored point and verify it matches
   * the expected value.
   *
   * `ecPointX` splits a 64-byte Point into its first 32 bytes (big-endian
   * unsigned x-coordinate) and converts to a script number.
   *
   * Use cases: comparing public key x-coordinates, Schnorr signature
   * verification (which only uses the x-coordinate).
   */
  public checkX(expectedX: bigint) {
    assert(ecPointX(this.pt) === expectedX);
  }

  /**
   * Extract the y-coordinate from the stored point and verify it matches
   * the expected value.
   *
   * `ecPointY` splits a 64-byte Point into its last 32 bytes (big-endian
   * unsigned y-coordinate) and converts to a script number.
   *
   * Use cases: full point comparison, parity checks for compressed encoding.
   */
  public checkY(expectedY: bigint) {
    assert(ecPointY(this.pt) === expectedY);
  }

  /**
   * Construct a point from x and y coordinates, then verify the result
   * matches the expected coordinates.
   *
   * `ecMakePoint(x, y)` encodes each coordinate as a 32-byte big-endian
   * unsigned integer and concatenates them into a 64-byte Point.
   *
   * Use cases: reconstructing points from stored coordinates, building
   * points from external data.
   */
  public checkMakePoint(x: bigint, y: bigint, expectedX: bigint, expectedY: bigint) {
    const p = ecMakePoint(x, y);
    assert(ecPointX(p) === expectedX);
    assert(ecPointY(p) === expectedY);
  }

  // -------------------------------------------------------------------
  // Curve membership
  // -------------------------------------------------------------------

  /**
   * Verify the stored point lies on the secp256k1 curve.
   *
   * `ecOnCurve(p)` checks the curve equation: y^2 === x^3 + 7 (mod p).
   * Returns true if the point satisfies the equation, false otherwise.
   *
   * Use cases: validating untrusted points from transaction inputs before
   * performing EC arithmetic (prevents invalid-curve attacks).
   */
  public checkOnCurve() {
    assert(ecOnCurve(this.pt));
  }

  // -------------------------------------------------------------------
  // Point arithmetic
  // -------------------------------------------------------------------

  /**
   * Add two curve points and verify the result.
   *
   * `ecAdd(a, b)` performs elliptic curve point addition using the affine
   * addition formula:
   *   lambda = (y2 - y1) / (x2 - x1) mod p
   *   x3 = lambda^2 - x1 - x2 mod p
   *   y3 = lambda(x1 - x3) - y1 mod p
   *
   * This compiles to ~800 bytes of Bitcoin Script including a modular
   * inverse computation.
   *
   * Use cases: combining public keys (key aggregation), Schnorr multi-sig,
   * Pedersen commitments (C = v*G + r*H).
   */
  public checkAdd(other: Point, expectedX: bigint, expectedY: bigint) {
    const result = ecAdd(this.pt, other);
    assert(ecPointX(result) === expectedX);
    assert(ecPointY(result) === expectedY);
  }

  /**
   * Multiply the stored point by a scalar and verify the result.
   *
   * `ecMul(p, k)` computes k * P using a 256-bit double-and-add algorithm
   * in Jacobian coordinates (to avoid per-step modular inverses). The final
   * result is converted back to affine coordinates.
   *
   * This is the most expensive EC operation: ~1,500 bytes of Bitcoin Script
   * with a 256-iteration loop.
   *
   * Use cases: public key derivation (P = k*G), Diffie-Hellman shared
   * secrets, BIP-32 child key derivation.
   */
  public checkMul(scalar: bigint, expectedX: bigint, expectedY: bigint) {
    const result = ecMul(this.pt, scalar);
    assert(ecPointX(result) === expectedX);
    assert(ecPointY(result) === expectedY);
  }

  /**
   * Multiply the generator point G by a scalar and verify the result.
   *
   * `ecMulGen(k)` is equivalent to `ecMul(EC_G, k)` but the generator
   * point is hardcoded into the compiled script, saving the overhead of
   * pushing 64 bytes of point data.
   *
   * Use cases: deriving a public key from a private key (the fundamental
   * operation in elliptic curve cryptography), generating nonce points
   * for Schnorr proofs (R = r*G).
   */
  public checkMulGen(scalar: bigint, expectedX: bigint, expectedY: bigint) {
    const result = ecMulGen(scalar);
    assert(ecPointX(result) === expectedX);
    assert(ecPointY(result) === expectedY);
  }

  // -------------------------------------------------------------------
  // Point negation
  // -------------------------------------------------------------------

  /**
   * Negate the stored point and verify the result's y-coordinate.
   *
   * `ecNegate(p)` returns the point (x, field_prime - y). This is the
   * additive inverse: P + (-P) = point at infinity.
   *
   * Use cases: subtraction of points (A - B = A + (-B)), cancellation
   * checks in zero-knowledge proofs.
   */
  public checkNegate(expectedNegY: bigint) {
    const neg = ecNegate(this.pt);
    assert(ecPointY(neg) === expectedNegY);
  }

  /**
   * Verify that negating a point twice returns the original point.
   *
   * This demonstrates the involution property: -(-P) = P. Double negation
   * is a no-op, which the compiler can optimize away at the ANF level.
   */
  public checkNegateRoundtrip() {
    const neg1 = ecNegate(this.pt);
    const neg2 = ecNegate(neg1);
    assert(ecPointX(neg2) === ecPointX(this.pt));
    assert(ecPointY(neg2) === ecPointY(this.pt));
  }

  // -------------------------------------------------------------------
  // Modular arithmetic
  // -------------------------------------------------------------------

  /**
   * Perform modular reduction and verify the result.
   *
   * `ecModReduce(value, mod)` computes `((value % mod) + mod) % mod`,
   * ensuring the result is always non-negative. This is essential for
   * EC group arithmetic where scalars must be in [0, n-1].
   *
   * Use cases: reducing Schnorr response values mod n, ensuring private
   * key scalars are in the valid range, hash-to-scalar conversion.
   */
  public checkModReduce(value: bigint, modulus: bigint, expected: bigint) {
    assert(ecModReduce(value, modulus) === expected);
  }

  // -------------------------------------------------------------------
  // Compressed encoding
  // -------------------------------------------------------------------

  /**
   * Compress the stored point to 33-byte public key format and verify.
   *
   * `ecEncodeCompressed(p)` produces a 33-byte encoding: a prefix byte
   * (0x02 if y is even, 0x03 if y is odd) followed by the 32-byte
   * x-coordinate. This is the standard Bitcoin compressed public key format.
   *
   * Use cases: generating public key hashes for P2PKH addresses, comparing
   * computed keys against stored key hashes, interoperating with standard
   * Bitcoin tooling.
   */
  public checkEncodeCompressed(expected: ByteString) {
    const compressed = ecEncodeCompressed(this.pt);
    assert(compressed === expected);
  }

  // -------------------------------------------------------------------
  // Algebraic properties
  // -------------------------------------------------------------------

  /**
   * Verify that scalar multiplication by 1 is the identity operation.
   *
   * For any point P: 1 * P = P. This is a fundamental algebraic property
   * and a useful sanity check that ecMul handles the identity scalar.
   */
  public checkMulIdentity() {
    const result = ecMul(this.pt, 1n);
    assert(ecPointX(result) === ecPointX(this.pt));
    assert(ecPointY(result) === ecPointY(this.pt));
  }

  /**
   * Verify that the result of ecAdd lies on the curve.
   *
   * Closure property: if A and B are on the curve, then A + B is also on
   * the curve. This is guaranteed by the group law but serves as a
   * correctness check for the EC addition implementation.
   */
  public checkAddOnCurve(other: Point) {
    const result = ecAdd(this.pt, other);
    assert(ecOnCurve(result));
  }

  /**
   * Verify that a generator multiplication result lies on the curve.
   *
   * For any scalar k, k * G must be a valid curve point. This tests the
   * ecMulGen implementation produces points satisfying the curve equation.
   */
  public checkMulGenOnCurve(scalar: bigint) {
    const result = ecMulGen(scalar);
    assert(ecOnCurve(result));
  }
}
