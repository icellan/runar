require 'runar'

# ECDemo -- A stateless contract demonstrating every built-in elliptic curve
# primitive available in Runar.
#
# Runar provides 10 built-in functions for secp256k1 elliptic curve arithmetic.
# These compile into Bitcoin Script opcodes that perform real EC math on-chain,
# enabling advanced cryptographic protocols like Schnorr signatures, zero-knowledge
# proofs, and key derivation -- all enforced by the Bitcoin network.
#
# Curve: secp256k1
#   - Field prime p = 2^256 - 2^32 - 977
#   - Group order n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#   - Generator point G is a fixed curve point; ec_mul_gen(k) computes k*G
#   - Points are 64 bytes: x[32] || y[32], big-endian unsigned, no prefix byte
#
# How EC operations compile to Bitcoin Script:
#   Each EC function expands into a sequence of stack operations during
#   compilation. For example, ec_mul compiles to a 256-iteration double-and-add
#   loop using Jacobian coordinates -- roughly 1,500 bytes of Script. ec_add
#   uses affine addition with modular inverses -- roughly 800 bytes. The
#   compiler handles all coordinate math automatically; the developer works
#   with high-level point operations.
#
# The 10 EC primitives:
#   1.  ec_point_x(p)             -- Extract x-coordinate from a point
#   2.  ec_point_y(p)             -- Extract y-coordinate from a point
#   3.  ec_make_point(x, y)       -- Construct a point from coordinates
#   4.  ec_on_curve(p)            -- Check if a point lies on the curve
#   5.  ec_add(a, b)              -- Add two curve points
#   6.  ec_mul(p, k)              -- Scalar multiplication: k * P
#   7.  ec_mul_gen(k)             -- Generator multiplication: k * G (optimized)
#   8.  ec_negate(p)              -- Negate a point: (x, p - y)
#   9.  ec_mod_reduce(v, m)       -- Modular reduction for group arithmetic
#   10. ec_encode_compressed(p)   -- Compress to 33-byte public key format
#
# This contract is stateless (SmartContract), so each method is an independent
# spending condition. No signature checks are performed -- the focus is purely
# on demonstrating EC operations.

class ECDemo < Runar::SmartContract
  # A curve point stored as a contract property. Used as input to most methods.
  prop :pt, Point

  def initialize(pt)
    super(pt)
    @pt = pt
  end

  # -----------------------------------------------------------------
  # Coordinate extraction and construction
  # -----------------------------------------------------------------

  # Extract the x-coordinate from the stored point and verify it matches
  # the expected value.
  #
  # ec_point_x splits a 64-byte Point into its first 32 bytes (big-endian
  # unsigned x-coordinate) and converts to a script number.
  #
  # Use cases: comparing public key x-coordinates, Schnorr signature
  # verification (which only uses the x-coordinate).
  runar_public expected_x: Bigint
  def check_x(expected_x)
    assert ec_point_x(@pt) == expected_x
  end

  # Extract the y-coordinate from the stored point and verify it matches
  # the expected value.
  #
  # ec_point_y splits a 64-byte Point into its last 32 bytes (big-endian
  # unsigned y-coordinate) and converts to a script number.
  #
  # Use cases: full point comparison, parity checks for compressed encoding.
  runar_public expected_y: Bigint
  def check_y(expected_y)
    assert ec_point_y(@pt) == expected_y
  end

  # Construct a point from x and y coordinates, then verify the result
  # matches the expected coordinates.
  #
  # ec_make_point(x, y) encodes each coordinate as a 32-byte big-endian
  # unsigned integer and concatenates them into a 64-byte Point.
  #
  # Use cases: reconstructing points from stored coordinates, building
  # points from external data.
  runar_public x: Bigint, y: Bigint, expected_x: Bigint, expected_y: Bigint
  def check_make_point(x, y, expected_x, expected_y)
    p = ec_make_point(x, y)
    assert ec_point_x(p) == expected_x
    assert ec_point_y(p) == expected_y
  end

  # -----------------------------------------------------------------
  # Curve membership
  # -----------------------------------------------------------------

  # Verify the stored point lies on the secp256k1 curve.
  #
  # ec_on_curve(p) checks the curve equation: y^2 == x^3 + 7 (mod p).
  # Returns true if the point satisfies the equation, false otherwise.
  #
  # Use cases: validating untrusted points from transaction inputs before
  # performing EC arithmetic (prevents invalid-curve attacks).
  runar_public
  def check_on_curve
    assert ec_on_curve(@pt)
  end

  # -----------------------------------------------------------------
  # Point arithmetic
  # -----------------------------------------------------------------

  # Add two curve points and verify the result.
  #
  # ec_add(a, b) performs elliptic curve point addition using the affine
  # addition formula:
  #   lambda = (y2 - y1) / (x2 - x1) mod p
  #   x3 = lambda^2 - x1 - x2 mod p
  #   y3 = lambda(x1 - x3) - y1 mod p
  #
  # This compiles to ~800 bytes of Bitcoin Script including a modular
  # inverse computation.
  #
  # Use cases: combining public keys (key aggregation), Schnorr multi-sig,
  # Pedersen commitments (C = v*G + r*H).
  runar_public other: Point, expected_x: Bigint, expected_y: Bigint
  def check_add(other, expected_x, expected_y)
    result = ec_add(@pt, other)
    assert ec_point_x(result) == expected_x
    assert ec_point_y(result) == expected_y
  end

  # Multiply the stored point by a scalar and verify the result.
  #
  # ec_mul(p, k) computes k * P using a 256-bit double-and-add algorithm
  # in Jacobian coordinates (to avoid per-step modular inverses). The final
  # result is converted back to affine coordinates.
  #
  # This is the most expensive EC operation: ~1,500 bytes of Bitcoin Script
  # with a 256-iteration loop.
  #
  # Use cases: public key derivation (P = k*G), Diffie-Hellman shared
  # secrets, BIP-32 child key derivation.
  runar_public scalar: Bigint, expected_x: Bigint, expected_y: Bigint
  def check_mul(scalar, expected_x, expected_y)
    result = ec_mul(@pt, scalar)
    assert ec_point_x(result) == expected_x
    assert ec_point_y(result) == expected_y
  end

  # Multiply the generator point G by a scalar and verify the result.
  #
  # ec_mul_gen(k) is equivalent to ec_mul(EC_G, k) but the generator point
  # is hardcoded into the compiled script, saving the overhead of pushing
  # 64 bytes of point data.
  #
  # Use cases: deriving a public key from a private key (the fundamental
  # operation in elliptic curve cryptography), generating nonce points
  # for Schnorr proofs (R = r*G).
  runar_public scalar: Bigint, expected_x: Bigint, expected_y: Bigint
  def check_mul_gen(scalar, expected_x, expected_y)
    result = ec_mul_gen(scalar)
    assert ec_point_x(result) == expected_x
    assert ec_point_y(result) == expected_y
  end

  # -----------------------------------------------------------------
  # Point negation
  # -----------------------------------------------------------------

  # Negate the stored point and verify the result's y-coordinate.
  #
  # ec_negate(p) returns the point (x, field_prime - y). This is the
  # additive inverse: P + (-P) = point at infinity.
  #
  # Use cases: subtraction of points (A - B = A + (-B)), cancellation
  # checks in zero-knowledge proofs.
  runar_public expected_neg_y: Bigint
  def check_negate(expected_neg_y)
    neg = ec_negate(@pt)
    assert ec_point_y(neg) == expected_neg_y
  end

  # Verify that negating a point twice returns the original point.
  #
  # This demonstrates the involution property: -(-P) = P. Double negation
  # is a no-op, which the compiler can optimize away at the ANF level.
  runar_public
  def check_negate_roundtrip
    neg1 = ec_negate(@pt)
    neg2 = ec_negate(neg1)
    assert ec_point_x(neg2) == ec_point_x(@pt)
    assert ec_point_y(neg2) == ec_point_y(@pt)
  end

  # -----------------------------------------------------------------
  # Modular arithmetic
  # -----------------------------------------------------------------

  # Perform modular reduction and verify the result.
  #
  # ec_mod_reduce(value, mod) computes ((value % mod) + mod) % mod,
  # ensuring the result is always non-negative. This is essential for
  # EC group arithmetic where scalars must be in [0, n-1].
  #
  # Use cases: reducing Schnorr response values mod n, ensuring private
  # key scalars are in the valid range, hash-to-scalar conversion.
  runar_public value: Bigint, modulus: Bigint, expected: Bigint
  def check_mod_reduce(value, modulus, expected)
    assert ec_mod_reduce(value, modulus) == expected
  end

  # -----------------------------------------------------------------
  # Compressed encoding
  # -----------------------------------------------------------------

  # Compress the stored point to 33-byte public key format and verify.
  #
  # ec_encode_compressed(p) produces a 33-byte encoding: a prefix byte
  # (0x02 if y is even, 0x03 if y is odd) followed by the 32-byte
  # x-coordinate. This is the standard Bitcoin compressed public key format.
  #
  # Use cases: generating public key hashes for P2PKH addresses, comparing
  # computed keys against stored key hashes, interoperating with standard
  # Bitcoin tooling.
  runar_public expected: ByteString
  def check_encode_compressed(expected)
    compressed = ec_encode_compressed(@pt)
    assert compressed == expected
  end

  # -----------------------------------------------------------------
  # Algebraic properties
  # -----------------------------------------------------------------

  # Verify that scalar multiplication by 1 is the identity operation.
  #
  # For any point P: 1 * P = P. This is a fundamental algebraic property
  # and a useful sanity check that ec_mul handles the identity scalar.
  runar_public
  def check_mul_identity
    result = ec_mul(@pt, 1)
    assert ec_point_x(result) == ec_point_x(@pt)
    assert ec_point_y(result) == ec_point_y(@pt)
  end

  # Verify that the result of ec_add lies on the curve.
  #
  # Closure property: if A and B are on the curve, then A + B is also on
  # the curve. This is guaranteed by the group law but serves as a
  # correctness check for the EC addition implementation.
  runar_public other: Point
  def check_add_on_curve(other)
    result = ec_add(@pt, other)
    assert ec_on_curve(result)
  end

  # Verify that a generator multiplication result lies on the curve.
  #
  # For any scalar k, k * G must be a valid curve point. This tests the
  # ec_mul_gen implementation produces points satisfying the curve equation.
  runar_public scalar: Bigint
  def check_mul_gen_on_curve(scalar)
    result = ec_mul_gen(scalar)
    assert ec_on_curve(result)
  end
end
