//! Real secp256k1 elliptic curve operations for testing.
//!
//! Uses the `k256` crate for real EC arithmetic. Point encoding is
//! 64 bytes: `x[32] || y[32]` (big-endian, no prefix byte).

use k256::elliptic_curve::group::{Group, GroupEncoding};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::prelude::{Bigint, BigintBig, ByteString, Point};

/// Parse a 64-byte Point (x[32] || y[32]) into a ProjectivePoint.
fn point_to_projective(p: &[u8]) -> ProjectivePoint {
    assert_eq!(p.len(), 64, "Point must be exactly 64 bytes");

    // Check for point at infinity (all zeros)
    if p.iter().all(|&b| b == 0) {
        return ProjectivePoint::IDENTITY;
    }

    // Build uncompressed SEC1 encoding: 0x04 || x || y
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(p);
    let encoded = k256::EncodedPoint::from_bytes(&sec1)
        .expect("invalid SEC1 encoding");
    let affine = AffinePoint::from_encoded_point(&encoded)
        .expect("point not on curve");
    ProjectivePoint::from(affine)
}

/// Serialize a ProjectivePoint to a 64-byte Point (x[32] || y[32]).
fn projective_to_point(p: &ProjectivePoint) -> Point {
    if p.is_identity().into() {
        return vec![0u8; 64];
    }
    let affine = p.to_affine();
    let encoded = affine.to_encoded_point(false); // uncompressed
    let bytes = encoded.as_bytes(); // 0x04 || x[32] || y[32]
    bytes[1..65].to_vec()
}

/// Convert an i64 scalar to a k256::Scalar (mod N).
fn i64_to_scalar(k: Bigint) -> Scalar {
    if k >= 0 {
        Scalar::from(k as u64)
    } else {
        // Negative: compute N - |k|
        Scalar::ZERO - Scalar::from((-k) as u64)
    }
}

/// Point addition on secp256k1.
pub fn ec_add(a: &[u8], b: &[u8]) -> Point {
    let pa = point_to_projective(a);
    let pb = point_to_projective(b);
    projective_to_point(&(pa + pb))
}

/// Scalar multiplication: k * P.
pub fn ec_mul(p: &[u8], k: Bigint) -> Point {
    let pp = point_to_projective(p);
    let s = i64_to_scalar(k);
    projective_to_point(&(pp * s))
}

/// Scalar multiplication with the generator: k * G.
pub fn ec_mul_gen(k: Bigint) -> Point {
    let s = i64_to_scalar(k);
    projective_to_point(&(ProjectivePoint::GENERATOR * s))
}

/// Point negation: returns (x, p - y).
pub fn ec_negate(p: &[u8]) -> Point {
    let pp = point_to_projective(p);
    projective_to_point(&(-pp))
}

/// Check if a point is on the secp256k1 curve.
pub fn ec_on_curve(p: &[u8]) -> bool {
    if p.len() != 64 {
        return false;
    }
    // The all-zero blob is this codegen's encoding of the point at infinity,
    // and it is NOT on the curve: the emitted ec_on_curve is exactly
    // x < p AND y < p AND y^2 == x^3 + 7, and 0 != 7. Returning true here (the
    // projective convention) made this mock disagree with the script it stands
    // in for, so `assert(ec_on_curve(r))` passed off-chain and failed on-chain
    // for r = O — an unspendable output found only after deploy. O is now
    // reachable from ec_add(P, -P), so this matters in practice.
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(p);
    let Ok(enc) = k256::EncodedPoint::from_bytes(&sec1) else { return false };
    let ct = AffinePoint::from_encoded_point(&enc);
    ct.is_some().into()
}

/// Non-negative modular reduction: ((value % m) + m) % m.
pub fn ec_mod_reduce(value: Bigint, m: Bigint) -> Bigint {
    let r = value % m;
    if r < 0 { r + m } else { r }
}

/// Encode a point as a 33-byte compressed public key.
pub fn ec_encode_compressed(p: &[u8]) -> ByteString {
    let pp = point_to_projective(p);
    let affine = pp.to_affine();
    affine.to_bytes().to_vec()
}

/// Construct a Point from two coordinate integers.
///
/// The coordinates are [`BigintBig`] and not [`Bigint`] because a secp256k1
/// coordinate is 256 bits: an `i64` parameter cannot accept one, so the only
/// points this could build were ones no curve contains. It wrote eight bytes
/// into `buf[24..32]` and `buf[56..64]` and left the other 48 zero.
///
/// Contract source spells the type `BigintBig`, which every `.runar.rs` parser
/// maps to the same `bigint` primitive as `Bigint` — the emitted Script is
/// unchanged. See [`ec_point_x`] for the other half of the round-trip.
pub fn ec_make_point(x: BigintBig, y: BigintBig) -> Point {
    assert!(
        x.sign() != num_bigint::Sign::Minus && y.sign() != num_bigint::Sign::Minus,
        "runar: ec_make_point needs unsigned coordinates, got ({x}, {y}) —          a Point is x[32]||y[32] big-endian unsigned"
    );
    assert!(
        x.bits() <= 256 && y.bits() <= 256,
        "runar: ec_make_point coordinate wider than 32 bytes (x {} bits, y {} bits) —          it would not fit the Point encoding the script builds",
        x.bits(),
        y.bits()
    );
    let mut buf = vec![0u8; 64];
    for (dst, src) in [(0usize, &x), (32usize, &y)] {
        let (_, mag) = src.clone().into_parts();
        let be = mag.to_bytes_be();
        // Right-align the big-endian magnitude in its 32-byte field.
        let start = dst + 32 - be.len();
        buf[start..dst + 32].copy_from_slice(&be);
    }
    buf
}

/// Extract the x-coordinate from a Point.
///
/// Returns [`BigintBig`]. It used to return [`Bigint`] (= `i64`) and reach it
/// by reading bytes `[24..32]` of the 32-byte big-endian coordinate as an
/// unsigned 64-bit number and casting: `ec_point_x(5G)` came back as a negative
/// `i64` while the compiled `OP_SPLIT`/`OP_BIN2NUM` pair left the whole 32-byte
/// coordinate on the stack. The doc comment said "only meaningful for small
/// test values" — no curve point has a small coordinate, so the accessor was
/// wrong for every input it would ever see.
pub fn ec_point_x(p: &[u8]) -> BigintBig {
    assert_eq!(p.len(), 64, "Point must be exactly 64 bytes");
    BigintBig::from_bytes_be(num_bigint::Sign::Plus, &p[0..32])
}

/// Extract the y-coordinate from a Point. See [`ec_point_x`].
pub fn ec_point_y(p: &[u8]) -> BigintBig {
    assert_eq!(p.len(), 64, "Point must be exactly 64 bytes");
    BigintBig::from_bytes_be(num_bigint::Sign::Plus, &p[32..64])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: the secp256k1 generator point as a 64-byte Point.
    fn ec_g() -> Point {
        ec_mul_gen(1)
    }

    #[test]
    fn ec_g_is_64_bytes() {
        assert_eq!(ec_g().len(), 64);
    }

    #[test]
    fn ec_g_is_on_curve() {
        assert!(ec_on_curve(&ec_g()));
    }

    #[test]
    fn ec_add_g_g_equals_ec_mul_g_2() {
        let g = ec_g();
        let sum = ec_add(&g, &g);
        let doubled = ec_mul(&g, 2);
        assert_eq!(sum, doubled);
    }

    #[test]
    fn ec_add_g_g_equals_ec_mul_gen_2() {
        let g = ec_g();
        let sum = ec_add(&g, &g);
        let gen2 = ec_mul_gen(2);
        assert_eq!(sum, gen2);
    }

    #[test]
    fn ec_mul_gen_1_equals_g() {
        let g = ec_g();
        let gen1 = ec_mul_gen(1);
        assert_eq!(gen1, g);
    }

    #[test]
    fn ec_negate_produces_on_curve_point() {
        let g = ec_g();
        let neg = ec_negate(&g);
        assert_eq!(neg.len(), 64);
        assert!(ec_on_curve(&neg));
        // Negated point should differ from original (y coordinate differs)
        assert_ne!(neg, g);
    }

    #[test]
    fn ec_negate_double_negate_is_identity() {
        let g = ec_g();
        let double_neg = ec_negate(&ec_negate(&g));
        assert_eq!(double_neg, g);
    }

    #[test]
    fn ec_add_point_and_negation_is_identity() {
        let g = ec_g();
        let neg = ec_negate(&g);
        let sum = ec_add(&g, &neg);
        // Point at infinity = 64 zero bytes
        assert_eq!(sum, vec![0u8; 64]);
    }

    #[test]
    fn ec_make_point_round_trip() {
        let x = BigintBig::from(12345);
        let y = BigintBig::from(67890);
        let p = ec_make_point(x.clone(), y.clone());
        assert_eq!(p.len(), 64);
        assert_eq!(ec_point_x(&p), x);
        assert_eq!(ec_point_y(&p), y);
    }

    /// The round trip at the width it is actually used at.
    ///
    /// The test above passes 12345 and 67890, which is how a constructor that
    /// could only take `i64` coordinates looked correct: no curve point has an
    /// 8-byte coordinate, so nothing it covered was a point. This rebuilds a
    /// REAL point from its own accessors and requires the result to be the
    /// point it came from — the identity `examples/rust/ec-unit` asserts in its
    /// contract and could not run.
    #[test]
    fn ec_make_point_round_trips_a_real_curve_point() {
        let p = ec_mul_gen(5);
        let x = ec_point_x(&p);
        let y = ec_point_y(&p);
        assert!(x.bits() > 64, "5G's x-coordinate fits 64 bits; it is not a curve point");
        assert!(y.bits() > 64, "5G's y-coordinate fits 64 bits; it is not a curve point");
        let rebuilt = ec_make_point(x, y);
        assert_eq!(rebuilt, p);
        assert!(ec_on_curve(&rebuilt));
    }

    #[test]
    fn ec_encode_compressed_produces_33_bytes() {
        let g = ec_g();
        let compressed = ec_encode_compressed(&g);
        assert_eq!(compressed.len(), 33);
        // First byte must be 0x02 or 0x03 (compressed prefix)
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    #[test]
    fn ec_on_curve_rejects_invalid_point() {
        // Random 64 bytes very unlikely to be on the curve
        let bad_point = vec![0xffu8; 64];
        assert!(!ec_on_curve(&bad_point));
    }

    #[test]
    fn ec_on_curve_rejects_wrong_length() {
        assert!(!ec_on_curve(&[0u8; 32]));
    }

    #[test]
    fn ec_on_curve_rejects_identity() {
        // The all-zero blob is the point at infinity, and it is NOT on the
        // curve — 0^2 != 0^3 + 7. That is the ONLY way a contract can detect O,
        // and the compiled script agrees. This used to assert the opposite, so
        // an `assert(ec_on_curve(r))` that was green off-chain deployed an
        // unspendable output whenever r was O. O is reachable from
        // ec_add(P, -P) and from ec_mul(P, 0).
        assert!(!ec_on_curve(&vec![0u8; 64]));
    }

    #[test]
    fn ec_mod_reduce_basic() {
        assert_eq!(ec_mod_reduce(10, 3), 1);
        assert_eq!(ec_mod_reduce(-1, 5), 4);
        assert_eq!(ec_mod_reduce(0, 7), 0);
    }

    #[test]
    fn ec_mul_associative() {
        // (G * 3) * 2 should equal G * 6
        let g = ec_g();
        let g3 = ec_mul(&g, 3);
        let g3x2 = ec_mul(&g3, 2);
        let g6 = ec_mul_gen(6);
        assert_eq!(g3x2, g6);
    }
}
