//! Real secp256k1 elliptic curve operations for testing.
//!
//! Uses the `k256` crate for real EC arithmetic. Point encoding is
//! 64 bytes: `x[32] || y[32]` (big-endian, no prefix byte).

use k256::elliptic_curve::group::{Group, GroupEncoding};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::prelude::{Bigint, ByteString, Point};

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
    // All zeros = point at infinity, consider it "on curve"
    if p.iter().all(|&b| b == 0) {
        return true;
    }
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
pub fn ec_make_point(x: Bigint, y: Bigint) -> Point {
    let mut buf = vec![0u8; 64];
    let xb = (x as u64).to_be_bytes();
    let yb = (y as u64).to_be_bytes();
    buf[24..32].copy_from_slice(&xb);
    buf[56..64].copy_from_slice(&yb);
    buf
}

/// Extract the x-coordinate from a Point as an i64.
/// Note: only meaningful for small test values; real coordinates are 256-bit.
pub fn ec_point_x(p: &[u8]) -> Bigint {
    assert_eq!(p.len(), 64, "Point must be exactly 64 bytes");
    // Return as i64 — will only work for small coordinates
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&p[24..32]);
    u64::from_be_bytes(bytes) as i64
}

/// Extract the y-coordinate from a Point as an i64.
/// Note: only meaningful for small test values; real coordinates are 256-bit.
pub fn ec_point_y(p: &[u8]) -> Bigint {
    assert_eq!(p.len(), 64, "Point must be exactly 64 bytes");
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&p[56..64]);
    u64::from_be_bytes(bytes) as i64
}
