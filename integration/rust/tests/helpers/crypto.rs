//! Crypto helpers for integration tests — WOTS+, Rabin, EC scalar math.

use k256::elliptic_curve::PrimeField;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// WOTS+ helpers
// ---------------------------------------------------------------------------

const WOTS_W: usize = 16;
const WOTS_N: usize = 32;
const WOTS_LEN1: usize = 64;
const WOTS_LEN2: usize = 3;
const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;

fn wots_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// WOTS+ chain: F(pubSeed || chainIdx_byte || stepIdx_byte || msg)
/// Must match the on-chain script which uses 1-byte indices in a single 66-byte hash.
fn wots_chain(x: &[u8], start: usize, steps: usize, pub_seed: &[u8], chain_idx: usize) -> Vec<u8> {
    let mut tmp = x.to_vec();
    for i in start..start + steps {
        let mut input = Vec::with_capacity(pub_seed.len() + 2 + tmp.len());
        input.extend_from_slice(pub_seed);
        input.push(chain_idx as u8);
        input.push(i as u8);
        input.extend_from_slice(&tmp);
        tmp = wots_sha256(&input);
    }
    tmp
}

pub struct WotsKeyPair {
    pub sk: Vec<Vec<u8>>,
    /// 64 bytes: pubSeed[32] || pkRoot[32]
    pub pk: Vec<u8>,
    pub pub_seed: Vec<u8>,
}

pub fn wots_keygen(seed: &[u8], pub_seed: &[u8]) -> WotsKeyPair {
    let mut sk = Vec::with_capacity(WOTS_LEN);
    for i in 0..WOTS_LEN {
        let mut buf = vec![0u8; WOTS_N + 4];
        let copy_len = seed.len().min(WOTS_N);
        buf[..copy_len].copy_from_slice(&seed[..copy_len]);
        buf[WOTS_N..WOTS_N + 4].copy_from_slice(&(i as u32).to_be_bytes());
        sk.push(wots_sha256(&buf));
    }

    // Public key: chain each sk[i] from 0 to W-1
    let mut all_pk = Vec::new();
    for i in 0..WOTS_LEN {
        let part = wots_chain(&sk[i], 0, WOTS_W - 1, pub_seed, i);
        all_pk.extend_from_slice(&part);
    }
    let pk_root = wots_sha256(&all_pk);

    let mut pk = Vec::with_capacity(64);
    pk.extend_from_slice(pub_seed);
    pk.extend_from_slice(&pk_root);

    WotsKeyPair {
        sk,
        pk,
        pub_seed: pub_seed.to_vec(),
    }
}

pub fn wots_pub_key_hex(kp: &WotsKeyPair) -> String {
    kp.pk.iter().map(|b| format!("{:02x}", b)).collect()
}

fn wots_extract_digits(msg_hash: &[u8]) -> Vec<usize> {
    let mut digits = Vec::with_capacity(WOTS_LEN1);
    for i in 0..WOTS_N {
        digits.push((msg_hash[i] >> 4) as usize);
        digits.push((msg_hash[i] & 0x0f) as usize);
    }
    digits
}

fn wots_checksum_digits(msg_digits: &[usize]) -> Vec<usize> {
    let mut csum: usize = 0;
    for &d in msg_digits {
        csum += WOTS_W - 1 - d;
    }
    let mut digits = vec![0usize; WOTS_LEN2];
    let mut c = csum;
    for i in (0..WOTS_LEN2).rev() {
        digits[i] = c % WOTS_W;
        c /= WOTS_W;
    }
    digits
}

#[allow(dead_code)]
pub fn wots_sign(msg: &[u8], sk: &[Vec<u8>], pub_seed: &[u8]) -> Vec<u8> {
    let msg_hash = wots_sha256(msg);
    let msg_digits = wots_extract_digits(&msg_hash);
    let csum_digits = wots_checksum_digits(&msg_digits);
    let mut all_digits = msg_digits;
    all_digits.extend_from_slice(&csum_digits);

    let mut sig = Vec::new();
    for i in 0..WOTS_LEN {
        let part = wots_chain(&sk[i], 0, all_digits[i], pub_seed, i);
        sig.extend_from_slice(&part);
    }
    sig
}

// ---------------------------------------------------------------------------
// Rabin helpers (using num-bigint for 260-bit arithmetic)
// ---------------------------------------------------------------------------

use num_bigint::BigInt;
use num_traits::{One, Zero, Signed};
use num_integer::Integer;

pub struct RabinKeyPair {
    pub p: BigInt,
    pub q: BigInt,
    pub n: BigInt,
}

/// Generate a deterministic Rabin keypair for testing.
/// Uses 130-bit primes (≡ 3 mod 4) matching the TS helper.
/// n must be > 2^256 so (sig²+padding) % n has the same byte width
/// as SHA-256 output — otherwise OP_EQUALVERIFY fails.
pub fn generate_rabin_key_pair() -> RabinKeyPair {
    let p = "1361129467683753853853498429727072846227".parse::<BigInt>().unwrap();
    let q = "1361129467683753853853498429727082846007".parse::<BigInt>().unwrap();
    let n = &p * &q;
    RabinKeyPair { p, q, n }
}

pub struct RabinSigResult {
    pub sig: BigInt,
    pub padding: BigInt,
}

/// Rabin-sign a message using the Chinese Remainder Theorem.
///
/// On-chain verification: (sig² + padding) mod n === hash mod n
/// So we need: sig² ≡ hash - padding (mod n)
#[allow(dead_code)]
pub fn rabin_sign(msg: &[u8], kp: &RabinKeyPair) -> RabinSigResult {
    let hash = Sha256::digest(msg);
    let hash_bn = buffer_to_unsigned_le(&hash);

    let zero = BigInt::zero();
    let one = BigInt::one();
    let four = BigInt::from(4);

    for pad in 0i64..1000 {
        let padding = BigInt::from(pad);
        let mut target = (&hash_bn - &padding).mod_floor(&kp.n);
        if target < zero {
            target += &kp.n;
        }
        if !is_qr_big(&target, &kp.p) || !is_qr_big(&target, &kp.q) {
            continue;
        }
        let p_exp = (&kp.p + &one) / &four;
        let sp = target.modpow(&p_exp, &kp.p);
        let q_exp = (&kp.q + &one) / &four;
        let sq = target.modpow(&q_exp, &kp.q);
        let sig = crt_big(&sp, &kp.p, &sq, &kp.q);

        // Verify: (sig² + padding) mod n === hash mod n
        let check = (&sig * &sig + &padding).mod_floor(&kp.n);
        if check == hash_bn.mod_floor(&kp.n) {
            return RabinSigResult { sig, padding };
        }
        // Try negative root
        let sig_alt = &kp.n - &sig;
        let check_alt = (&sig_alt * &sig_alt + &padding).mod_floor(&kp.n);
        if check_alt == hash_bn.mod_floor(&kp.n) {
            return RabinSigResult { sig: sig_alt, padding };
        }
    }
    panic!("Rabin sign: no valid padding found");
}

/// Interpret bytes as unsigned little-endian BigInt (matches Bitcoin Script).
fn buffer_to_unsigned_le(buf: &[u8]) -> BigInt {
    let mut result = BigInt::zero();
    for (i, &b) in buf.iter().enumerate() {
        result += BigInt::from(b) << (i * 8);
    }
    result
}

fn is_qr_big(a: &BigInt, p: &BigInt) -> bool {
    if (a % p).is_zero() {
        return true;
    }
    let exp = (p - BigInt::one()) / BigInt::from(2);
    a.modpow(&exp, p) == BigInt::one()
}

fn crt_big(a1: &BigInt, m1: &BigInt, a2: &BigInt, m2: &BigInt) -> BigInt {
    let n = m1 * m2;
    let q_inv_p = m2.modpow(&(m1 - BigInt::from(2)), m1);
    let p_inv_q = m1.modpow(&(m2 - BigInt::from(2)), m2);
    let t1 = ((a1 * m2 * &q_inv_p) % &n + &n) % &n;
    let t2 = ((a2 * m1 * &p_inv_q) % &n + &n) % &n;
    ((&t1 + &t2) % &n + &n) % &n
}

/// Encode a BigInt as a LE sign-magnitude hex string suitable for SdkValue::Bytes.
/// This produces the same encoding as Bitcoin Script numbers (LE with sign bit).
pub fn bigint_to_script_num_hex(n: &BigInt) -> String {
    if n.is_zero() {
        return "00".to_string();
    }
    let negative = n.is_negative();
    let abs_val = if negative { -n } else { n.clone() };
    let mut bytes = abs_val.to_bytes_le().1; // (sign, bytes_le)

    // Add sign bit
    if bytes.last().map_or(false, |&b| b & 0x80 != 0) {
        bytes.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = bytes.len() - 1;
        bytes[last] |= 0x80;
    }

    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// EC scalar helpers (secp256k1)
// ---------------------------------------------------------------------------

/// secp256k1 field prime p.
pub const EC_P: u128 = 0; // Too large for u128, use big arithmetic below

// We use simple big integer arithmetic via a wrapper around u64 arrays.
// For these integration tests, we only need to compute ecMulGen for small scalars.
// We'll use a simplified approach with string-based big integers.

/// Pad a hex string to 64 chars (32 bytes).
fn pad64(hex: &str) -> String {
    format!("{:0>64}", hex)
}

/// Encode two coordinate hex strings into a 128-char (64-byte) point.
pub fn encode_point(x_hex: &str, y_hex: &str) -> String {
    format!("{}{}", pad64(x_hex), pad64(y_hex))
}

/// Compute k*G on secp256k1 using the Rust compiler's EC module.
/// Returns (x_hex, y_hex) as zero-padded 64-char hex strings.
///
/// For integration tests we just need a few known points. We hardcode
/// the generator and use the k256 crate to compute multiples.
pub fn ec_mul_gen(k: u64) -> (String, String) {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    let scalar = Scalar::from(k);
    let point = ProjectivePoint::GENERATOR * scalar;
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(false); // uncompressed: 04 || x || y

    let x_bytes = encoded.x().expect("point at infinity");
    let y_bytes = encoded.y().expect("point at infinity");

    let x_hex: String = x_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let y_hex: String = y_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    (x_hex, y_hex)
}

/// Encode k*G as a 128-char hex point string.
pub fn ec_mul_gen_point(k: u64) -> String {
    let (x, y) = ec_mul_gen(k);
    encode_point(&x, &y)
}

/// secp256k1 group order N as a hex string.
#[allow(dead_code)]
pub const EC_N_HEX: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

/// Compute k*G and return (x, y) as k256 Scalar values for arithmetic.
/// Also provides the secp256k1 group order N as a Scalar.
#[allow(dead_code)]
pub fn ec_mul_gen_scalar(k: u64) -> (k256::Scalar, k256::ProjectivePoint) {
    use k256::{ProjectivePoint, Scalar};
    let scalar = Scalar::from(k);
    let point = ProjectivePoint::GENERATOR * scalar;
    (scalar, point)
}

/// Schnorr ZKP proof generation helper (legacy — with caller-supplied challenge).
/// Given private key k (as u64), returns (pub_key_hex, r_point_hex, s_hex, e_hex)
/// where the proof satisfies s*G = R + e*P.
#[allow(dead_code)]
pub fn generate_schnorr_proof(k: u64, r_nonce: u64, e_challenge: u64) -> (String, String, String, String) {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    let k_scalar = Scalar::from(k);
    let r_scalar = Scalar::from(r_nonce);
    let e_scalar = Scalar::from(e_challenge);

    // P = k*G (public key)
    let p_point = (ProjectivePoint::GENERATOR * k_scalar).to_affine();
    let p_enc = p_point.to_encoded_point(false);
    let px: String = p_enc.x().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let py: String = p_enc.y().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let pub_key_hex = format!("{}{}", pad64(&px), pad64(&py));

    // R = r*G (nonce commitment)
    let r_point = (ProjectivePoint::GENERATOR * r_scalar).to_affine();
    let r_enc = r_point.to_encoded_point(false);
    let rx: String = r_enc.x().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let ry: String = r_enc.y().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let r_point_hex = format!("{}{}", pad64(&rx), pad64(&ry));

    // s = r + e*k mod n
    let s_scalar = r_scalar + e_scalar * k_scalar;

    // Convert s to big-endian hex
    let s_bytes = s_scalar.to_bytes();
    let s_hex: String = s_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    // e as hex
    let e_bytes = e_scalar.to_bytes();
    let e_hex: String = e_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    (pub_key_hex, r_point_hex, s_hex, e_hex)
}

/// Schnorr ZKP proof generation with Fiat-Shamir challenge derivation.
/// The challenge e is derived as bin2num(hash256(R || P)), matching the on-chain
/// Fiat-Shamir computation.
///
/// Returns (pub_key_hex, r_point_hex, s_script_num_hex) where s is encoded as
/// a Bitcoin Script number (LE signed magnitude) for use with SdkValue::Bytes.
#[allow(dead_code)]
pub fn generate_schnorr_proof_fs(k: u64, r_nonce: u64) -> (String, String, String) {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{FieldBytes, ProjectivePoint, Scalar};

    let k_scalar = Scalar::from(k);
    let r_scalar = Scalar::from(r_nonce);

    // P = k*G (public key)
    let p_affine = (ProjectivePoint::GENERATOR * k_scalar).to_affine();
    let p_enc = p_affine.to_encoded_point(false);
    let px: String = p_enc.x().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let py: String = p_enc.y().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let pub_key_hex = format!("{}{}", pad64(&px), pad64(&py));

    // R = r*G (nonce commitment)
    let r_affine = (ProjectivePoint::GENERATOR * r_scalar).to_affine();
    let r_enc = r_affine.to_encoded_point(false);
    let rx: String = r_enc.x().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let ry: String = r_enc.y().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let r_point_hex = format!("{}{}", pad64(&rx), pad64(&ry));

    // Fiat-Shamir: e = bin2num(hash256(R || P))
    let combined_hex = format!("{}{}", r_point_hex, pub_key_hex);
    let combined_bytes: Vec<u8> = (0..combined_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&combined_hex[i..i + 2], 16).unwrap())
        .collect();

    let h1 = Sha256::digest(&combined_bytes);
    let h2 = Sha256::digest(&h1);
    let mut hash_data = h2.to_vec(); // 32 bytes

    // bin2num: LE signed-magnitude
    let is_neg = (hash_data[31] & 0x80) != 0;
    hash_data[31] &= 0x7f;

    // Convert LE to BE for k256 Scalar
    hash_data.reverse();

    // Magnitude is < 2^255 < n, so from_repr always succeeds
    let bytes_array: [u8; 32] = hash_data.try_into().unwrap();
    let e_magnitude: Scalar = Scalar::from_repr_vartime(FieldBytes::from(bytes_array))
        .expect("255-bit magnitude always < secp256k1 order");
    let e_scalar = if is_neg { -e_magnitude } else { e_magnitude };

    // s = r + e*k mod n
    let s_scalar = r_scalar + e_scalar * k_scalar;

    // Convert s to script number hex (LE signed magnitude) for SdkValue::Bytes
    let s_be_bytes = s_scalar.to_bytes();
    let s_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &s_be_bytes);
    let s_script_hex = bigint_to_script_num_hex(&s_bigint);

    (pub_key_hex, r_point_hex, s_script_hex)
}
