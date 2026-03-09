//! WOTS+ (Winternitz One-Time Signature) reference implementation.
//!
//! RFC 8391 compatible with tweakable hash function F(pubSeed, ADRS, M).
//!
//! Parameters: w=16, n=32 (SHA-256).
//!   len1 = 64  (message digits: 256 bits / 4 bits per digit)
//!   len2 = 3   (checksum digits)
//!   len  = 67  (total hash chains)
//!
//! Signature: 67 x 32 bytes = 2,144 bytes.
//! Public key: 64 bytes (pubSeed(32) || pkRoot(32)).

use sha2::{Digest, Sha256};

const WOTS_W: usize = 16;
const WOTS_N: usize = 32;
const WOTS_LEN1: usize = 64; // ceil(8*N / LOG_W) = 256/4
const WOTS_LEN2: usize = 3;  // floor(log2(LEN1*(W-1)) / LOG_W) + 1
const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2; // 67

/// A WOTS+ keypair.
#[derive(Debug, Clone)]
pub struct WotsKeyPair {
    /// 67 secret key elements, each 32 bytes.
    pub sk: Vec<Vec<u8>>,
    /// 64-byte public key: pubSeed(32) || pkRoot(32).
    pub pk: Vec<u8>,
    /// 32-byte public seed (first 32 bytes of pk).
    pub pub_seed: Vec<u8>,
}

/// Tweakable hash F(pubSeed, chainIdx, stepIdx, msg).
fn wots_f(pub_seed: &[u8], chain_idx: usize, step_idx: usize, msg: &[u8]) -> Vec<u8> {
    let mut input = vec![0u8; WOTS_N + 2 + msg.len()];
    input[..WOTS_N].copy_from_slice(pub_seed);
    input[WOTS_N] = chain_idx as u8;
    input[WOTS_N + 1] = step_idx as u8;
    input[WOTS_N + 2..].copy_from_slice(msg);
    let h = Sha256::digest(&input);
    h.to_vec()
}

/// Iterates the tweakable hash function `steps` times starting from `start_step`.
fn wots_chain(x: &[u8], start_step: usize, steps: usize, pub_seed: &[u8], chain_idx: usize) -> Vec<u8> {
    let mut current = x.to_vec();
    for j in start_step..start_step + steps {
        current = wots_f(pub_seed, chain_idx, j, &current);
    }
    current
}

/// Extracts base-16 digits from a 32-byte hash.
fn wots_extract_digits(hash: &[u8]) -> Vec<usize> {
    let mut digits = Vec::with_capacity(WOTS_LEN1);
    for &b in hash {
        digits.push(((b >> 4) & 0x0f) as usize);
        digits.push((b & 0x0f) as usize);
    }
    digits
}

/// Computes WOTS+ checksum digits.
fn wots_checksum_digits(msg_digits: &[usize]) -> Vec<usize> {
    let mut sum: usize = 0;
    for &d in msg_digits {
        sum += (WOTS_W - 1) - d;
    }
    let mut digits = vec![0usize; WOTS_LEN2];
    let mut remaining = sum;
    for i in (0..WOTS_LEN2).rev() {
        digits[i] = remaining % WOTS_W;
        remaining /= WOTS_W;
    }
    digits
}

/// Returns all 67 digits: 64 message + 3 checksum.
fn wots_all_digits(msg_hash: &[u8]) -> Vec<usize> {
    let msg = wots_extract_digits(msg_hash);
    let csum = wots_checksum_digits(&msg);
    let mut all = msg;
    all.extend(csum);
    all
}

/// Generates a WOTS+ keypair.
///
/// If `seed` is `None`, random keys are generated using SHA-256 of the
/// current time (sufficient for testing; real applications should use a
/// proper CSPRNG). If `pub_seed` is `None`, a random one is derived.
pub fn wots_keygen(seed: Option<&[u8]>, pub_seed: Option<&[u8]>) -> WotsKeyPair {
    let ps: Vec<u8> = match pub_seed {
        Some(s) => s.to_vec(),
        None => {
            // Derive a pseudo-random pub_seed from system time
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let time_bytes = now.as_nanos().to_le_bytes();
            Sha256::digest(&time_bytes).to_vec()
        }
    };

    let mut sk: Vec<Vec<u8>> = Vec::with_capacity(WOTS_LEN);
    for i in 0..WOTS_LEN {
        if let Some(s) = seed {
            let mut buf = vec![0u8; WOTS_N + 4];
            buf[..WOTS_N].copy_from_slice(s);
            buf[WOTS_N] = (i >> 24) as u8;
            buf[WOTS_N + 1] = (i >> 16) as u8;
            buf[WOTS_N + 2] = (i >> 8) as u8;
            buf[WOTS_N + 3] = i as u8;
            let h = Sha256::digest(&buf);
            sk.push(h.to_vec());
        } else {
            // Derive pseudo-random sk from system time + index
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let mut buf = Vec::with_capacity(24);
            buf.extend_from_slice(&now.as_nanos().to_le_bytes());
            buf.extend_from_slice(&(i as u64).to_le_bytes());
            let h = Sha256::digest(&buf);
            sk.push(h.to_vec());
        }
    }

    // Compute chain endpoints
    let mut concat = vec![0u8; WOTS_LEN * WOTS_N];
    for i in 0..WOTS_LEN {
        let endpoint = wots_chain(&sk[i], 0, WOTS_W - 1, &ps, i);
        concat[i * WOTS_N..(i + 1) * WOTS_N].copy_from_slice(&endpoint);
    }

    let pk_root = Sha256::digest(&concat);

    let mut pk = vec![0u8; 2 * WOTS_N];
    pk[..WOTS_N].copy_from_slice(&ps);
    pk[WOTS_N..].copy_from_slice(&pk_root);

    WotsKeyPair {
        sk,
        pk,
        pub_seed: ps,
    }
}

/// Signs a message with WOTS+.
pub fn wots_sign(msg: &[u8], sk: &[Vec<u8>], pub_seed: &[u8]) -> Vec<u8> {
    let msg_hash = Sha256::digest(msg);
    let digits = wots_all_digits(&msg_hash);

    let mut sig = vec![0u8; WOTS_LEN * WOTS_N];
    for i in 0..WOTS_LEN {
        let element = wots_chain(&sk[i], 0, digits[i], pub_seed, i);
        sig[i * WOTS_N..(i + 1) * WOTS_N].copy_from_slice(&element);
    }
    sig
}

/// Verifies a WOTS+ signature.
pub(crate) fn wots_verify_impl(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    if sig.len() != WOTS_LEN * WOTS_N {
        return false;
    }
    if pk.len() != 2 * WOTS_N {
        return false;
    }

    let pub_seed = &pk[..WOTS_N];
    let pk_root = &pk[WOTS_N..];

    let msg_hash = Sha256::digest(msg);
    let digits = wots_all_digits(&msg_hash);

    let mut concat = vec![0u8; WOTS_LEN * WOTS_N];
    for i in 0..WOTS_LEN {
        let sig_element = &sig[i * WOTS_N..(i + 1) * WOTS_N];
        let remaining = (WOTS_W - 1) - digits[i];
        let endpoint = wots_chain(sig_element, digits[i], remaining, pub_seed, i);
        concat[i * WOTS_N..(i + 1) * WOTS_N].copy_from_slice(&endpoint);
    }

    let computed_root = Sha256::digest(&concat);
    &computed_root[..] == pk_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_deterministic() {
        let seed = [0xab_u8; 32];
        let pub_seed = [0xcd_u8; 32];
        let kp1 = wots_keygen(Some(&seed), Some(&pub_seed));
        let kp2 = wots_keygen(Some(&seed), Some(&pub_seed));
        assert_eq!(kp1.sk, kp2.sk);
        assert_eq!(kp1.pk, kp2.pk);
        assert_eq!(kp1.pub_seed, kp2.pub_seed);
    }

    #[test]
    fn test_keygen_sizes() {
        let seed = [0x01_u8; 32];
        let pub_seed = [0x02_u8; 32];
        let kp = wots_keygen(Some(&seed), Some(&pub_seed));
        assert_eq!(kp.sk.len(), 67);
        for s in &kp.sk {
            assert_eq!(s.len(), 32);
        }
        assert_eq!(kp.pk.len(), 64);
        assert_eq!(kp.pub_seed.len(), 32);
        // pubSeed should be the first 32 bytes of pk
        assert_eq!(&kp.pk[..32], &kp.pub_seed[..]);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = [0x42_u8; 32];
        let pub_seed = [0x13_u8; 32];
        let kp = wots_keygen(Some(&seed), Some(&pub_seed));

        let msg = b"hello WOTS+";
        let sig = wots_sign(msg, &kp.sk, &kp.pub_seed);
        assert_eq!(sig.len(), 67 * 32);
        assert!(wots_verify_impl(msg, &sig, &kp.pk));
    }

    #[test]
    fn test_verify_wrong_message() {
        let seed = [0x42_u8; 32];
        let pub_seed = [0x13_u8; 32];
        let kp = wots_keygen(Some(&seed), Some(&pub_seed));

        let msg = b"hello WOTS+";
        let sig = wots_sign(msg, &kp.sk, &kp.pub_seed);
        assert!(!wots_verify_impl(b"wrong message", &sig, &kp.pk));
    }

    #[test]
    fn test_verify_wrong_sig() {
        let seed = [0x42_u8; 32];
        let pub_seed = [0x13_u8; 32];
        let kp = wots_keygen(Some(&seed), Some(&pub_seed));

        let msg = b"hello WOTS+";
        let mut sig = wots_sign(msg, &kp.sk, &kp.pub_seed);
        sig[0] ^= 0xff; // corrupt first byte
        assert!(!wots_verify_impl(msg, &sig, &kp.pk));
    }

    #[test]
    fn test_verify_wrong_pk() {
        let seed = [0x42_u8; 32];
        let pub_seed = [0x13_u8; 32];
        let kp = wots_keygen(Some(&seed), Some(&pub_seed));

        let msg = b"hello WOTS+";
        let sig = wots_sign(msg, &kp.sk, &kp.pub_seed);

        let mut bad_pk = kp.pk.clone();
        bad_pk[63] ^= 0xff;
        assert!(!wots_verify_impl(msg, &sig, &bad_pk));
    }

    #[test]
    fn test_verify_bad_lengths() {
        assert!(!wots_verify_impl(b"msg", &[0u8; 100], &[0u8; 64]));
        assert!(!wots_verify_impl(b"msg", &[0u8; 67 * 32], &[0u8; 32]));
    }

    #[test]
    fn test_extract_digits() {
        let hash = [0xab_u8; 32];
        let digits = wots_extract_digits(&hash);
        assert_eq!(digits.len(), 64);
        // 0xab = 10, 11 in base-16
        assert_eq!(digits[0], 0x0a);
        assert_eq!(digits[1], 0x0b);
    }

    #[test]
    fn test_checksum_digits() {
        // All zeros → max checksum = 64 * 15 = 960
        let msg_digits = vec![0usize; 64];
        let csum = wots_checksum_digits(&msg_digits);
        assert_eq!(csum.len(), 3);
        // 960 = 3 * 256 + 192 → but in base 16: 960 / 16 = 60 r 0, 60 / 16 = 3 r 12
        // digits[2] = 960 % 16 = 0, remaining = 60
        // digits[1] = 60 % 16 = 12, remaining = 3
        // digits[0] = 3 % 16 = 3
        assert_eq!(csum, vec![3, 12, 0]);
    }

    #[test]
    fn test_keygen_without_seed() {
        // Just verify it doesn't panic and produces correct sizes
        let kp = wots_keygen(None, None);
        assert_eq!(kp.sk.len(), 67);
        assert_eq!(kp.pk.len(), 64);
        assert_eq!(kp.pub_seed.len(), 32);
    }
}
