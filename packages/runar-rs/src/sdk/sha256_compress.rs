// ---------------------------------------------------------------------------
// sha256_compress.rs — SHA-256 compression utility for inductive contracts
// ---------------------------------------------------------------------------
//
// Provides a pure SHA-256 compression function and a helper that computes
// partial SHA-256 state for inductive contract parent-tx verification.
// The on-chain script receives only the last 3 blocks and the intermediate
// hash state, avoiding the need to push the full raw parent tx.
// ---------------------------------------------------------------------------

/// SHA-256 round constants (FIPS 180-4 Section 4.2.2).
/// 64 values derived from the fractional parts of the cube roots of
/// the first 64 primes.
pub const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values (FIPS 180-4 Section 5.3.3).
/// Derived from the fractional parts of the square roots of
/// the first 8 primes.
pub const SHA256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Pure SHA-256 compression function for one 64-byte block.
///
/// Takes an 8-word intermediate hash state and a 64-byte message block,
/// applies the 64 rounds of SHA-256 compression, and returns the
/// updated 8-word state.
pub fn sha256_compress_block(state: &[u32; 8], block: &[u8; 64]) -> [u32; 8] {
    // Expand 16 message words to 64
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = ((block[i * 4] as u32) << 24)
            | ((block[i * 4 + 1] as u32) << 16)
            | ((block[i * 4 + 2] as u32) << 8)
            | (block[i * 4 + 3] as u32);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = s1
            .wrapping_add(w[t - 7])
            .wrapping_add(s0)
            .wrapping_add(w[t - 16]);
    }

    // Initialize working variables
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // 64 rounds of compression
    for t in 0..64 {
        let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[t])
            .wrapping_add(w[t]);
        let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    // Add compressed chunk to current hash state
    [
        a.wrapping_add(state[0]),
        b.wrapping_add(state[1]),
        c.wrapping_add(state[2]),
        d.wrapping_add(state[3]),
        e.wrapping_add(state[4]),
        f.wrapping_add(state[5]),
        g.wrapping_add(state[6]),
        h.wrapping_add(state[7]),
    ]
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("hex_to_bytes: odd-length hex string".to_string());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("hex_to_bytes: invalid hex at offset {}: {}", i, e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

fn state_to_hex(state: &[u32; 8]) -> String {
    let mut hex = String::with_capacity(64);
    for word in state {
        hex.push_str(&format!("{:08x}", word));
    }
    hex
}

// ---------------------------------------------------------------------------
// SHA-256 padding
// ---------------------------------------------------------------------------

/// Apply SHA-256 padding to a message (FIPS 180-4 Section 5.1.1).
///
/// Appends:
///   1. A single 0x80 byte
///   2. Zero bytes until (length mod 64) == 56
///   3. 8-byte big-endian bit length of the original message
fn sha256_pad(message: &[u8]) -> Vec<u8> {
    let msg_len = message.len();
    let bit_len = (msg_len as u64) * 8;

    // Calculate padded length: message + 0x80 + zeros + 8 bytes length
    let mut padded_len = msg_len + 1; // +1 for the 0x80 byte
    while padded_len % 64 != 56 {
        padded_len += 1;
    }
    padded_len += 8; // 8-byte big-endian bit length

    let mut padded = vec![0u8; padded_len];
    padded[..msg_len].copy_from_slice(message);
    padded[msg_len] = 0x80;

    // Append 8-byte big-endian bit length
    let len_offset = padded_len - 8;
    padded[len_offset] = (bit_len >> 56) as u8;
    padded[len_offset + 1] = (bit_len >> 48) as u8;
    padded[len_offset + 2] = (bit_len >> 40) as u8;
    padded[len_offset + 3] = (bit_len >> 32) as u8;
    padded[len_offset + 4] = (bit_len >> 24) as u8;
    padded[len_offset + 5] = (bit_len >> 16) as u8;
    padded[len_offset + 6] = (bit_len >> 8) as u8;
    padded[len_offset + 7] = bit_len as u8;

    padded
}

// ---------------------------------------------------------------------------
// Partial SHA-256 for inductive contracts
// ---------------------------------------------------------------------------

/// Result of computing partial SHA-256 for an inductive contract's parent tx.
#[derive(Debug, Clone)]
pub struct PartialSha256Result {
    /// 32-byte hex: intermediate SHA-256 state after compressing blocks 0..N-4
    pub parent_hash_state: String,
    /// 64-byte hex: the (N-2)th block (third-to-last)
    pub parent_tail_block1: String,
    /// 64-byte hex: the (N-1)th block (second-to-last)
    pub parent_tail_block2: String,
    /// 64-byte hex: the Nth block (last, contains padding)
    pub parent_tail_block3: String,
    /// Number of raw (unpadded) tx bytes in the three tail blocks
    pub parent_raw_tail_len: usize,
}

/// Compute partial SHA-256 for an inductive contract's parent transaction.
///
/// Instead of pushing the full raw parent tx on-chain, we pre-compute the
/// SHA-256 state up to (but not including) the last 3 blocks. The on-chain
/// script receives:
///   - The intermediate hash state (32 bytes)
///   - The three tail blocks (64 bytes each)
///   - The raw tail length (to locate fields within the tail)
///
/// It then completes the double-SHA256 to derive the parent txid and
/// verifies it against the outpoint in the sighash preimage.
pub fn compute_partial_sha256_for_inductive(raw_tx_hex: &str) -> Result<PartialSha256Result, String> {
    let raw_bytes = hex_to_bytes(raw_tx_hex)?;
    let padded = sha256_pad(&raw_bytes);
    let total_blocks = padded.len() / 64;

    if total_blocks < 3 {
        return Err(format!(
            "compute_partial_sha256_for_inductive: need >= 3 SHA-256 blocks but got {}. \
             Raw tx is {} bytes — inductive contracts require raw_tail_len >= 115.",
            total_blocks,
            raw_bytes.len()
        ));
    }

    // Compress all blocks except the last 3 to get intermediate state
    let mut state = SHA256_INIT;
    let pre_hashed_blocks = total_blocks - 3;
    for i in 0..pre_hashed_blocks {
        let offset = i * 64;
        let block: [u8; 64] = padded[offset..offset + 64]
            .try_into()
            .map_err(|_| "sha256: block slice conversion failed".to_string())?;
        state = sha256_compress_block(&state, &block);
    }

    let tail_offset1 = pre_hashed_blocks * 64;
    let tail_offset2 = (pre_hashed_blocks + 1) * 64;
    let tail_offset3 = (pre_hashed_blocks + 2) * 64;
    let tail_block1 = bytes_to_hex(&padded[tail_offset1..tail_offset1 + 64]);
    let tail_block2 = bytes_to_hex(&padded[tail_offset2..tail_offset2 + 64]);
    let tail_block3 = bytes_to_hex(&padded[tail_offset3..tail_offset3 + 64]);

    // Raw tail length = total raw bytes minus the bytes already compressed
    let raw_tail_len = raw_bytes.len() - pre_hashed_blocks * 64;

    if raw_tail_len < 115 {
        return Err(format!(
            "compute_partial_sha256_for_inductive: raw_tail_len is {} but must be >= 115 \
             to contain the 111-byte internal fields + 4-byte locktime.",
            raw_tail_len
        ));
    }

    Ok(PartialSha256Result {
        parent_hash_state: state_to_hex(&state),
        parent_tail_block1: tail_block1,
        parent_tail_block2: tail_block2,
        parent_tail_block3: tail_block3,
        parent_raw_tail_len: raw_tail_len,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    #[test]
    fn test_sha256_compress_matches_stdlib() {
        // Compress a known message and verify against sha2 crate
        let message = b"Hello, Bitcoin SV!";
        let padded = sha256_pad(message);
        assert_eq!(padded.len() % 64, 0);

        let mut state = SHA256_INIT;
        let total_blocks = padded.len() / 64;
        for i in 0..total_blocks {
            let block: [u8; 64] = padded[i * 64..(i + 1) * 64].try_into().unwrap();
            state = sha256_compress_block(&state, &block);
        }

        // Convert state to bytes (big-endian)
        let mut hash_bytes = Vec::with_capacity(32);
        for word in &state {
            hash_bytes.extend_from_slice(&word.to_be_bytes());
        }

        // Compare with sha2 crate
        let expected = Sha256::digest(message);
        assert_eq!(hash_bytes, expected.as_slice());
    }

    #[test]
    fn test_partial_sha256_basic() {
        // A synthetic 300-byte "tx" should produce 5 padded blocks
        // (300 + 1 + padding + 8 = 320 = 5 * 64)
        let raw_hex = "ab".repeat(300);
        let result = compute_partial_sha256_for_inductive(&raw_hex).unwrap();

        // parent_hash_state should be 64 hex chars (32 bytes)
        assert_eq!(result.parent_hash_state.len(), 64);
        // tail blocks should each be 128 hex chars (64 bytes)
        assert_eq!(result.parent_tail_block1.len(), 128);
        assert_eq!(result.parent_tail_block2.len(), 128);
        assert_eq!(result.parent_tail_block3.len(), 128);
        // raw_tail_len = 300 - 2*64 = 172
        assert_eq!(result.parent_raw_tail_len, 172);
    }

    #[test]
    fn test_partial_sha256_small_tx() {
        // 200-byte tx → padded to 256 bytes (4 blocks), so pre_hashed_blocks = 1
        let raw_hex = "cd".repeat(200);
        let result = compute_partial_sha256_for_inductive(&raw_hex).unwrap();

        assert_eq!(result.parent_raw_tail_len, 136);
    }

    #[test]
    fn test_partial_sha256_too_small_tx() {
        // 100-byte tx → padded to 128 bytes (2 blocks) — not enough for 3 tail blocks
        let raw_hex = "cd".repeat(100);
        let result = compute_partial_sha256_for_inductive(&raw_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_sha256_reconstructs_full_hash() {
        // Verify that compressing the tail blocks on top of the partial state
        // produces the same result as hashing the full message.
        let raw_hex = "de".repeat(300);
        let raw_bytes = hex_to_bytes(&raw_hex).unwrap();

        let result = compute_partial_sha256_for_inductive(&raw_hex).unwrap();

        // Reconstruct: start from partial state, compress 3 tail blocks
        let state_bytes = hex_to_bytes(&result.parent_hash_state).unwrap();
        let mut state = [0u32; 8];
        for i in 0..8 {
            state[i] = ((state_bytes[i * 4] as u32) << 24)
                | ((state_bytes[i * 4 + 1] as u32) << 16)
                | ((state_bytes[i * 4 + 2] as u32) << 8)
                | (state_bytes[i * 4 + 3] as u32);
        }

        let block1_bytes = hex_to_bytes(&result.parent_tail_block1).unwrap();
        let block1: [u8; 64] = block1_bytes.try_into().unwrap();
        state = sha256_compress_block(&state, &block1);

        let block2_bytes = hex_to_bytes(&result.parent_tail_block2).unwrap();
        let block2: [u8; 64] = block2_bytes.try_into().unwrap();
        state = sha256_compress_block(&state, &block2);

        let block3_bytes = hex_to_bytes(&result.parent_tail_block3).unwrap();
        let block3: [u8; 64] = block3_bytes.try_into().unwrap();
        state = sha256_compress_block(&state, &block3);

        let mut reconstructed = Vec::with_capacity(32);
        for word in &state {
            reconstructed.extend_from_slice(&word.to_be_bytes());
        }

        // Compare with full SHA-256
        let expected = Sha256::digest(&raw_bytes);
        assert_eq!(reconstructed, expected.as_slice());
    }
}
