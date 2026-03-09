//! SLH-DSA (FIPS 205) SHA-256 reference implementation.
//!
//! Implements all 6 SHA-256 parameter sets for key generation, signing, and
//! verification. Used by the Rúnar crate for real SLH-DSA verification in
//! contract tests.
//!
//! Based on FIPS 205 (Stateless Hash-Based Digital Signature Standard).
//! Only the SHA2 instantiation (not SHAKE) is implemented.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Parameter sets (FIPS 205 Table 1, SHA2 variants only)
// ---------------------------------------------------------------------------

/// SLH-DSA parameter set.
#[derive(Debug, Clone, Copy)]
pub struct SlhParams {
    pub name: &'static str,
    /// Security parameter (hash output bytes): 16, 24, or 32
    pub n: usize,
    /// Total tree height
    pub h: usize,
    /// Number of hypertree layers
    pub d: usize,
    /// Height of each subtree: h/d
    pub hp: usize,
    /// FORS tree height
    pub a: usize,
    /// Number of FORS trees
    pub k: usize,
    /// Winternitz parameter (always 16)
    pub w: usize,
    /// WOTS+ chain count
    pub len: usize,
}

/// Compute WOTS+ total chain length from n and w.
const fn wots_len(n: usize, w: usize) -> usize {
    // len1 = ceil(8*n / log2(w))
    // For w=16, log2(w) = 4, so len1 = ceil(8*n / 4) = 2*n
    // len2 = floor(log2(len1 * (w-1)) / log2(w)) + 1
    // For w=16: floor(log2(2*n * 15) / 4) + 1
    let log2_w: usize = match w {
        16 => 4,
        _ => 4, // only w=16 in FIPS 205 SHA2
    };
    let len1 = (8 * n + log2_w - 1) / log2_w;
    // floor(log2(len1 * (w-1))) via leading zeros
    let product = len1 * (w - 1);
    let mut bits = 0usize;
    let mut v = product;
    while v > 1 {
        v >>= 1;
        bits += 1;
    }
    let len2 = bits / log2_w + 1;
    len1 + len2
}

pub const SLH_SHA2_128S: SlhParams = SlhParams {
    name: "SLH-DSA-SHA2-128s",
    n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, w: 16,
    len: wots_len(16, 16),
};

pub const SLH_SHA2_128F: SlhParams = SlhParams {
    name: "SLH-DSA-SHA2-128f",
    n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, w: 16,
    len: wots_len(16, 16),
};

pub const SLH_SHA2_192S: SlhParams = SlhParams {
    name: "SLH-DSA-SHA2-192s",
    n: 24, h: 63, d: 7, hp: 9, a: 14, k: 17, w: 16,
    len: wots_len(24, 16),
};

pub const SLH_SHA2_192F: SlhParams = SlhParams {
    name: "SLH-DSA-SHA2-192f",
    n: 24, h: 66, d: 22, hp: 3, a: 8, k: 33, w: 16,
    len: wots_len(24, 16),
};

pub const SLH_SHA2_256S: SlhParams = SlhParams {
    name: "SLH-DSA-SHA2-256s",
    n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22, w: 16,
    len: wots_len(32, 16),
};

pub const SLH_SHA2_256F: SlhParams = SlhParams {
    name: "SLH-DSA-SHA2-256f",
    n: 32, h: 68, d: 17, hp: 4, a: 8, k: 35, w: 16,
    len: wots_len(32, 16),
};

// ---------------------------------------------------------------------------
// ADRS (Address) — 32-byte domain separator (FIPS 205 Section 4.2)
// ---------------------------------------------------------------------------

const ADRS_SIZE: usize = 32;

// Address type constants
const ADRS_WOTS_HASH: u32 = 0;
const ADRS_WOTS_PK: u32 = 1;
const ADRS_TREE: u32 = 2;
const ADRS_FORS_TREE: u32 = 3;
const ADRS_FORS_ROOTS: u32 = 4;
const ADRS_WOTS_PRF: u32 = 5;
const ADRS_FORS_PRF: u32 = 6;

type Adrs = [u8; ADRS_SIZE];

fn new_adrs() -> Adrs {
    [0u8; ADRS_SIZE]
}

fn set_layer_address(adrs: &mut Adrs, layer: u32) {
    adrs[0] = (layer >> 24) as u8;
    adrs[1] = (layer >> 16) as u8;
    adrs[2] = (layer >> 8) as u8;
    adrs[3] = layer as u8;
}

fn set_tree_address(adrs: &mut Adrs, tree: u64) {
    // Bytes 4-15 (12 bytes for tree address, big-endian)
    // u64 only covers bytes 8-15 (lower 8 bytes); bytes 4-7 are always 0 for u64
    for i in 0..12 {
        let shift = 8 * i;
        adrs[4 + 11 - i] = if shift < 64 {
            (tree >> shift) as u8
        } else {
            0
        };
    }
}

fn set_type(adrs: &mut Adrs, typ: u32) {
    // Bytes 16-19: type (big-endian u32), also zeroes bytes 20-31
    adrs[16] = (typ >> 24) as u8;
    adrs[17] = (typ >> 16) as u8;
    adrs[18] = (typ >> 8) as u8;
    adrs[19] = typ as u8;
    for i in 20..32 {
        adrs[i] = 0;
    }
}

fn set_key_pair_address(adrs: &mut Adrs, kp: u32) {
    adrs[20] = (kp >> 24) as u8;
    adrs[21] = (kp >> 16) as u8;
    adrs[22] = (kp >> 8) as u8;
    adrs[23] = kp as u8;
}

fn set_chain_address(adrs: &mut Adrs, chain: u32) {
    adrs[24] = (chain >> 24) as u8;
    adrs[25] = (chain >> 16) as u8;
    adrs[26] = (chain >> 8) as u8;
    adrs[27] = chain as u8;
}

fn set_hash_address(adrs: &mut Adrs, hash: u32) {
    adrs[28] = (hash >> 24) as u8;
    adrs[29] = (hash >> 16) as u8;
    adrs[30] = (hash >> 8) as u8;
    adrs[31] = hash as u8;
}

fn set_tree_height(adrs: &mut Adrs, height: u32) {
    set_chain_address(adrs, height);
}

fn set_tree_index(adrs: &mut Adrs, index: u32) {
    set_hash_address(adrs, index);
}

fn get_key_pair_address(adrs: &Adrs) -> u32 {
    ((adrs[20] as u32) << 24)
        | ((adrs[21] as u32) << 16)
        | ((adrs[22] as u32) << 8)
        | (adrs[23] as u32)
}

/// Compressed ADRS for SHA2 (22 bytes): drop bytes 3..6
fn compress_adrs(adrs: &Adrs) -> [u8; 22] {
    let mut c = [0u8; 22];
    c[0] = adrs[3]; // layer (1 byte)
    // tree address bytes 8-15 (8 bytes)
    c[1..9].copy_from_slice(&adrs[8..16]);
    // type (1 byte)
    c[9] = adrs[19];
    // bytes 20-31 (12 bytes)
    c[10..22].copy_from_slice(&adrs[20..32]);
    c
}

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn trunc(data: &[u8], n: usize) -> Vec<u8> {
    data[..n].to_vec()
}

fn to_byte(value: u32, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    let mut val = value;
    for i in (0..n).rev() {
        if val == 0 {
            break;
        }
        b[i] = (val & 0xff) as u8;
        val >>= 8;
    }
    b
}

// ---------------------------------------------------------------------------
// Hash functions (FIPS 205 Section 11.1 — SHA2 instantiation)
// ---------------------------------------------------------------------------

/// Tweakable hash: T_l(PK.seed, ADRS, M) = trunc_n(SHA-256(PK.seed || pad || ADRSc || M))
fn slh_t(pk_seed: &[u8], adrs: &Adrs, msg: &[u8], n: usize) -> Vec<u8> {
    let adrs_c = compress_adrs(adrs);
    let pad_len = 64 - n;
    let mut input = Vec::with_capacity(n + pad_len + 22 + msg.len());
    input.extend_from_slice(pk_seed);
    input.extend(std::iter::repeat(0u8).take(pad_len));
    input.extend_from_slice(&adrs_c);
    input.extend_from_slice(msg);
    trunc(&sha256_hash(&input), n)
}

/// PRF: PRF(PK.seed, SK.seed, ADRS) = T(PK.seed, ADRS, SK.seed)
fn slh_prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs, n: usize) -> Vec<u8> {
    slh_t(pk_seed, adrs, sk_seed, n)
}

/// PRFmsg: randomized message hashing
fn slh_prf_msg(sk_prf: &[u8], opt_rand: &[u8], msg: &[u8], n: usize) -> Vec<u8> {
    let pad_len = 64 - n;
    let mut input = Vec::with_capacity(pad_len + n + n + msg.len());
    input.extend(std::iter::repeat(0u8).take(pad_len));
    input.extend_from_slice(sk_prf);
    input.extend_from_slice(opt_rand);
    input.extend_from_slice(msg);
    trunc(&sha256_hash(&input), n)
}

/// Hmsg: hash message to get FORS + tree indices (SHA-256 based MGF1)
fn slh_hmsg(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(r.len() + pk_seed.len() + pk_root.len() + msg.len());
    seed.extend_from_slice(r);
    seed.extend_from_slice(pk_seed);
    seed.extend_from_slice(pk_root);
    seed.extend_from_slice(msg);
    let hash = sha256_hash(&seed);

    let mut result = vec![0u8; out_len];
    let mut offset = 0;
    let mut counter: u32 = 0;
    while offset < out_len {
        let mut block_input = Vec::with_capacity(32 + 4);
        block_input.extend_from_slice(&hash);
        block_input.extend_from_slice(&to_byte(counter, 4));
        let block = sha256_hash(&block_input);
        let copy_len = std::cmp::min(32, out_len - offset);
        result[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
        offset += copy_len;
        counter += 1;
    }
    result
}

// ---------------------------------------------------------------------------
// WOTS+ (FIPS 205 Section 5)
// ---------------------------------------------------------------------------

fn wots_chain(
    x: &[u8],
    start: u32,
    steps: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    n: usize,
) -> Vec<u8> {
    let mut tmp = x.to_vec();
    for j in start..start + steps {
        set_hash_address(adrs, j);
        tmp = slh_t(pk_seed, adrs, &tmp, n);
    }
    tmp
}

fn wots_len1(n: usize, w: usize) -> usize {
    let log2_w = (w as f64).log2() as usize;
    (8 * n + log2_w - 1) / log2_w
}

fn wots_len2(n: usize, w: usize) -> usize {
    let l1 = wots_len1(n, w);
    let log2_w = (w as f64).log2();
    ((l1 as f64 * (w - 1) as f64).log2() / log2_w).floor() as usize + 1
}

fn base_w(msg: &[u8], w: usize, out_len: usize) -> Vec<u32> {
    let log_w = (w as f64).log2() as u32;
    let mut bits = Vec::new();
    for &byte in msg {
        let mut j = 8i32 - log_w as i32;
        while j >= 0 {
            bits.push(((byte as u32) >> (j as u32)) & ((w as u32) - 1));
            j -= log_w as i32;
        }
    }
    bits.truncate(out_len);
    bits
}

fn slh_wots_pk_from_sig(
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    params: &SlhParams,
) -> Vec<u8> {
    let SlhParams { n, w, len, .. } = *params;
    let l1 = wots_len1(n, w);
    let l2 = wots_len2(n, w);

    let msg_digits = base_w(msg, w, l1);

    // Compute checksum
    let mut csum: u32 = 0;
    for &d in &msg_digits {
        csum += (w as u32 - 1) - d;
    }
    // Encode checksum in base-w
    let log2_w = (w as f64).log2();
    let shift = 8 - (((l2 as f64) * log2_w) as u32 % 8);
    let shift = if shift == 8 { 0 } else { shift };
    let csum_byte_len = ((l2 as f64 * log2_w) / 8.0).ceil() as usize;
    let csum_bytes = to_byte(csum << shift, csum_byte_len);
    let csum_digits = base_w(&csum_bytes, w, l2);

    let mut all_digits = msg_digits;
    all_digits.extend_from_slice(&csum_digits);

    let kp_addr = get_key_pair_address(adrs);
    let mut tmp_adrs = *adrs;
    set_type(&mut tmp_adrs, ADRS_WOTS_HASH);
    set_key_pair_address(&mut tmp_adrs, kp_addr);

    let mut parts = Vec::with_capacity(len * n);
    for i in 0..len {
        set_chain_address(&mut tmp_adrs, i as u32);
        let sig_i = &sig[i * n..(i + 1) * n];
        let chain_result = wots_chain(
            sig_i,
            all_digits[i],
            (w as u32) - 1 - all_digits[i],
            pk_seed,
            &mut tmp_adrs,
            n,
        );
        parts.extend_from_slice(&chain_result);
    }

    // Compress: T_len(PK.seed, ADRS_pk, pk_0 || ... || pk_{len-1})
    let mut pk_adrs = *adrs;
    set_type(&mut pk_adrs, ADRS_WOTS_PK);
    slh_t(pk_seed, &pk_adrs, &parts, n)
}

fn slh_wots_sign(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    params: &SlhParams,
) -> Vec<u8> {
    let SlhParams { n, w, len, .. } = *params;
    let l1 = wots_len1(n, w);
    let l2 = wots_len2(n, w);

    let msg_digits = base_w(msg, w, l1);

    let mut csum: u32 = 0;
    for &d in &msg_digits {
        csum += (w as u32 - 1) - d;
    }
    let log2_w = (w as f64).log2();
    let shift = 8 - (((l2 as f64) * log2_w) as u32 % 8);
    let shift = if shift == 8 { 0 } else { shift };
    let csum_byte_len = ((l2 as f64 * log2_w) / 8.0).ceil() as usize;
    let csum_bytes = to_byte(csum << shift, csum_byte_len);
    let csum_digits = base_w(&csum_bytes, w, l2);

    let mut all_digits = msg_digits;
    all_digits.extend_from_slice(&csum_digits);

    let kp_addr = get_key_pair_address(adrs);

    let mut sig_parts = Vec::with_capacity(len * n);
    for i in 0..len {
        let mut sk_adrs = *adrs;
        set_type(&mut sk_adrs, ADRS_WOTS_PRF);
        set_key_pair_address(&mut sk_adrs, kp_addr);
        set_chain_address(&mut sk_adrs, i as u32);
        set_hash_address(&mut sk_adrs, 0);
        let sk = slh_prf(pk_seed, sk_seed, &sk_adrs, n);

        let mut chain_adrs = *adrs;
        set_type(&mut chain_adrs, ADRS_WOTS_HASH);
        set_key_pair_address(&mut chain_adrs, kp_addr);
        set_chain_address(&mut chain_adrs, i as u32);
        let chain_result = wots_chain(&sk, 0, all_digits[i], pk_seed, &mut chain_adrs, n);
        sig_parts.extend_from_slice(&chain_result);
    }
    sig_parts
}

fn slh_wots_pk(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    params: &SlhParams,
) -> Vec<u8> {
    let SlhParams { n, w, len, .. } = *params;
    let kp_addr = get_key_pair_address(adrs);

    let mut parts = Vec::with_capacity(len * n);
    for i in 0..len {
        let mut sk_adrs = *adrs;
        set_type(&mut sk_adrs, ADRS_WOTS_PRF);
        set_key_pair_address(&mut sk_adrs, kp_addr);
        set_chain_address(&mut sk_adrs, i as u32);
        set_hash_address(&mut sk_adrs, 0);
        let sk = slh_prf(pk_seed, sk_seed, &sk_adrs, n);

        let mut chain_adrs = *adrs;
        set_type(&mut chain_adrs, ADRS_WOTS_HASH);
        set_key_pair_address(&mut chain_adrs, kp_addr);
        set_chain_address(&mut chain_adrs, i as u32);
        let chain_result = wots_chain(&sk, 0, (w as u32) - 1, pk_seed, &mut chain_adrs, n);
        parts.extend_from_slice(&chain_result);
    }

    let mut pk_adrs = *adrs;
    set_type(&mut pk_adrs, ADRS_WOTS_PK);
    slh_t(pk_seed, &pk_adrs, &parts, n)
}

// ---------------------------------------------------------------------------
// XMSS (FIPS 205 Section 6) — Merkle tree with WOTS+ leaves
// ---------------------------------------------------------------------------

fn slh_xmss_node(
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx: u32,
    height: u32,
    adrs: &Adrs,
    params: &SlhParams,
) -> Vec<u8> {
    let n = params.n;

    if height == 0 {
        // Leaf: WOTS+ public key
        let mut leaf_adrs = *adrs;
        set_type(&mut leaf_adrs, ADRS_WOTS_HASH);
        set_key_pair_address(&mut leaf_adrs, idx);
        return slh_wots_pk(sk_seed, pk_seed, &leaf_adrs, params);
    }

    let left = slh_xmss_node(sk_seed, pk_seed, 2 * idx, height - 1, adrs, params);
    let right = slh_xmss_node(sk_seed, pk_seed, 2 * idx + 1, height - 1, adrs, params);

    let mut node_adrs = *adrs;
    set_type(&mut node_adrs, ADRS_TREE);
    set_tree_height(&mut node_adrs, height);
    set_tree_index(&mut node_adrs, idx);

    let mut combined = Vec::with_capacity(2 * n);
    combined.extend_from_slice(&left);
    combined.extend_from_slice(&right);
    slh_t(pk_seed, &node_adrs, &combined, n)
}

fn slh_xmss_sign(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx: u32,
    adrs: &Adrs,
    params: &SlhParams,
) -> Vec<u8> {
    let hp = params.hp;

    // WOTS+ signature
    let mut sig_adrs = *adrs;
    set_type(&mut sig_adrs, ADRS_WOTS_HASH);
    set_key_pair_address(&mut sig_adrs, idx);
    let sig = slh_wots_sign(msg, sk_seed, pk_seed, &sig_adrs, params);

    // Authentication path
    let mut result = sig;
    for j in 0..hp {
        let sibling = (idx >> j) ^ 1;
        let auth_node = slh_xmss_node(sk_seed, pk_seed, sibling, j as u32, adrs, params);
        result.extend_from_slice(&auth_node);
    }

    result
}

fn slh_xmss_pk_from_sig(
    idx: u32,
    sig_xmss: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    params: &SlhParams,
) -> Vec<u8> {
    let SlhParams { n, hp, len, .. } = *params;
    let wots_sig_len = len * n;
    let wots_sig = &sig_xmss[..wots_sig_len];
    let auth = &sig_xmss[wots_sig_len..];

    // Reconstruct WOTS+ public key from signature
    let mut w_adrs = *adrs;
    set_type(&mut w_adrs, ADRS_WOTS_HASH);
    set_key_pair_address(&mut w_adrs, idx);
    let mut node = slh_wots_pk_from_sig(wots_sig, msg, pk_seed, &w_adrs, params);

    // Walk the authentication path up the Merkle tree
    let mut tree_adrs = *adrs;
    set_type(&mut tree_adrs, ADRS_TREE);
    for j in 0..hp {
        let auth_j = &auth[j * n..(j + 1) * n];
        set_tree_height(&mut tree_adrs, (j + 1) as u32);
        set_tree_index(&mut tree_adrs, idx >> (j + 1) as u32);

        let mut combined = Vec::with_capacity(2 * n);
        if ((idx >> j) & 1) == 0 {
            combined.extend_from_slice(&node);
            combined.extend_from_slice(auth_j);
        } else {
            combined.extend_from_slice(auth_j);
            combined.extend_from_slice(&node);
        }
        node = slh_t(pk_seed, &tree_adrs, &combined, n);
    }
    node
}

// ---------------------------------------------------------------------------
// FORS (FIPS 205 Section 8) — Forest of random subsets
// ---------------------------------------------------------------------------

/// Extract a-bit index for FORS tree i from message digest md.
pub fn extract_fors_idx(md: &[u8], tree_idx: usize, a: usize) -> u32 {
    let bit_start = tree_idx * a;
    let byte_start = bit_start / 8;
    let bit_offset = bit_start % 8;

    let mut value: u32 = 0;
    let mut bits_read: usize = 0;
    let mut i = byte_start;

    while bits_read < a {
        let byte = if i < md.len() { md[i] } else { 0 };
        let avail_bits = if i == byte_start { 8 - bit_offset } else { 8 };
        let bits_to_take = std::cmp::min(avail_bits, a - bits_read);
        let shift = if i == byte_start {
            avail_bits - bits_to_take
        } else {
            8 - bits_to_take
        };
        let mask = (1u32 << bits_to_take) - 1;
        value = (value << bits_to_take) | (((byte as u32) >> shift) & mask);
        bits_read += bits_to_take;
        i += 1;
    }

    value
}

fn slh_fors_node(
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx: u32,
    height: u32,
    adrs: &Adrs,
    tree_idx: usize,
    params: &SlhParams,
) -> Vec<u8> {
    let SlhParams { n, a, .. } = *params;

    if height == 0 {
        let mut sk_adrs = *adrs;
        set_type(&mut sk_adrs, ADRS_FORS_PRF);
        set_key_pair_address(&mut sk_adrs, get_key_pair_address(adrs));
        set_tree_height(&mut sk_adrs, 0);
        set_tree_index(&mut sk_adrs, (tree_idx * (1 << a) + idx as usize) as u32);
        let sk = slh_prf(pk_seed, sk_seed, &sk_adrs, n);

        let mut leaf_adrs = *adrs;
        set_type(&mut leaf_adrs, ADRS_FORS_TREE);
        set_key_pair_address(&mut leaf_adrs, get_key_pair_address(adrs));
        set_tree_height(&mut leaf_adrs, 0);
        set_tree_index(&mut leaf_adrs, (tree_idx * (1 << a) + idx as usize) as u32);
        return slh_t(pk_seed, &leaf_adrs, &sk, n);
    }

    let left = slh_fors_node(sk_seed, pk_seed, 2 * idx, height - 1, adrs, tree_idx, params);
    let right = slh_fors_node(sk_seed, pk_seed, 2 * idx + 1, height - 1, adrs, tree_idx, params);

    let mut node_adrs = *adrs;
    set_type(&mut node_adrs, ADRS_FORS_TREE);
    set_key_pair_address(&mut node_adrs, get_key_pair_address(adrs));
    set_tree_height(&mut node_adrs, height);
    set_tree_index(&mut node_adrs, (tree_idx * (1usize << (a - height as usize)) + idx as usize) as u32);

    let mut combined = Vec::with_capacity(2 * n);
    combined.extend_from_slice(&left);
    combined.extend_from_slice(&right);
    slh_t(pk_seed, &node_adrs, &combined, n)
}

fn slh_fors_sign(
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    params: &SlhParams,
) -> Vec<u8> {
    let SlhParams { n, a, k, .. } = *params;
    let kp_addr = get_key_pair_address(adrs);
    let mut parts = Vec::new();

    for i in 0..k {
        let idx = extract_fors_idx(md, i, a);

        // Secret value
        let mut sk_adrs = *adrs;
        set_type(&mut sk_adrs, ADRS_FORS_PRF);
        set_key_pair_address(&mut sk_adrs, kp_addr);
        set_tree_height(&mut sk_adrs, 0);
        set_tree_index(&mut sk_adrs, (i * (1 << a) + idx as usize) as u32);
        let sk = slh_prf(pk_seed, sk_seed, &sk_adrs, n);
        parts.extend_from_slice(&sk);

        // Authentication path: sibling nodes at each height
        for j in 0..a {
            let sibling_idx = ((idx as usize) >> j) ^ 1;
            let auth_node = slh_fors_node(
                sk_seed,
                pk_seed,
                sibling_idx as u32,
                j as u32,
                adrs,
                i,
                params,
            );
            parts.extend_from_slice(&auth_node);
        }
    }

    parts
}

fn slh_fors_pk_from_sig(
    fors_signature: &[u8],
    md: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    params: &SlhParams,
) -> Vec<u8> {
    let SlhParams { n, a, k, .. } = *params;
    let kp_addr = get_key_pair_address(adrs);
    let mut roots = Vec::with_capacity(k * n);
    let mut offset = 0;

    for i in 0..k {
        let idx = extract_fors_idx(md, i, a);

        // Secret value -> leaf
        let sk = &fors_signature[offset..offset + n];
        offset += n;

        let mut leaf_adrs = *adrs;
        set_type(&mut leaf_adrs, ADRS_FORS_TREE);
        set_key_pair_address(&mut leaf_adrs, kp_addr);
        set_tree_height(&mut leaf_adrs, 0);
        set_tree_index(&mut leaf_adrs, (i * (1 << a) + idx as usize) as u32);
        let mut node = slh_t(pk_seed, &leaf_adrs, sk, n);

        // Walk auth path
        let mut auth_adrs = *adrs;
        set_type(&mut auth_adrs, ADRS_FORS_TREE);
        set_key_pair_address(&mut auth_adrs, kp_addr);

        for j in 0..a {
            let auth_j = &fors_signature[offset..offset + n];
            offset += n;

            set_tree_height(&mut auth_adrs, (j + 1) as u32);
            let tree_index = (i * (1usize << (a - j - 1))) + ((idx as usize) >> (j + 1));
            set_tree_index(&mut auth_adrs, tree_index as u32);

            let mut combined = Vec::with_capacity(2 * n);
            if (((idx as usize) >> j) & 1) == 0 {
                combined.extend_from_slice(&node);
                combined.extend_from_slice(auth_j);
            } else {
                combined.extend_from_slice(auth_j);
                combined.extend_from_slice(&node);
            }
            node = slh_t(pk_seed, &auth_adrs, &combined, n);
        }
        roots.extend_from_slice(&node);
    }

    // Compress FORS roots into public key
    let mut fors_pk_adrs = *adrs;
    set_type(&mut fors_pk_adrs, ADRS_FORS_ROOTS);
    set_key_pair_address(&mut fors_pk_adrs, kp_addr);
    slh_t(pk_seed, &fors_pk_adrs, &roots, n)
}

// ---------------------------------------------------------------------------
// Top-level: keygen, sign, verify (FIPS 205 Sections 9-10)
// ---------------------------------------------------------------------------

/// SLH-DSA key pair.
#[derive(Debug, Clone)]
pub struct SlhKeyPair {
    /// SK.seed || SK.prf || PK.seed || PK.root
    pub sk: Vec<u8>,
    /// PK.seed || PK.root
    pub pk: Vec<u8>,
}

/// Generate an SLH-DSA key pair.
///
/// If `seed` is provided it must be exactly 3*n bytes (SK.seed || SK.prf || PK.seed).
/// If `None`, a deterministic fallback seed is used (tests should always provide a seed).
pub fn slh_keygen(params: &SlhParams, seed: Option<&[u8]>) -> SlhKeyPair {
    let n = params.n;
    let s = match seed {
        Some(s) => s.to_vec(),
        None => {
            // Deterministic fallback: hash a fixed string and extend
            let mut result = Vec::with_capacity(3 * n);
            let h = sha256_hash(b"slh-dsa-default-seed-for-keygen");
            while result.len() < 3 * n {
                let mut input = Vec::new();
                input.extend_from_slice(&h);
                input.extend_from_slice(&(result.len() as u32).to_be_bytes());
                let block = sha256_hash(&input);
                let take = std::cmp::min(32, 3 * n - result.len());
                result.extend_from_slice(&block[..take]);
            }
            result
        }
    };

    let sk_seed = &s[..n];
    let sk_prf = &s[n..2 * n];
    let pk_seed = &s[2 * n..3 * n];

    // Compute root of the top XMSS tree
    let mut adrs = new_adrs();
    set_layer_address(&mut adrs, (params.d - 1) as u32);
    let root = slh_xmss_node(sk_seed, pk_seed, 0, params.hp as u32, &adrs, params);

    let mut sk = Vec::with_capacity(4 * n);
    sk.extend_from_slice(sk_seed);
    sk.extend_from_slice(sk_prf);
    sk.extend_from_slice(pk_seed);
    sk.extend_from_slice(&root);

    let mut pk = Vec::with_capacity(2 * n);
    pk.extend_from_slice(pk_seed);
    pk.extend_from_slice(&root);

    SlhKeyPair { sk, pk }
}

/// Sign a message using SLH-DSA.
pub fn slh_sign(params: &SlhParams, msg: &[u8], sk: &[u8]) -> Vec<u8> {
    let SlhParams { n, d, hp, k, a, .. } = *params;
    let sk_seed = &sk[..n];
    let sk_prf = &sk[n..2 * n];
    let pk_seed = &sk[2 * n..3 * n];
    let pk_root = &sk[3 * n..4 * n];

    // Randomize (deterministic: optRand = pkSeed)
    let opt_rand = pk_seed;
    let r = slh_prf_msg(sk_prf, opt_rand, msg, n);

    // Compute message digest
    let md_len = (k * a + 7) / 8;
    let tree_idx_len = (params.h - hp + 7) / 8;
    let leaf_idx_len = (hp + 7) / 8;
    let digest_len = md_len + tree_idx_len + leaf_idx_len;
    let digest = slh_hmsg(&r, pk_seed, pk_root, msg, digest_len);

    let md = &digest[..md_len];
    let mut tree_idx: u64 = 0;
    for i in 0..tree_idx_len {
        tree_idx = (tree_idx << 8) | (digest[md_len + i] as u64);
    }
    tree_idx &= (1u64 << (params.h - hp)) - 1;

    let mut leaf_idx: u32 = 0;
    for i in 0..leaf_idx_len {
        leaf_idx = (leaf_idx << 8) | (digest[md_len + tree_idx_len + i] as u32);
    }
    leaf_idx &= (1u32 << hp) - 1;

    // FORS signature
    let mut fors_adrs = new_adrs();
    set_tree_address(&mut fors_adrs, tree_idx);
    set_type(&mut fors_adrs, ADRS_FORS_TREE);
    set_key_pair_address(&mut fors_adrs, leaf_idx);
    let fors_sig = slh_fors_sign(md, sk_seed, pk_seed, &fors_adrs, params);

    // Get FORS public key to sign with hypertree
    let fors_pk = slh_fors_pk_from_sig(&fors_sig, md, pk_seed, &fors_adrs, params);

    // Hypertree signature
    let mut result = Vec::new();
    result.extend_from_slice(&r);
    result.extend_from_slice(&fors_sig);

    let mut current_msg = fors_pk;
    let mut current_tree_idx = tree_idx;
    let mut current_leaf_idx = leaf_idx;

    for layer in 0..d {
        let mut layer_adrs = new_adrs();
        set_layer_address(&mut layer_adrs, layer as u32);
        set_tree_address(&mut layer_adrs, current_tree_idx);

        let xmss_sig = slh_xmss_sign(
            &current_msg,
            sk_seed,
            pk_seed,
            current_leaf_idx,
            &layer_adrs,
            params,
        );

        // Compute next layer's message (root of this XMSS tree)
        current_msg = slh_xmss_pk_from_sig(
            current_leaf_idx,
            &xmss_sig,
            &current_msg,
            pk_seed,
            &layer_adrs,
            params,
        );

        result.extend_from_slice(&xmss_sig);

        current_leaf_idx = (current_tree_idx & ((1u64 << hp) - 1)) as u32;
        current_tree_idx >>= hp;
    }

    result
}

/// Verify an SLH-DSA signature.
pub fn slh_verify(params: &SlhParams, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    let SlhParams { n, d, hp, k, a, len, .. } = *params;

    if pk.len() != 2 * n {
        return false;
    }
    let pk_seed = &pk[..n];
    let pk_root = &pk[n..2 * n];

    // Parse signature
    let mut offset = 0;
    if sig.len() < n {
        return false;
    }
    let r = &sig[offset..offset + n];
    offset += n;

    let fors_sig_len = k * (1 + a) * n;
    if sig.len() < offset + fors_sig_len {
        return false;
    }
    let fors_sig = &sig[offset..offset + fors_sig_len];
    offset += fors_sig_len;

    // Compute message digest
    let md_len = (k * a + 7) / 8;
    let tree_idx_len = (params.h - hp + 7) / 8;
    let leaf_idx_len = (hp + 7) / 8;
    let digest_len = md_len + tree_idx_len + leaf_idx_len;
    let digest = slh_hmsg(r, pk_seed, pk_root, msg, digest_len);

    let md = &digest[..md_len];
    let mut tree_idx: u64 = 0;
    for i in 0..tree_idx_len {
        tree_idx = (tree_idx << 8) | (digest[md_len + i] as u64);
    }
    tree_idx &= (1u64 << (params.h - hp)) - 1;

    let mut leaf_idx: u32 = 0;
    for i in 0..leaf_idx_len {
        leaf_idx = (leaf_idx << 8) | (digest[md_len + tree_idx_len + i] as u32);
    }
    leaf_idx &= (1u32 << hp) - 1;

    // Verify FORS
    let mut fors_adrs = new_adrs();
    set_tree_address(&mut fors_adrs, tree_idx);
    set_type(&mut fors_adrs, ADRS_FORS_TREE);
    set_key_pair_address(&mut fors_adrs, leaf_idx);
    let mut current_msg = slh_fors_pk_from_sig(fors_sig, md, pk_seed, &fors_adrs, params);

    // Verify hypertree
    let mut current_tree_idx = tree_idx;
    let mut current_leaf_idx = leaf_idx;

    let xmss_sig_len = (len + hp) * n;
    for _layer in 0..d {
        if sig.len() < offset + xmss_sig_len {
            return false;
        }
        let xmss_sig = &sig[offset..offset + xmss_sig_len];
        offset += xmss_sig_len;

        let mut layer_adrs = new_adrs();
        set_layer_address(&mut layer_adrs, _layer as u32);
        set_tree_address(&mut layer_adrs, current_tree_idx);

        current_msg = slh_xmss_pk_from_sig(
            current_leaf_idx,
            xmss_sig,
            &current_msg,
            pk_seed,
            &layer_adrs,
            params,
        );

        current_leaf_idx = (current_tree_idx & ((1u64 << hp) - 1)) as u32;
        current_tree_idx >>= hp;
    }

    // Compare computed root to PK.root
    if current_msg.len() != pk_root.len() {
        return false;
    }
    current_msg == pk_root
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wots_len_values() {
        // Verify computed len values match FIPS 205
        assert_eq!(SLH_SHA2_128S.len, 35); // 2*16 + 3 = 35
        assert_eq!(SLH_SHA2_192S.len, 51); // 2*24 + 3 = 51
        assert_eq!(SLH_SHA2_256S.len, 67); // 2*32 + 3 = 67
    }

    #[test]
    fn test_compress_adrs_roundtrip() {
        let mut adrs = new_adrs();
        set_layer_address(&mut adrs, 5);
        set_tree_address(&mut adrs, 42);
        set_type(&mut adrs, ADRS_WOTS_HASH);
        set_key_pair_address(&mut adrs, 7);
        set_chain_address(&mut adrs, 3);
        set_hash_address(&mut adrs, 9);

        let c = compress_adrs(&adrs);
        assert_eq!(c.len(), 22);
        assert_eq!(c[0], 5); // layer
        assert_eq!(c[9], 0); // type (WOTS_HASH = 0)
    }

    #[test]
    fn test_extract_fors_idx() {
        let md = vec![0b10110011, 0b01010101, 0b11001100];
        // tree_idx=0, a=4: first 4 bits = 1011 = 11
        assert_eq!(extract_fors_idx(&md, 0, 4), 11);
        // tree_idx=1, a=4: next 4 bits = 0011 = 3
        assert_eq!(extract_fors_idx(&md, 1, 4), 3);
        // tree_idx=2, a=4: next 4 bits = 0101 = 5
        assert_eq!(extract_fors_idx(&md, 2, 4), 5);
    }

    #[test]
    fn test_base_w() {
        // w=16 means 4-bit nibbles
        let msg = vec![0xAB, 0xCD];
        let digits = base_w(&msg, 16, 4);
        assert_eq!(digits, vec![0xA, 0xB, 0xC, 0xD]);
    }

    #[test]
    fn test_keygen_sign_verify_128f() {
        // Use 128f (fastest parameter set) for testing
        let params = &SLH_SHA2_128F;
        let seed = vec![0x42u8; 3 * params.n];
        let kp = slh_keygen(params, Some(&seed));

        assert_eq!(kp.sk.len(), 4 * params.n);
        assert_eq!(kp.pk.len(), 2 * params.n);

        // pk should be the last 2*n bytes of sk
        assert_eq!(&kp.sk[2 * params.n..], &kp.pk[..]);

        let msg = b"hello SLH-DSA";
        let sig = slh_sign(params, msg, &kp.sk);
        assert!(slh_verify(params, msg, &sig, &kp.pk));

        // Tampered message should fail
        assert!(!slh_verify(params, b"tampered", &sig, &kp.pk));
    }

    #[test]
    fn test_verify_wrong_pk_fails() {
        let params = &SLH_SHA2_128F;
        let seed1 = vec![0x01u8; 3 * params.n];
        let seed2 = vec![0x02u8; 3 * params.n];
        let kp1 = slh_keygen(params, Some(&seed1));
        let kp2 = slh_keygen(params, Some(&seed2));

        let msg = b"test message";
        let sig = slh_sign(params, msg, &kp1.sk);

        // Correct key verifies
        assert!(slh_verify(params, msg, &sig, &kp1.pk));
        // Wrong key fails
        assert!(!slh_verify(params, msg, &sig, &kp2.pk));
    }

    #[test]
    fn test_verify_bad_pk_length() {
        let params = &SLH_SHA2_128F;
        assert!(!slh_verify(params, b"msg", b"sig", b"short"));
    }
}
