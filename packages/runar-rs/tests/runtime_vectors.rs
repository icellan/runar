//! Runtime vectors — cross-SDK consistency check.
//!
//! Loads `conformance/runtime-vectors/hashes.json` (the cross-SDK source of
//! truth for `sha256Finalize`, `blake3Compress`, and `blake3Hash` outputs)
//! and asserts that the Rust SDK's runtime helpers in `runar_lang::prelude`
//! produce the documented output byte-for-byte. Every other consumer
//! (TS / Java / Python / Go / Zig / Ruby) loads the same file and runs the
//! equivalent assertion; a divergence between any two runtime impls shows
//! up here.
//!
//! Reference: `_consumers` in the JSON file enumerates the per-SDK tests
//! that share these vectors.

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

use runar_lang::prelude::{blake3_compress, blake3_hash, sha256_finalize};

#[derive(Deserialize)]
struct Sha256FinalizeVector {
    name: String,
    state: String,
    remaining: String,
    msg_bit_len: i64,
    expected: String,
}

#[derive(Deserialize)]
struct Blake3HashVector {
    name: String,
    input: String,
    expected: String,
}

#[derive(Deserialize)]
struct Blake3CompressVector {
    name: String,
    state: String,
    block: String,
    expected: String,
}

#[derive(Deserialize)]
struct Constants {
    sha256_iv: String,
    blake3_iv: String,
}

#[derive(Deserialize)]
struct RuntimeVectors {
    constants: Constants,
    sha256_finalize: Vec<Sha256FinalizeVector>,
    blake3_hash: Vec<Blake3HashVector>,
    blake3_compress: Vec<Blake3CompressVector>,
}

/// Walk up from CARGO_MANIFEST_DIR until we find the conformance dir.
fn load_vectors() -> RuntimeVectors {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("conformance/runtime-vectors/hashes.json");
        if candidate.is_file() {
            let data = fs::read_to_string(&candidate)
                .unwrap_or_else(|e| panic!("read {}: {}", candidate.display(), e));
            return serde_json::from_str(&data)
                .unwrap_or_else(|e| panic!("parse {}: {}", candidate.display(), e));
        }
        if !dir.pop() {
            panic!(
                "could not locate conformance/runtime-vectors/hashes.json walking up from {}",
                env!("CARGO_MANIFEST_DIR")
            );
        }
    }
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex digit"))
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for byte in b {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

#[test]
fn runtime_vectors_sha256_finalize() {
    let v = load_vectors();
    assert!(
        !v.sha256_finalize.is_empty(),
        "hashes.json carries no sha256_finalize vectors"
    );
    for case in &v.sha256_finalize {
        let state = from_hex(&case.state);
        let remaining = from_hex(&case.remaining);
        let got = sha256_finalize(&state, &remaining, case.msg_bit_len);
        assert_eq!(
            to_hex(&got),
            case.expected,
            "sha256_finalize({}) mismatch",
            case.name
        );
    }
}

#[test]
fn runtime_vectors_blake3_compress() {
    let v = load_vectors();
    assert!(
        !v.blake3_compress.is_empty(),
        "hashes.json carries no blake3_compress vectors"
    );
    for case in &v.blake3_compress {
        let state = from_hex(&case.state);
        let block = from_hex(&case.block);
        let got = blake3_compress(&state, &block);
        assert_eq!(
            to_hex(&got),
            case.expected,
            "blake3_compress({}) mismatch",
            case.name
        );
    }
}

#[test]
fn runtime_vectors_blake3_hash() {
    let v = load_vectors();
    assert!(
        !v.blake3_hash.is_empty(),
        "hashes.json carries no blake3_hash vectors"
    );
    for case in &v.blake3_hash {
        let input = from_hex(&case.input);
        let got = blake3_hash(&input);
        assert_eq!(
            to_hex(&got),
            case.expected,
            "blake3_hash({}) mismatch",
            case.name
        );
    }
}

#[test]
fn runtime_vectors_constants() {
    let v = load_vectors();
    // BLAKE3 deliberately reuses the SHA-256 IV in its compression
    // function. Catching a constant-table typo against the JSON source is
    // the whole point of this row.
    assert_eq!(
        v.constants.blake3_iv, v.constants.sha256_iv,
        "blake3_iv must equal sha256_iv (BLAKE3 spec)"
    );
    let cv = from_hex(&v.constants.blake3_iv);
    let zero_block = vec![0u8; 64];
    let got = blake3_compress(&cv, &zero_block);
    assert_eq!(got.len(), 32, "blake3_compress(IV, zeros) must yield 32 bytes");
}
