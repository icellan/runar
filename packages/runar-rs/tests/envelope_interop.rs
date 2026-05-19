//! Cross-tier interop test for the signed-envelope wire protocol.
//!
//! Loads `conformance/sdk-envelope/fixtures.json` (TS reference) and asserts
//! canonical_json byte-parity + verify ok/reason parity. See CLAUDE.md
//! §"Seven SDKs Must Stay in Sync".

use std::path::PathBuf;

use runar_lang::sdk::{
    canonical_json, verify_envelope, SignedEnvelope, VerifyEnvelopeOpts, VerifyEnvelopeReason,
};
use serde_json::Value;

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../conformance/sdk-envelope/fixtures.json");
    p
}

fn load_fixture() -> Value {
    let bytes = std::fs::read(fixture_path()).expect("read fixture");
    serde_json::from_slice(&bytes).expect("parse fixture")
}

#[test]
fn canonical_json_vectors() {
    let fixture = load_fixture();
    let vectors = fixture["canonical_json_vectors"].as_array().unwrap();
    for (i, v) in vectors.iter().enumerate() {
        let got = canonical_json(&v["input"]).expect("canonical_json");
        let expected = v["expected"].as_str().unwrap();
        assert_eq!(got, expected, "vector {i}");
    }
}

fn envelope_from_value(v: &Value) -> SignedEnvelope {
    SignedEnvelope {
        payload: v["payload"].as_str().unwrap().to_string(),
        sig: v["sig"].as_str().unwrap().to_string(),
        pubkey: v["pubkey"].as_str().unwrap().to_string(),
        nonce: v["nonce"].as_i64().unwrap(),
        expires_at: v["expiresAt"].as_i64().unwrap(),
    }
}

#[test]
fn verify_valid_envelope() {
    let fixture = load_fixture();
    let env = envelope_from_value(&fixture["valid_envelope"]);
    let now_ms = fixture["verify_now_ms"].as_i64().unwrap();
    let r = verify_envelope(VerifyEnvelopeOpts {
        envelope: &env,
        expected_keys: None,
        clock_skew_ms: None,
        now_ms: Some(now_ms),
    });
    assert!(r.ok, "reason: {:?}", r.reason);
}

#[test]
fn rejection_vectors() {
    let fixture = load_fixture();
    let now_ms = fixture["verify_now_ms"].as_i64().unwrap();
    let rejections = fixture["rejection_vectors"].as_array().unwrap();
    for rv in rejections {
        let env = envelope_from_value(&rv["envelope"]);
        let r = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env,
            expected_keys: None,
            clock_skew_ms: None,
            now_ms: Some(now_ms),
        });
        assert!(!r.ok, "rejection {} should be ok=false", rv["reason"]);
        let expected = match rv["reason"].as_str().unwrap() {
            "missing-fields" => VerifyEnvelopeReason::MissingFields,
            "expired" => VerifyEnvelopeReason::Expired,
            "bad-json" => VerifyEnvelopeReason::BadJson,
            "envelope-mismatch" => VerifyEnvelopeReason::EnvelopeMismatch,
            "bad-sig" => VerifyEnvelopeReason::BadSig,
            "pubkey-not-allowed" => VerifyEnvelopeReason::PubkeyNotAllowed,
            other => panic!("unknown reason {other}"),
        };
        assert_eq!(r.reason, Some(expected), "rejection {}", rv["reason"]);
    }
}

/// RFC 8785 §3.2.2.2 — canonical_json MUST reject malformed Unicode (lone
/// surrogate). See audits/canonical-json-rfc8785-parity.md §3 rec 6 (D6).
///
/// Rust's `String` type is correct-by-construction: it cannot hold a lone
/// surrogate at all (the encoding is rejected at `String::from_utf8` /
/// `str::from_utf8` time). This test asserts that property explicitly — if a
/// future change weakens the input type (e.g. switches to `Vec<u8>` with an
/// `unsafe` blessing), the rejection invariant must move down into
/// canonical_json itself.
#[test]
fn canonical_json_rejection_vectors() {
    let fixture = load_fixture();
    let rvs = fixture["canonical_json_rejection_vectors"]
        .as_array()
        .expect("canonical_json_rejection_vectors missing");
    assert!(!rvs.is_empty(), "canonical_json_rejection_vectors empty");
    for v in rvs {
        let id = v["_vector_id"].as_str().unwrap_or("?");
        let units = v["input_value_utf16_units"].as_array().unwrap();
        // Encode each code unit as its 3-byte UTF-8 form (illegal for
        // surrogates).
        let mut bytes: Vec<u8> = Vec::new();
        for u in units {
            let cp = u.as_u64().unwrap() as u32;
            bytes.push(0xe0 | ((cp >> 12) as u8));
            bytes.push(0x80 | (((cp >> 6) & 0x3f) as u8));
            bytes.push(0x80 | ((cp & 0x3f) as u8));
        }
        // The gate: Rust's safe string constructors MUST reject this byte
        // sequence. canonical_json is therefore never reachable with a lone
        // surrogate in well-formed (non-unsafe) Rust code.
        let r = std::str::from_utf8(&bytes);
        assert!(
            r.is_err(),
            "vector {id}: str::from_utf8 unexpectedly accepted lone-surrogate bytes; \
             the Rust tier's canonical_json correct-by-construction gate is broken — \
             canonical_json itself must now reject lone surrogates explicitly"
        );
    }
}
