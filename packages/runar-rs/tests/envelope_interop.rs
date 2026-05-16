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
