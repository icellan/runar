//! Cross-tier interop test for the signed-envelope wire protocol.
//!
//! Loads `conformance/sdk-envelope/fixtures.json` (TS reference) and asserts
//! canonical_json byte-parity + verify ok/reason parity. See CLAUDE.md
//! §"Seven SDKs Must Stay in Sync".

use std::path::PathBuf;

use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use runar_lang::sdk::{
    canonical_json, verify_envelope, SignedEnvelope, VerifyEnvelopeOpts, VerifyEnvelopeReason,
    MAX_ENVELOPE_PAYLOAD_DEPTH,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../conformance/sdk-envelope/fixtures.json");
    p
}

fn load_fixture() -> Value {
    let bytes = std::fs::read(fixture_path()).expect("read fixture");
    serde_json::from_slice(&bytes).expect("parse fixture")
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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

/// GAP-064 cross-tier signing reproduction. Signing the SAME payload with the
/// SAME key (priv=1) via RFC 6979 deterministic ECDSA (plain-SHA-256 nonce,
/// low-S) MUST yield the byte-identical DER signature the TS reference
/// committed. k256's `sign_prehash` signs the 32-byte digest directly and is
/// deterministic + low-S, matching @bsv/sdk's `primitives/ECDSA` sign.
#[test]
fn signing_vectors() {
    let fixture = load_fixture();
    let alice = SigningKey::from_bytes(
        &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]
        .into(),
    )
    .unwrap();

    let svs = fixture["signing_vectors"]
        .as_array()
        .expect("signing_vectors missing");
    assert!(!svs.is_empty(), "signing_vectors empty");
    for v in svs {
        let id = v["_vector_id"].as_str().unwrap_or("?");
        let expected_payload = v["expected_payload"].as_str().unwrap();
        let expected_sig = v["expected_sig"].as_str().unwrap();

        // Drift guard: re-derive the canonical payload from data + lifetime.
        let mut merged: Map<String, Value> = v["data"].as_object().unwrap().clone();
        merged.insert("nonce".into(), v["nonce"].clone());
        merged.insert("expiresAt".into(), v["expiresAt"].clone());
        let payload = canonical_json(&Value::Object(merged)).expect("canonical_json");
        assert_eq!(payload, expected_payload, "vector {id}: payload");

        // Sign sha256(expected_payload) with priv=1 deterministic ECDSA -> DER.
        let digest = Sha256::digest(expected_payload.as_bytes());
        let (sig, _): (Signature, _) = alice.sign_prehash(&digest).expect("sign_prehash");
        let der = to_hex(sig.to_der().as_bytes());
        assert_eq!(der, expected_sig, "vector {id}: signature divergence");
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

/// R-260. `verify_envelope` must bound payload nesting ITSELF rather than
/// inherit whatever cap serde_json happens to impose, because that cap differs
/// per tier (ruby 100, THIS tier 127, ts/go/python/zig none, java a
/// `StackOverflowError` whose threshold is the JVM's `-Xss` flag). All seven
/// tiers enforce `MAX_ENVELOPE_PAYLOAD_DEPTH` on the payload TEXT, so the same
/// bytes get the same `VerifyEnvelopeReason` everywhere.
#[test]
fn payload_depth_vectors() {
    let fixture = load_fixture();
    let now_ms = fixture["verify_now_ms"].as_i64().unwrap();
    let vectors = fixture["depth_vectors"]
        .as_array()
        .expect("depth_vectors missing");
    assert!(!vectors.is_empty(), "depth_vectors empty");
    for v in vectors {
        let id = v["_vector_id"].as_str().unwrap_or("?");
        let env = envelope_from_value(&v["envelope"]);
        let r = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env,
            expected_keys: None,
            clock_skew_ms: None,
            now_ms: Some(now_ms),
        });
        if v["expect_ok"].as_bool().unwrap() {
            assert!(r.ok, "{id}: expected ok=true, got {:?}", r.reason);
            continue;
        }
        assert!(!r.ok, "{id}: expected ok=false");
        let want = match v["reason"].as_str().unwrap() {
            "bad-json" => VerifyEnvelopeReason::BadJson,
            other => panic!("unknown reason {other}"),
        };
        assert_eq!(r.reason, Some(want), "{id}");
    }
}

/// The bound is part of the wire contract, so the fixture pins it and every
/// tier asserts its own constant against the fixture's number.
#[test]
fn payload_depth_limit_matches_fixture() {
    let fixture = load_fixture();
    assert_eq!(
        fixture["payload_depth_limit"].as_u64().unwrap() as usize,
        MAX_ENVELOPE_PAYLOAD_DEPTH
    );
}

/// R-261. An EXPLICIT clock skew of 0 must mean 0, not "not supplied". Six
/// tiers already distinguished the two (this one via `Option::unwrap_or`); Go
/// conflated them and silently gave a caller asking for strict expiry a
/// five-second replay window, and both Go and Java did the same with the
/// now-override. A `null` in the vector means the caller supplies no value and
/// the tier default applies — that is the control: an over-strict fix reddens
/// on cs2/cs3, not cs1.
#[test]
fn clock_skew_vectors() {
    let fixture = load_fixture();
    let env = envelope_from_value(&fixture["valid_envelope"]);
    let vectors = fixture["clock_skew_vectors"]
        .as_array()
        .expect("clock_skew_vectors missing");
    assert!(!vectors.is_empty(), "clock_skew_vectors empty");
    for v in vectors {
        let id = v["_vector_id"].as_str().unwrap_or("?");
        let r = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env,
            expected_keys: None,
            clock_skew_ms: v["clock_skew_ms"].as_i64(),
            now_ms: Some(v["now_ms"].as_i64().unwrap()),
        });
        if v["expect_ok"].as_bool().unwrap() {
            assert!(r.ok, "{id}: expected ok=true, got {:?}", r.reason);
            continue;
        }
        assert!(!r.ok, "{id}: expected ok=false");
        let want = match v["reason"].as_str().unwrap() {
            "expired" => VerifyEnvelopeReason::Expired,
            other => panic!("unknown reason {other}"),
        };
        assert_eq!(r.reason, Some(want), "{id}");
    }
}
