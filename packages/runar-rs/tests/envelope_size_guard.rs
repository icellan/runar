//! BUG-008 follow-up: envelope size-guard regression tests for the
//! Rust tier. Mirrors `packages/runar-go/sdk_envelope_size_test.go`.

use runar_lang::sdk::{
    verify_envelope, SignedEnvelope, VerifyEnvelopeOpts, VerifyEnvelopeReason,
    MAX_ENVELOPE_FIELD_BYTES, MAX_ENVELOPE_PAYLOAD_BYTES,
};

fn baseline() -> SignedEnvelope {
    SignedEnvelope {
        payload: "{}".to_string(),
        sig: "deadbeef".to_string(),
        pubkey: "deadbeef".to_string(),
        nonce: 1,
        expires_at: i64::MAX / 2,
    }
}

#[test]
fn verify_envelope_rejects_oversized_payload() {
    let mut env = baseline();
    env.payload = " ".repeat(MAX_ENVELOPE_PAYLOAD_BYTES + 1);
    let res = verify_envelope(VerifyEnvelopeOpts {
        envelope: &env,
        expected_keys: None,
        clock_skew_ms: None,
        now_ms: Some(0),
    });
    assert!(!res.ok);
    assert_eq!(res.reason, Some(VerifyEnvelopeReason::TooLarge));
}

#[test]
fn verify_envelope_rejects_oversized_sig() {
    let mut env = baseline();
    env.sig = "a".repeat(MAX_ENVELOPE_FIELD_BYTES + 1);
    let res = verify_envelope(VerifyEnvelopeOpts {
        envelope: &env,
        expected_keys: None,
        clock_skew_ms: None,
        now_ms: Some(0),
    });
    assert_eq!(res.reason, Some(VerifyEnvelopeReason::TooLarge));
}

#[test]
fn verify_envelope_rejects_oversized_pubkey() {
    let mut env = baseline();
    env.pubkey = "a".repeat(MAX_ENVELOPE_FIELD_BYTES + 1);
    let res = verify_envelope(VerifyEnvelopeOpts {
        envelope: &env,
        expected_keys: None,
        clock_skew_ms: None,
        now_ms: Some(0),
    });
    assert_eq!(res.reason, Some(VerifyEnvelopeReason::TooLarge));
}

#[test]
fn verify_envelope_normal_sized_envelope_passes_size_check() {
    // A small but otherwise invalid envelope: the size guard must NOT
    // fire (it should reach missing-fields / bad-sig downstream).
    let env = baseline();
    let res = verify_envelope(VerifyEnvelopeOpts {
        envelope: &env,
        expected_keys: None,
        clock_skew_ms: None,
        now_ms: Some(0),
    });
    assert_ne!(res.reason, Some(VerifyEnvelopeReason::TooLarge));
}
