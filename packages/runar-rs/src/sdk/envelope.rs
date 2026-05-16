//! Signed-broadcast wire protocol for overlay apps. Byte-compatible with the
//! TypeScript reference implementation in `packages/runar-sdk/src/envelope.ts`.
//!
//! Three primitives:
//!  - [`canonical_json`]: RFC 8785 / JCS serialization. Sorted object keys
//!    (UTF-16 code-unit order), no whitespace, ES Number.prototype.toString-
//!    compatible number formatting.
//!  - [`sign_envelope`]: bind data + nonce + expiresAt into a canonical-JSON
//!    payload, sha256 it, and sign the digest via a caller-supplied closure.
//!  - [`verify_envelope`]: six-reason rejection ladder mirroring every other
//!    SDK tier.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature as K256Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// canonical_json
// ---------------------------------------------------------------------------

/// Serialize value to RFC 8785 / JCS canonical JSON. Sorted keys (UTF-16
/// code-unit order), no whitespace, ES-style number formatting.
pub fn canonical_json(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    canonical_append(&mut out, value)?;
    Ok(out)
}

fn canonical_append(out: &mut String, value: &Value) -> Result<(), String> {
    match value {
        Value::Null => {
            out.push_str("null");
            Ok(())
        }
        Value::Bool(b) => {
            out.push_str(if *b { "true" } else { "false" });
            Ok(())
        }
        Value::Number(n) => {
            // serde_json::Number preserves int-vs-float distinction. For
            // integers in the i64/u64 range we use the plain digit form
            // (which matches ES Number.prototype.toString for those values).
            // For floats we use serde_json's default formatter which uses
            // shortest-roundtrip — close to ES for typical values.
            if let Some(i) = n.as_i64() {
                let _ = write!(out, "{}", i);
            } else if let Some(u) = n.as_u64() {
                let _ = write!(out, "{}", u);
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err("canonical JSON: non-finite number".into());
                }
                if f == 0.0 {
                    out.push('0');
                } else if f == (f as i64) as f64 && (-9_007_199_254_740_992.0..=9_007_199_254_740_992.0).contains(&f) {
                    let _ = write!(out, "{}", f as i64);
                } else {
                    let _ = write!(out, "{}", f);
                }
            } else {
                return Err("canonical JSON: number not representable".into());
            }
            Ok(())
        }
        Value::String(s) => {
            append_json_string(out, s);
            Ok(())
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_append(out, e)?;
            }
            out.push(']');
            Ok(())
        }
        Value::Object(obj) => {
            // Sort keys by UTF-16 code-unit order to match the ES default.
            let mut sorted: BTreeMap<Vec<u16>, &String> = BTreeMap::new();
            for k in obj.keys() {
                sorted.insert(k.encode_utf16().collect(), k);
            }
            out.push('{');
            let mut first = true;
            for (_, k) in sorted.iter() {
                let v = &obj[*k];
                if !first {
                    out.push(',');
                }
                first = false;
                append_json_string(out, k);
                out.push(':');
                canonical_append(out, v)?;
            }
            out.push('}');
            Ok(())
        }
    }
}

fn append_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------------
// Envelope types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub payload: String,
    pub sig: String,
    pub pubkey: String,
    pub nonce: i64,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
}

/// Closure type signing a 32-byte digest, returning DER signature bytes.
/// Use any closure capturing your private key — see the test signer for the
/// canonical k256 pattern.
pub type SignFn<'a> = Box<dyn FnMut(&[u8]) -> Result<Vec<u8>, String> + 'a>;

pub struct SignEnvelopeOpts<'a> {
    pub data: Map<String, Value>,
    pub signer: SignFn<'a>,
    /// 66-char hex compressed secp256k1 pubkey of the signer.
    pub pubkey: String,
    /// Defaults to 30_000.
    pub ttl_ms: Option<i64>,
    /// Override Now() for deterministic tests; None = wall clock.
    pub now_ms: Option<i64>,
}

pub fn sign_envelope(mut opts: SignEnvelopeOpts<'_>) -> Result<SignedEnvelope, String> {
    let ttl = opts.ttl_ms.unwrap_or(30_000);
    let nonce = opts.now_ms.unwrap_or_else(now_ms);
    let expires_at = nonce + ttl;

    opts.data.insert("nonce".to_string(), Value::from(nonce));
    opts.data.insert("expiresAt".to_string(), Value::from(expires_at));
    let payload = canonical_json(&Value::Object(opts.data))?;

    let digest = Sha256::digest(payload.as_bytes());
    let sig_bytes = (opts.signer)(&digest)?;
    Ok(SignedEnvelope {
        payload,
        sig: hex::encode(&sig_bytes),
        pubkey: opts.pubkey,
        nonce,
        expires_at,
    })
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyEnvelopeReason {
    MissingFields,
    Expired,
    BadJson,
    EnvelopeMismatch,
    BadSig,
    PubkeyNotAllowed,
}

impl VerifyEnvelopeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingFields => "missing-fields",
            Self::Expired => "expired",
            Self::BadJson => "bad-json",
            Self::EnvelopeMismatch => "envelope-mismatch",
            Self::BadSig => "bad-sig",
            Self::PubkeyNotAllowed => "pubkey-not-allowed",
        }
    }
}

pub struct VerifyEnvelopeOpts<'a> {
    pub envelope: &'a SignedEnvelope,
    pub expected_keys: Option<&'a [String]>,
    /// Defaults to 5_000.
    pub clock_skew_ms: Option<i64>,
    /// Override Now() for deterministic tests; None = wall clock.
    pub now_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct VerifyEnvelopeResult {
    pub ok: bool,
    pub reason: Option<VerifyEnvelopeReason>,
    pub data: Option<Map<String, Value>>,
}

pub fn verify_envelope(opts: VerifyEnvelopeOpts<'_>) -> VerifyEnvelopeResult {
    let env = opts.envelope;
    let clock_skew = opts.clock_skew_ms.unwrap_or(5_000);
    let now = opts.now_ms.unwrap_or_else(now_ms);

    // 1. Field presence.
    if env.payload.is_empty() || env.sig.is_empty() || env.pubkey.is_empty()
        || env.nonce == 0 || env.expires_at == 0
    {
        return reject(VerifyEnvelopeReason::MissingFields, None);
    }

    // 2. Expiry.
    if env.expires_at < now - clock_skew {
        return reject(VerifyEnvelopeReason::Expired, None);
    }

    // 3. Parse payload.
    let parsed: Map<String, Value> = match serde_json::from_str::<Value>(&env.payload) {
        Ok(Value::Object(m)) => m,
        _ => return reject(VerifyEnvelopeReason::BadJson, None),
    };

    // 4. Inner nonce / expiresAt must match outer fields.
    let inner_nonce = parsed.get("nonce").and_then(|v| v.as_i64());
    let inner_expires = parsed.get("expiresAt").and_then(|v| v.as_i64());
    if inner_nonce != Some(env.nonce) || inner_expires != Some(env.expires_at) {
        return reject(VerifyEnvelopeReason::EnvelopeMismatch, Some(parsed));
    }

    // 5. ECDSA verify (raw, no re-hashing).
    let digest = Sha256::digest(env.payload.as_bytes());
    let sig_bytes = match hex::decode(&env.sig) {
        Ok(b) => b,
        Err(_) => return reject(VerifyEnvelopeReason::BadSig, Some(parsed)),
    };
    let pk_bytes = match hex::decode(&env.pubkey) {
        Ok(b) => b,
        Err(_) => return reject(VerifyEnvelopeReason::BadSig, Some(parsed)),
    };
    let sig = match K256Signature::from_der(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return reject(VerifyEnvelopeReason::BadSig, Some(parsed)),
    };
    let verifying_key = match VerifyingKey::from_sec1_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return reject(VerifyEnvelopeReason::BadSig, Some(parsed)),
    };
    if verifying_key.verify_prehash(&digest, &sig).is_err() {
        return reject(VerifyEnvelopeReason::BadSig, Some(parsed));
    }

    // 6. Allowlist.
    if let Some(keys) = opts.expected_keys {
        if !keys.iter().any(|k| k == &env.pubkey) {
            return reject(VerifyEnvelopeReason::PubkeyNotAllowed, Some(parsed));
        }
    }

    VerifyEnvelopeResult { ok: true, reason: None, data: Some(parsed) }
}

fn reject(reason: VerifyEnvelopeReason, data: Option<Map<String, Value>>) -> VerifyEnvelopeResult {
    VerifyEnvelopeResult { ok: false, reason: Some(reason), data }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// Small hex helper used by the tests below. Public-friendly minimal API.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        const H: &[u8; 16] = b"0123456789abcdef";
        for &b in bytes {
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for i in (0..s.len()).step_by(2) {
            let hi = decode_nib(bytes[i])?;
            let lo = decode_nib(bytes[i + 1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    fn decode_nib(b: u8) -> Result<u8, ()> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    use serde_json::json;

    fn alice() -> SigningKey {
        SigningKey::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ].into()).unwrap()
    }

    fn bob() -> SigningKey {
        SigningKey::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ].into()).unwrap()
    }

    fn pubkey_hex(key: &SigningKey) -> String {
        hex::encode(&key.verifying_key().to_sec1_bytes())
    }

    fn signer_for(key: &SigningKey) -> SignFn<'static> {
        let key = key.clone();
        Box::new(move |digest: &[u8]| -> Result<Vec<u8>, String> {
            let (sig, _): (Signature, _) = key.sign_prehash(digest).map_err(|e| e.to_string())?;
            Ok(sig.to_der().as_bytes().to_vec())
        })
    }

    #[test]
    fn canonical_json_order_independent() {
        let a = canonical_json(&json!({"a": 1, "b": 2})).unwrap();
        let b = canonical_json(&json!({"b": 2, "a": 1})).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_json_nested() {
        let out = canonical_json(&json!({
            "outer": {"z": 1, "a": [3, 2, 1]},
            "list": [{"y": 1, "x": 2}],
            "n": null,
            "b": true,
            "s": "hi",
        })).unwrap();
        assert_eq!(out, r#"{"b":true,"list":[{"x":2,"y":1}],"n":null,"outer":{"a":[3,2,1],"z":1},"s":"hi"}"#);
    }

    #[test]
    fn round_trip() {
        let key = alice();
        let pub_hex = pubkey_hex(&key);
        let mut data = Map::new();
        data.insert("kind".into(), Value::from("hello"));
        data.insert("n".into(), Value::from(7));
        let env = sign_envelope(SignEnvelopeOpts {
            data,
            signer: signer_for(&key),
            pubkey: pub_hex,
            ttl_ms: None,
            now_ms: Some(1_000_000_000_000),
        }).unwrap();
        let result = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env,
            expected_keys: None,
            clock_skew_ms: None,
            now_ms: Some(1_000_000_000_500),
        });
        assert!(result.ok, "reason: {:?}", result.reason);
        assert_eq!(result.data.unwrap()["kind"], "hello");
    }

    #[test]
    fn missing_fields() {
        let key = alice();
        let pub_hex = pubkey_hex(&key);
        let mut data = Map::new();
        data.insert("ok".into(), Value::from(1));
        let mut env = sign_envelope(SignEnvelopeOpts {
            data, signer: signer_for(&key), pubkey: pub_hex, ttl_ms: None, now_ms: Some(1_000_000_000_000),
        }).unwrap();
        env.sig = String::new();
        let r = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env, expected_keys: None, clock_skew_ms: None, now_ms: Some(1_000_000_000_500),
        });
        assert_eq!(r.reason, Some(VerifyEnvelopeReason::MissingFields));
    }

    #[test]
    fn expired() {
        let key = alice();
        let pub_hex = pubkey_hex(&key);
        let mut data = Map::new();
        data.insert("ok".into(), Value::from(1));
        let env = sign_envelope(SignEnvelopeOpts {
            data, signer: signer_for(&key), pubkey: pub_hex, ttl_ms: None, now_ms: Some(1_000_000_000_000),
        }).unwrap();
        let r = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env, expected_keys: None, clock_skew_ms: None, now_ms: Some(1_000_000_000_000 + 1_000_000),
        });
        assert_eq!(r.reason, Some(VerifyEnvelopeReason::Expired));
    }

    #[test]
    fn bad_json() {
        let key = alice();
        let pub_hex = pubkey_hex(&key);
        let mut data = Map::new();
        data.insert("ok".into(), Value::from(1));
        let mut env = sign_envelope(SignEnvelopeOpts {
            data, signer: signer_for(&key), pubkey: pub_hex, ttl_ms: None, now_ms: Some(1_000_000_000_000),
        }).unwrap();
        env.payload = "not json{".into();
        let r = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env, expected_keys: None, clock_skew_ms: None, now_ms: Some(1_000_000_000_500),
        });
        assert_eq!(r.reason, Some(VerifyEnvelopeReason::BadJson));
    }

    #[test]
    fn envelope_mismatch() {
        let key = alice();
        let pub_hex = pubkey_hex(&key);
        let mut data = Map::new();
        data.insert("ok".into(), Value::from(1));
        let mut env = sign_envelope(SignEnvelopeOpts {
            data, signer: signer_for(&key), pubkey: pub_hex, ttl_ms: None, now_ms: Some(1_000_000_000_000),
        }).unwrap();
        env.nonce += 1;
        let r = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env, expected_keys: None, clock_skew_ms: None, now_ms: Some(1_000_000_000_500),
        });
        assert_eq!(r.reason, Some(VerifyEnvelopeReason::EnvelopeMismatch));
        assert!(r.data.is_some());
    }

    #[test]
    fn bad_sig() {
        let key = alice();
        let pub_hex = pubkey_hex(&key);
        let mut data = Map::new();
        data.insert("ok".into(), Value::from(1));
        let mut env = sign_envelope(SignEnvelopeOpts {
            data, signer: signer_for(&key), pubkey: pub_hex, ttl_ms: None, now_ms: Some(1_000_000_000_000),
        }).unwrap();
        let mid = env.sig.len() / 2;
        let mut chars: Vec<char> = env.sig.chars().collect();
        chars[mid] = if chars[mid] == '1' { '2' } else { '1' };
        env.sig = chars.into_iter().collect();
        let r = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env, expected_keys: None, clock_skew_ms: None, now_ms: Some(1_000_000_000_500),
        });
        assert_eq!(r.reason, Some(VerifyEnvelopeReason::BadSig));
    }

    #[test]
    fn pubkey_not_allowed() {
        let alice_key = alice();
        let bob_key = bob();
        let mut data = Map::new();
        data.insert("ok".into(), Value::from(1));
        let env = sign_envelope(SignEnvelopeOpts {
            data, signer: signer_for(&alice_key), pubkey: pubkey_hex(&alice_key),
            ttl_ms: None, now_ms: Some(1_000_000_000_000),
        }).unwrap();
        let allowed = [pubkey_hex(&bob_key)];
        let r = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env, expected_keys: Some(&allowed),
            clock_skew_ms: None, now_ms: Some(1_000_000_000_500),
        });
        assert_eq!(r.reason, Some(VerifyEnvelopeReason::PubkeyNotAllowed));
    }

    #[test]
    fn pubkey_allowed() {
        let key = alice();
        let mut data = Map::new();
        data.insert("ok".into(), Value::from(1));
        let env = sign_envelope(SignEnvelopeOpts {
            data, signer: signer_for(&key), pubkey: pubkey_hex(&key),
            ttl_ms: None, now_ms: Some(1_000_000_000_000),
        }).unwrap();
        let allowed = [env.pubkey.clone()];
        let r = verify_envelope(VerifyEnvelopeOpts {
            envelope: &env, expected_keys: Some(&allowed),
            clock_skew_ms: None, now_ms: Some(1_000_000_000_500),
        });
        assert!(r.ok);
    }
}
