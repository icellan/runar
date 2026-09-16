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
    canonical_append(&mut out, value, 1)?;
    // G3: total output guard, on the finished buffer's UTF-8 byte length.
    if out.len() > MAX_ENVELOPE_PAYLOAD_BYTES {
        return Err(format!(
            "canonical JSON: output exceeds {MAX_ENVELOPE_PAYLOAD_BYTES} bytes (actual {})",
            out.len()
        ));
    }
    Ok(out)
}

/// `depth` is the 1-based nesting level of the container being written
/// (outermost = 1); scalars ignore it.
fn canonical_append(out: &mut String, value: &Value, depth: usize) -> Result<(), String> {
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
            // For floats we run the ECMA-262 §6.1.6.1.13 Number::toString
            // algorithm so output matches the TS reference byte-for-byte.
            if let Some(i) = n.as_i64() {
                let _ = write!(out, "{}", i);
            } else if let Some(u) = n.as_u64() {
                let _ = write!(out, "{}", u);
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err("canonical JSON: non-finite number".into());
                }
                out.push_str(&format_ecma262_double(f));
            } else {
                return Err("canonical JSON: number not representable".into());
            }
            Ok(())
        }
        Value::String(s) => {
            append_json_string(out, s)?;
            Ok(())
        }
        Value::Array(arr) => {
            // G1: depth guard on entry to the container, before children.
            if depth > MAX_WIRE_NESTING {
                return Err(format!("canonical JSON: nesting exceeds {MAX_WIRE_NESTING}"));
            }
            out.push('[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_append(out, e, depth + 1)?;
            }
            out.push(']');
            Ok(())
        }
        Value::Object(obj) => {
            // G1: depth guard on entry to the container, before children.
            if depth > MAX_WIRE_NESTING {
                return Err(format!("canonical JSON: nesting exceeds {MAX_WIRE_NESTING}"));
            }
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
                append_json_string(out, k)?;
                out.push(':');
                canonical_append(out, v, depth + 1)?;
            }
            out.push('}');
            Ok(())
        }
    }
}

/// Format a finite double per ECMA-262 §6.1.6.1.13 Number::toString. Output
/// is byte-identical to JS `JSON.stringify(x)` / `String(x)` for any finite
/// `x` (including NaN/Inf, which the caller is responsible for filtering).
///
/// Algorithm (paraphrased from the spec):
///   1. If x == 0, return "0".
///   2. If x < 0, return "-" + format(-x).
///   3. Otherwise pick the shortest digit string n (s digits) and integer k
///      s.t. n * 10^(k - s) == x and the float round-trips.
///   4. If k <= 21 and k >= s, output digits + (k - s) zeros.
///   5. If 0 < k <= 21, output digits[..k] + "." + digits[k..].
///   6. If -6 < k <= 0, output "0." + ((-k) zeros) + digits.
///   7. Else (single-digit case) output digits + "e" + sign + |k - 1|, or
///      digits[0] + "." + digits[1..] + "e" + sign + |k - 1|.
fn format_ecma262_double(x: f64) -> String {
    if x == 0.0 {
        return "0".to_string();
    }
    if x.is_sign_negative() {
        return format!("-{}", format_ecma262_double(-x));
    }
    // Rust's default `{}` for f64 prints the shortest round-trip decimal
    // string (Ryu-equivalent). For values like 1e21 it emits "1e21";
    // for 1.5e10 it emits "15000000000". We re-derive (digits, k) from
    // the formatted string and re-emit per the ECMA rules, so the output
    // is independent of Rust's chosen surface form.
    let s = format!("{}", x);

    // Split into mantissa and explicit exponent (Rust's debug shape).
    let (mantissa, exp_part): (&str, i32) = match s.find(['e', 'E']) {
        Some(i) => {
            let (m, e) = s.split_at(i);
            let e_val: i32 = e[1..].parse().unwrap_or(0);
            (m, e_val)
        }
        None => (s.as_str(), 0),
    };

    // Split mantissa into integer and fractional parts.
    let (int_part, frac_part) = match mantissa.find('.') {
        Some(i) => (&mantissa[..i], &mantissa[i + 1..]),
        None => (mantissa, ""),
    };

    // Collect significant digits (skip leading zeros for normalization),
    // track how many leading zeros there were in the fractional part so we
    // can compute k correctly.
    let raw_digits: String = int_part.chars().chain(frac_part.chars()).collect();
    let leading_zeros: usize = raw_digits.bytes().take_while(|b| *b == b'0').count();
    let trimmed_leading: &str = &raw_digits[leading_zeros..];
    // Strip trailing zeros so we have only the significant digits.
    let mut digits: String = trimmed_leading.trim_end_matches('0').to_string();
    if digits.is_empty() {
        // The value was 0 (caught above) or all-zeros after normalization —
        // safe to emit "0".
        return "0".to_string();
    }

    // Compute k: position of decimal relative to the digit string.
    //   - int_part.len() is the number of digits before the decimal in the
    //     surface form.
    //   - leading_zeros are absorbed (they shift k down).
    //   - exp_part adjusts k by its value.
    let int_digit_count = int_part.len() as i32;
    let k: i32 = int_digit_count - (leading_zeros as i32) + exp_part;
    let s_len: i32 = digits.len() as i32;

    // ECMA-262 §6.1.6.1.13.
    if k >= s_len && k <= 21 {
        digits.push_str(&"0".repeat((k - s_len) as usize));
        return digits;
    }
    if k > 0 && k <= 21 {
        let (a, b) = digits.split_at(k as usize);
        return format!("{}.{}", a, b);
    }
    if k > -6 && k <= 0 {
        return format!("0.{}{}", "0".repeat((-k) as usize), digits);
    }
    // Scientific notation.
    let exp = k - 1;
    let exp_sign = if exp >= 0 { '+' } else { '-' };
    let exp_abs = exp.unsigned_abs();
    if s_len == 1 {
        format!("{}e{}{}", digits, exp_sign, exp_abs)
    } else {
        let (a, b) = digits.split_at(1);
        format!("{}.{}e{}{}", a, b, exp_sign, exp_abs)
    }
}

fn append_json_string(out: &mut String, s: &str) -> Result<(), String> {
    // G2: string-byte guard on the RAW input, before escaping, so the bound is
    // about the caller's data rather than about how much the escaper inflated
    // it. Object KEYS route through here too, so an oversized key is rejected
    // the same way an oversized value is.
    if s.len() > MAX_ENVELOPE_FIELD_BYTES {
        return Err(format!(
            "canonical JSON: string exceeds {MAX_ENVELOPE_FIELD_BYTES} bytes (actual {})",
            s.len()
        ));
    }
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
    Ok(())
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
    /// Mirrors the TS 'too-large' reason. Returned BEFORE any JSON parse /
    /// ECDSA verify work when an envelope string field exceeds its
    /// InputLimits cap (DoS-bound). BUG-008 follow-up.
    TooLarge,
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
            Self::TooLarge => "too-large",
        }
    }
}

/// Envelope DoS-bound caps. Mirror InputLimits.{MAX_IR_BYTES,
/// MAX_STRING_BYTES} from the TS schema package. BUG-008 follow-up.
pub const MAX_ENVELOPE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ENVELOPE_FIELD_BYTES: usize = 4 * 1024 * 1024;

/// Maximum payload nesting `verify_envelope` will parse: the number of containers
/// enclosing a value, 1-based, outermost = 1. 100 is accepted, 101 is rejected.
/// R-260.
///
/// Without an explicit bound the limit was whatever each tier's stock JSON library
/// imposed, and those differ. Measured on ONE envelope, payload
/// {"deep":<N-deep array>,...}: ruby flipped to bad-json at total depth 101
/// (JSON.parse default max_nesting: 100) and rust at 128 (serde_json
/// RECURSION_LIMIT); ts, go, python and zig accepted every depth probed (zig's
/// iterative scanner took 100001 without complaint); and java threw
/// StackOverflowError straight OUT of verify -- its hand-written parser is
/// recursive with no cap and verify catches Exception, not Error -- at ~5000 deep
/// on a default JVM stack and ~1000 deep under -Xss512k, i.e. a contract escape on
/// unauthenticated input whose threshold was a JVM launch flag rather than a
/// protocol property.
///
/// 100 is Ruby's native JSON.parse default EXACTLY and sits 27 below rust's 127,
/// so no tier has to hand-roll or reconfigure its parser to stay inside it. It is
/// also far above what the wire needs: the deepest of the 163 checked-in
/// conformance artifacts is depth 15 and conformance/sdk-envelope/fixtures.json
/// tops out at 6. The number is deliberately the SAME as canonicalJson's emit-side
/// bound: if parse were the smaller of the two, a tier could emit a legal,
/// correctly-signed envelope that another tier is physically unable to parse.
///
/// The guard runs on the payload TEXT, immediately before the stock parser, and is
/// a flat non-recursive bracket scan so the guard itself cannot overflow.
pub const MAX_ENVELOPE_PAYLOAD_DEPTH: usize = 100;

/// Bounds the nesting `canonical_json` will EMIT: the number of containers
/// enclosing a value, 1-based, outermost = 1. 100 is accepted, 101 is rejected.
///
/// Deliberately the same number `verify_envelope` enforces on the parse side
/// (`MAX_ENVELOPE_PAYLOAD_DEPTH`) — if emit allowed more than parse, this tier
/// could produce a legal, correctly-signed envelope another tier is physically
/// unable to read. It is NOT the compiler's IR nesting bound (512): that
/// serves the `--ir` loader, which reads a trusted local file rather than
/// unauthenticated wire input. R-260.
///
/// `canonical_json`'s byte guards reuse the envelope caps rather than
/// restating the numbers, so emit and parse cannot drift apart: a single
/// string field is bounded by `MAX_ENVELOPE_FIELD_BYTES` (4 MiB) and the
/// finished document by `MAX_ENVELOPE_PAYLOAD_BYTES` (16 MiB).
pub const MAX_WIRE_NESTING: usize = 100;

/// Does the payload text nest deeper than MAX_ENVELOPE_PAYLOAD_DEPTH?
///
/// Counts the maximum number of simultaneously-open {/[ containers, skipping
/// anything inside a JSON string (so a value of "[[[[..." is not nesting). The
/// scan is FLAT -- no recursion -- which is the point: a guard that recursed
/// would overflow on exactly the input it exists to reject. It bails out the
/// instant the bound is passed, so a 200 KB bracket bomb costs a few hundred
/// bytes of scanning.
///
/// This does not validate JSON; malformed input still falls through to the real
/// parser and its own bad-json rejection.
fn payload_exceeds_max_depth(payload: &str) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in payload.as_bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_ENVELOPE_PAYLOAD_DEPTH {
                    return true;
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    false
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

    // 0. DoS-bound size guard. Reject envelopes whose string fields exceed
    //    their InputLimits cap BEFORE running JSON parse, hashing, or
    //    ECDSA verify — those operations are linear in input size and a
    //    pathological 100 MB payload would otherwise pin the thread.
    //    Mirrors the TS 'too-large' rejection at sdk/envelope.ts:104.
    //    BUG-008 follow-up.
    if env.payload.len() > MAX_ENVELOPE_PAYLOAD_BYTES
        || env.sig.len() > MAX_ENVELOPE_FIELD_BYTES
        || env.pubkey.len() > MAX_ENVELOPE_FIELD_BYTES
    {
        return reject(VerifyEnvelopeReason::TooLarge, None);
    }

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
    //
    // R-260: bound nesting on the TEXT, before serde_json, so the answer does
    // not depend on its RECURSION_LIMIT (127 here, but 100 in ruby and absent
    // in four other tiers). Same bound and same reason in all seven tiers.
    if payload_exceeds_max_depth(&env.payload) {
        return reject(VerifyEnvelopeReason::BadJson, None);
    }
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
    fn canonical_json_formats_floats_per_ecma262() {
        // Audit D5. serde_json::Value::from(f64) preserves the int-vs-float
        // distinction; the canonical serializer must run the ECMA-262 §6.1.6.1.13
        // Number::toString algorithm rather than relying on Rust's default
        // Display impl.
        assert_eq!(canonical_json(&json!({"v": 0.1})).unwrap(), r#"{"v":0.1}"#);
        assert_eq!(canonical_json(&json!({"v": 1e21})).unwrap(), r#"{"v":1e+21}"#);
        assert_eq!(canonical_json(&json!({"v": 1e-7})).unwrap(), r#"{"v":1e-7}"#);
        assert_eq!(canonical_json(&json!({"v": 1e-300})).unwrap(), r#"{"v":1e-300}"#);
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
