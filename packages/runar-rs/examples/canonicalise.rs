//! Rust-tier CLI shim for the cross-tier canonicalJson (RFC 8785 / JCS)
//! differential fuzzer (conformance/fuzzer/canonical-json-differential.ts).
//!
//! Protocol (single-shot, stdin -> stdout), mirrors the Go shim
//! (packages/runar-go/cmd/canonicalise):
//!
//!   {"mode":"json","value":<any JSON>}
//!       Parse `value` with serde_json (which preserves the int-vs-float
//!       distinction just like the envelope_interop test), run
//!       runar_lang::sdk::canonical_json, print canonical bytes, exit 0.
//!   {"mode":"utf16","key":"<string>","units":[<int>,...]}
//!       Build {key: <string from UTF-16 code units>}. Rust's `String` is
//!       guaranteed well-formed UTF-8 and cannot hold a lone surrogate, so a
//!       lone surrogate is rejected *structurally at the type boundary* —
//!       which is the documented Rust behaviour in fixtures.json. The shim
//!       reports that as a typed rejection (exit 3) so it lines up with the
//!       other tiers' runtime lone-surrogate rejection.
//!   {"mode":"deep","depth":<int>,"shape":"array"|"object"}
//!       Build `depth` nested containers around the integer leaf 1, NATIVELY.
//!   {"mode":"bigstring","bytes":<int>,"where":"value"|"key"}
//!       Build a one-entry object whose value (or key) is `bytes` ASCII 'a',
//!       NATIVELY, and respond with the SHA-256 of the canonical bytes.
//!
//!   Why `deep` / `bigstring` describe the value instead of carrying it, and
//!   why it matters MOST in this tier: serde_json caps deserialization at 128
//!   nested containers and that cap is NOT configurable at the default feature
//!   set. Sent as a JSON request, any case deeper than ~126 died here with
//!   "parse request: recursion limit exceeded" on stderr, exit 1, never
//!   reaching canonical_json — so the transport was enforcing a limit an order
//!   of magnitude below the one under test, and the resulting failure was easy
//!   to misread as this tier's guard firing. It has no depth guard.
//!   Building the value natively sidesteps the request parser entirely.
//!
//!   On a typed rejection the shim prints "RUNAR_CANON_ERR:<message>" to
//!   stdout and exits 3; any other failure exits 1.
//!
//! Run via: `cargo run --quiet --example canonicalise`

use std::io::Read;

use runar_lang::sdk::canonical_json;
use serde_json::Value;
use sha2::{Digest, Sha256};

const DIGEST_PREFIX: &str = "RUNAR_CANON_SHA256:";

/// Nest `depth` containers around the integer leaf 1, iteratively.
fn build_deep(depth: u64, shape: &str) -> Value {
    let mut v = Value::from(1i64);
    for _ in 0..depth {
        v = if shape == "array" {
            Value::Array(vec![v])
        } else {
            let mut m = serde_json::Map::new();
            m.insert("k".to_string(), v);
            Value::Object(m)
        };
    }
    v
}

/// One-entry object whose value (or key) is `n` ASCII 'a'.
fn build_big_string(n: usize, where_: &str) -> Value {
    let s = "a".repeat(n);
    let mut m = serde_json::Map::new();
    if where_ == "value" {
        m.insert("s".to_string(), Value::String(s));
    } else {
        m.insert(s, Value::from(1i64));
    }
    Value::Object(m)
}

fn main() {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        eprintln!("read stdin");
        std::process::exit(1);
    }

    let req: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parse request: {e}");
            std::process::exit(1);
        }
    };

    let mode = req.get("mode").and_then(|m| m.as_str()).unwrap_or("");
    let input: Value = match mode {
        "json" => req.get("value").cloned().unwrap_or(Value::Null),
        "utf16" => {
            let key = req
                .get("key")
                .and_then(|k| k.as_str())
                .unwrap_or("")
                .to_string();
            let units: Vec<u32> = req
                .get("units")
                .and_then(|u| u.as_array())
                .map(|arr| arr.iter().filter_map(|n| n.as_u64().map(|x| x as u32)).collect())
                .unwrap_or_default();
            match utf16_units_to_string(&units) {
                Ok(s) => {
                    let mut obj = serde_json::Map::new();
                    obj.insert(key, Value::String(s));
                    Value::Object(obj)
                }
                Err(msg) => {
                    // Lone surrogate: Rust rejects structurally at the String
                    // type boundary, before canonical_json is even called.
                    print!("RUNAR_CANON_ERR:{msg}");
                    std::process::exit(3);
                }
            }
        }
        "deep" => build_deep(
            req.get("depth").and_then(|d| d.as_u64()).unwrap_or(0),
            req.get("shape").and_then(|s| s.as_str()).unwrap_or("array"),
        ),
        "bigstring" => build_big_string(
            req.get("bytes").and_then(|b| b.as_u64()).unwrap_or(0) as usize,
            req.get("where").and_then(|w| w.as_str()).unwrap_or("value"),
        ),
        _ => {
            eprintln!("unknown mode {mode:?}");
            std::process::exit(1);
        }
    };

    match canonical_json(&input) {
        Ok(s) => {
            if mode == "bigstring" {
                print!("{DIGEST_PREFIX}{:x}", Sha256::digest(s.as_bytes()));
            } else {
                print!("{s}");
            }
        }
        Err(e) => {
            print!("RUNAR_CANON_ERR:{e}");
            std::process::exit(3);
        }
    }
}

/// Decode UTF-16 code units to a Rust `String`. Returns Err on any lone
/// surrogate (which a Rust `String` cannot represent).
fn utf16_units_to_string(units: &[u32]) -> Result<String, String> {
    let u16s: Vec<u16> = units.iter().map(|&u| u as u16).collect();
    char::decode_utf16(u16s.iter().copied())
        .map(|r| r.map_err(|e| format!("canonical JSON: lone surrogate U+{:04X}", e.unpaired_surrogate())))
        .collect()
}
