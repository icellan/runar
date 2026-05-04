//! Live BRC-100 WalletClient round-trip integration test.
//!
//! Mirrors `integration/ruby/spec/wallet_client_spec.rb`. Environment-gated:
//! runs only when `RUNAR_WALLET_ENDPOINT` is set to the base URL of a
//! BRC-100 JSON-over-HTTP wallet endpoint. When unset, the test exits
//! cleanly so local + CI runs stay green without any wallet setup.
//!
//! Optional env:
//!   RUNAR_WALLET_ENDPOINT — base URL, required to actually run
//!   RUNAR_WALLET_AUTH     — bearer token, optional
//!   RUNAR_WALLET_BASKET   — basket name, default "runar-integration-test"
//!
//! Asserts:
//!   * getPublicKey returns a 33-byte compressed pubkey (66 hex chars,
//!     prefix 02/03).
//!   * listOutputs returns an array; each entry (if any) exposes at least
//!     one of outpoint / satoshis / lockingScript.

use serde_json::{json, Value};

const TIMEOUT_SECS: u64 = 30;

fn endpoint() -> Option<String> {
    std::env::var("RUNAR_WALLET_ENDPOINT").ok().filter(|s| !s.is_empty())
}

fn post(base: &str, method: &str, body: Value, auth: Option<&str>) -> Result<Value, String> {
    let url = format!("{}/{}", base.trim_end_matches('/'), method);
    let mut req = ureq::post(&url)
        .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
        .set("Content-Type", "application/json");
    if let Some(token) = auth {
        req = req.set("Authorization", &format!("Bearer {token}"));
    }
    let resp = req
        .send_string(&body.to_string())
        .map_err(|e| format!("wallet {method} request failed: {e}"))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("wallet {method} read failed: {e}"))?;
    serde_json::from_str::<Value>(&text)
        .map_err(|e| format!("wallet {method} parse failed: {e}; body={text}"))
}

#[test]
fn wallet_client_live_round_trip() {
    let Some(base) = endpoint() else {
        eprintln!(
            "RUNAR_WALLET_ENDPOINT not set — skipping live BRC-100 wallet round-trip. \
             Set RUNAR_WALLET_ENDPOINT to a BRC-100 wallet URL to enable."
        );
        return;
    };

    let auth = std::env::var("RUNAR_WALLET_AUTH").ok();
    let basket = std::env::var("RUNAR_WALLET_BASKET")
        .unwrap_or_else(|_| "runar-integration-test".to_string());

    // 1. getPublicKey: must return a 33-byte compressed secp256k1 key.
    let resp = post(
        &base,
        "getPublicKey",
        json!({
            "protocolID": [2, "runar integration"],
            "keyID": "1",
        }),
        auth.as_deref(),
    )
    .expect("getPublicKey");
    let pub_key = resp
        .get("publicKey")
        .or_else(|| resp.get("publicKeyHex"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("getPublicKey: missing publicKey in response: {resp}"))
        .to_string();
    assert_eq!(
        pub_key.len(),
        66,
        "getPublicKey: expected 66 hex chars, got {} ({pub_key})",
        pub_key.len()
    );
    let prefix = &pub_key[..2];
    assert!(
        prefix == "02" || prefix == "03",
        "getPublicKey: expected compressed prefix 02/03, got {prefix}"
    );
    assert!(
        pub_key.chars().all(|c| c.is_ascii_hexdigit()),
        "getPublicKey: not hex: {pub_key}"
    );

    // 2. listOutputs: must return an array (possibly empty).
    let resp = post(
        &base,
        "listOutputs",
        json!({
            "basket": basket,
            "tags": Vec::<String>::new(),
            "limit": 10,
        }),
        auth.as_deref(),
    )
    .expect("listOutputs");
    let outputs = resp
        .get("outputs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for (i, out) in outputs.iter().enumerate() {
        let obj = out.as_object().unwrap_or_else(|| {
            panic!("listOutputs[{i}]: expected object, got {out}")
        });
        let has_field = obj.contains_key("outpoint")
            || obj.contains_key("satoshis")
            || obj.contains_key("lockingScript");
        assert!(
            has_field,
            "listOutputs[{i}]: missing canonical outpoint/satoshis/lockingScript: {out}"
        );
    }
}
