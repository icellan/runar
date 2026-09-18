//! Cross-tier BIP-143 sighash interop test (GAP-003).
//!
//! Loads `conformance/sdk-bip143/fixtures.json` (TS reference, generated via
//! @bsv/sdk TransactionSignature.format) and asserts, for every scenario, that
//! this tier's HAND-WRITTEN BIP-143 implementation:
//!
//!   1. recomputes the full preimage byte-identically from (unsignedTxHex,
//!      inputIndex, prevScriptHex, prevValueSats) — the core node-free
//!      cross-tier correctness check;
//!   2. produces sha256d(preimage) == the fixture digestHex; and
//!   3. verifies the TS-produced sigHex against pubkeyHex over that digest.
//!
//! Rust is one of two tiers (with itself + Ruby/Python) that implement BIP-143
//! by hand rather than via an upstream SDK, so it carries the highest
//! divergence risk. Any failure here is a real consensus bug. See CLAUDE.md
//! §"Seven SDKs Must Stay in Sync".

use std::path::PathBuf;

use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use runar_lang::sdk::oppushtx::compute_op_push_tx_with_code_sep_sighash;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../conformance/sdk-bip143/fixtures.json");
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

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

#[test]
fn bip143_preimage_and_signature() {
    let fixture = load_fixture();
    let scenarios = fixture["scenarios"].as_array().expect("scenarios array");
    assert!(!scenarios.is_empty(), "fixture has no scenarios");

    for s in scenarios {
        let name = s["scenario"].as_str().unwrap();
        let tx = s["unsignedTxHex"].as_str().unwrap();
        let idx = s["inputIndex"].as_u64().unwrap() as usize;
        let sub = s["prevScriptHex"].as_str().unwrap();
        let sats = s["prevValueSats"].as_i64().unwrap();
        let want_preimage = s["preimageHex"].as_str().unwrap();
        let want_digest = s["digestHex"].as_str().unwrap();
        let sig_hex = s["sigHex"].as_str().unwrap();
        let pubkey_hex = s["pubkeyHex"].as_str().unwrap();
        let flags = s["sighashFlags"].as_u64().unwrap() as u32;

        // 1. Independently recompute the BIP-143 preimage (hand-written impl)
        //    under the scenario's OWN sighash flags.
        //
        //    R-206: this used to reject anything but 0x41, and every scenario
        //    in the fixture was ALL|FORKID — so the per-mode zeroing rules were
        //    implemented seven times and compared zero times.
        let (_sig, got_preimage) = compute_op_push_tx_with_code_sep_sighash(tx, idx, sub, sats, -1, flags)
            .expect("compute_op_push_tx_with_code_sep_sighash");
        assert_eq!(
            got_preimage, want_preimage,
            "{name}: BIP-143 PREIMAGE DIVERGENCE from TS reference"
        );

        // 2. sha256d(preimage) must equal the published digest.
        let preimage_bytes = hex_to_bytes(&got_preimage);
        let got_digest = to_hex(&sha256d(&preimage_bytes));
        assert_eq!(got_digest, want_digest, "{name}: sighash digest divergence");

        // 3. The TS-produced signature must verify over this tier's digest.
        let der = hex_to_bytes(&sig_hex[..sig_hex.len() - 2]); // strip sighash byte
        let sig = Signature::from_der(&der).expect("parse DER sig");
        let vk = VerifyingKey::from_sec1_bytes(&hex_to_bytes(pubkey_hex)).expect("parse pubkey");
        let digest = sha256d(&preimage_bytes);
        vk.verify_prehash(&digest, &sig).unwrap_or_else(|_| {
            panic!("{name}: TS reference signature does not verify under this tier's digest")
        });
    }
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
