//! N-076: `TokenWallet::get_utxos` must discover a deployed token contract with
//! the slot-aware matcher (`matches_artifact`), not a raw prefix of the
//! template. The template carries a constructor slot, a codeSepIndex slot
//! (baked as OP_1) and a `codePartLenSlots` field (the deployed code-part
//! length), none of which a literal prefix of the template can equal.
//!
//! Proves: a deployed instance of such a template (with a state section) is
//! found, while scripts that share the pre-slot prefix but differ after it,
//! carry a wrong code-part length, or are unrelated are not.
//! Does NOT prove: on-chain spendability of the matched UTXO, nor that an
//! artifact with only codeSepIndex slots (no constructor slots) is matched --
//! `matches_artifact` itself compares such a template literally.

use runar_lang::sdk::provider::MockProvider;
use runar_lang::sdk::signer::MockSigner;
use runar_lang::sdk::types::{RunarArtifact, Utxo};
use runar_lang::sdk::{Signer, TokenWallet};

// bytes: 76 a9 [00] 88 [00] 75 04 [00000000] ac
//   ctor slot @2, codeSepIndex slot @4, codePartLen field @7
fn artifact() -> RunarArtifact {
    serde_json::from_value(serde_json::json!({
        "version": "runar-v0.1.0",
        "contractName": "FungibleToken",
        "abi": {
            "constructor": { "params": [{ "name": "supply", "type": "bigint" }] },
            "methods": []
        },
        "script": "76a9008800750400000000ac",
        "stateFields": [{ "name": "balance", "type": "bigint", "index": 1 }],
        "constructorSlots": [{ "paramIndex": 0, "byteOffset": 2 }],
        "codeSepIndexSlots": [{ "byteOffset": 4, "codeSepIndex": 0 }],
        "codePartLenSlots": [{ "byteOffset": 7 }]
    }))
    .unwrap()
}

// supply = 02aabb, codeSepIndex baked as OP_1, code part is 14 bytes.
fn deployed(tail: &str, len: &str) -> String {
    format!("76a902aabb88517504{len}{tail}6a0100")
}

fn discover(scripts: &[String]) -> Vec<String> {
    let mut provider = MockProvider::testnet();
    let signer = MockSigner::new();
    let addr = signer.get_address().unwrap();
    for (i, s) in scripts.iter().enumerate() {
        provider.add_utxo(&addr, Utxo {
            txid: format!("{:x}", i).repeat(64),
            output_index: 0,
            satoshis: 1000,
            script: s.clone(),
        });
    }
    let wallet = TokenWallet::new(artifact(), Box::new(provider), Box::new(signer));
    wallet.get_utxos().unwrap().into_iter().map(|u| u.txid[..1].to_string()).collect()
}

#[test]
fn finds_a_deployed_slotted_instance() {
    assert_eq!(discover(&[deployed("ac", "0e000000")]), vec!["0"]);
}

#[test]
fn rejects_scripts_that_only_share_the_prefix() {
    assert!(discover(&[deployed("ad", "0e000000")]).is_empty(), "differs after the slots");
    assert!(discover(&[deployed("ac", "0f000000")]).is_empty(), "wrong code-part length");
    assert!(
        discover(&[format!("76a914{}88ac", "11".repeat(20))]).is_empty(),
        "unrelated script"
    );
}
