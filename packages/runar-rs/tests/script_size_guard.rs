//! Item 8 — ScriptSizeExceededError at SDK entry points (Rust).
//!
//! Verifies that deploy/call/provider entry points reject scripts that
//! exceed MAX_SCRIPT_BYTES with a typed ScriptSizeExceededError BEFORE
//! any signing / broadcast work happens.

use runar_lang::sdk::{
    Provider, MockProvider, MockSigner, RunarContract,
    ScriptSizeExceededError, MAX_SCRIPT_BYTES,
    Utxo, DeployOptions,
};
use runar_lang::sdk::types::{RunarArtifact, Abi, AbiConstructor, AbiMethod};

fn oversized_script_hex() -> String {
    "51".repeat(MAX_SCRIPT_BYTES + 1)
}

fn at_limit_script_hex() -> String {
    "51".repeat(MAX_SCRIPT_BYTES)
}

fn make_artifact(script: &str, contract_name: &str, methods: Vec<AbiMethod>) -> RunarArtifact {
    RunarArtifact {
        version: "runar-v0.1.0".to_string(),
        contract_name: contract_name.to_string(),
        abi: Abi {
            constructor: AbiConstructor { params: vec![] },
            methods,
        },
        script: script.to_string(),
        state_fields: None,
        constructor_slots: None,
        code_sep_index_slots: None,
        code_separator_index: None,
        code_separator_indices: None,
        anf: None,
    }
}

#[test]
fn deploy_rejects_oversized_script() {
    let artifact = make_artifact(&oversized_script_hex(), "OversizedContract", vec![]);
    let mut contract = RunarContract::new(artifact, vec![]);
    let mut provider = MockProvider::testnet();
    let mock_addr = "0".repeat(20);
    let signer = MockSigner::new();
    let _ = &mock_addr;
    provider.add_utxo(&mock_addr, Utxo {
        txid: "a".repeat(64),
        output_index: 0,
        satoshis: 100_000,
        script: format!("76a914{}88ac", "0".repeat(40)),
    });

    let result = contract.deploy(&mut provider, &signer, &DeployOptions {
        satoshis: 1000,
        change_address: None,
    });
    let err = result.expect_err("expected ScriptSizeExceededError");
    assert!(err.contains("OversizedContract.deploy"), "context missing: {}", err);
    assert!(err.contains(&format!("limit={}", MAX_SCRIPT_BYTES)), "limit missing: {}", err);
    assert!(err.contains(&format!("actual={}", MAX_SCRIPT_BYTES + 1)), "actual missing: {}", err);

    // No broadcast should have occurred.
    assert_eq!(provider.get_broadcasted_txs().len(), 0);
}

#[test]
fn call_rejects_oversized_current_utxo_script() {
    // Use from_utxo() to simulate a reconnect with a poisoned (oversized)
    // locking script. This avoids needing to actually deploy first.
    let artifact = make_artifact("51", "OversizedContract", vec![AbiMethod {
        name: "spend".to_string(),
        params: vec![],
        is_public: true,
        is_terminal: None,
    }]);
    let utxo = Utxo {
        txid: "a".repeat(64),
        output_index: 0,
        satoshis: 50_000,
        script: oversized_script_hex(),
    };
    let mut contract = RunarContract::from_utxo(artifact, &utxo);

    let mut provider = MockProvider::testnet();
    let mock_addr = "0".repeat(20);
    let signer = MockSigner::new();
    let _ = &mock_addr;
    provider.add_utxo(&mock_addr, Utxo {
        txid: "b".repeat(64),
        output_index: 0,
        satoshis: 100_000,
        script: format!("76a914{}88ac", "0".repeat(40)),
    });

    let result = contract.call("spend", &[], &mut provider, &signer, None);
    let err = result.expect_err("expected ScriptSizeExceededError");
    assert!(err.contains("OversizedContract.call(spend)"), "context missing: {}", err);
    assert!(err.contains(&format!("limit={}", MAX_SCRIPT_BYTES)));
    assert!(err.contains(&format!("actual={}", MAX_SCRIPT_BYTES + 1)));

    // No broadcast should have happened — guard fires BEFORE signing/broadcast.
    assert_eq!(provider.get_broadcasted_txs().len(), 0);
}

#[test]
fn mock_provider_get_utxos_rejects_oversized_script() {
    let mut provider = MockProvider::testnet();
    provider.add_utxo("addr", Utxo {
        txid: "b".repeat(64),
        output_index: 0,
        satoshis: 1000,
        script: oversized_script_hex(),
    });
    let err = provider.get_utxos("addr").expect_err("expected ScriptSizeExceededError");
    assert!(err.contains("MockProvider.get_utxos"), "context missing: {}", err);
    assert!(err.contains(&format!("limit={}", MAX_SCRIPT_BYTES)));
    assert!(err.contains(&format!("actual={}", MAX_SCRIPT_BYTES + 1)));
}

#[test]
fn mock_provider_get_contract_utxo_rejects_oversized_script() {
    let mut provider = MockProvider::testnet();
    provider.add_contract_utxo("script-hash", Utxo {
        txid: "c".repeat(64),
        output_index: 0,
        satoshis: 1000,
        script: oversized_script_hex(),
    });
    let err = provider.get_contract_utxo("script-hash").expect_err("expected error");
    assert!(err.contains("MockProvider.get_contract_utxo"), "context missing: {}", err);
}

#[test]
fn at_limit_script_passes_provider_guard() {
    let mut provider = MockProvider::testnet();
    provider.add_utxo("addr", Utxo {
        txid: "d".repeat(64),
        output_index: 0,
        satoshis: 1000,
        script: at_limit_script_hex(),
    });
    let utxos = provider.get_utxos("addr").expect("expected at-limit script to pass");
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].script.len(), MAX_SCRIPT_BYTES * 2);
}

#[test]
fn typed_error_can_be_downcast() {
    let err = ScriptSizeExceededError {
        limit: MAX_SCRIPT_BYTES,
        actual: MAX_SCRIPT_BYTES + 1,
        context: "demo".to_string(),
    };
    let message: String = err.clone().into();
    assert!(message.contains(&format!("limit={}", MAX_SCRIPT_BYTES)));
    assert!(message.contains(&format!("actual={}", MAX_SCRIPT_BYTES + 1)));
    assert!(message.contains("demo"));
    assert_eq!(err.limit, MAX_SCRIPT_BYTES);
    assert_eq!(err.actual, MAX_SCRIPT_BYTES + 1);
}
