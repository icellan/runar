//! SHA-256 finalize integration test — sha256Finalize(state, remaining,
//! msgBitLen) primitive.
//!
//! Mirrors `integration/ts/sha256-finalize.test.ts`. Verifies:
//!   - The compiled artifact has a non-trivial script size.
//!   - Deploy succeeds on regtest under the `regtest` feature.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

#[test]
fn test_sha256_finalize_compile() {
    let artifact = compile_contract(
        "examples/ts/sha256-finalize/Sha256FinalizeTest.runar.ts",
    );
    assert_eq!(artifact.contract_name, "Sha256FinalizeTest");
    assert!(!artifact.script.is_empty());
}

#[test]
fn test_sha256_finalize_script_size() {
    let artifact = compile_contract(
        "examples/ts/sha256-finalize/Sha256FinalizeTest.runar.ts",
    );
    let script_bytes = artifact.script.len() / 2;
    assert!(
        script_bytes > 1_000,
        "sha256-finalize script too small: {} bytes",
        script_bytes
    );
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_sha256_finalize_deploy() {
    skip_if_no_node();

    let artifact = compile_contract(
        "examples/ts/sha256-finalize/Sha256FinalizeTest.runar.ts",
    );

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let expected = "00".repeat(32);
    let mut contract = RunarContract::new(
        artifact,
        vec![SdkValue::Bytes(expected)],
    );

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        })
        .expect("sha256-finalize deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}
