//! SHA-256 compress integration test — sha256Compress(state, block) primitive.
//!
//! Mirrors `integration/ts/sha256-compress.test.ts`. Verifies:
//!   - The compiled artifact has a non-trivial script size (SHA-256 compress
//!     is several KB once inlined).
//!   - Deploy succeeds on regtest under the `regtest` feature.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

#[test]
fn test_sha256_compress_compile() {
    let artifact = compile_contract(
        "examples/ts/sha256-compress/Sha256CompressTest.runar.ts",
    );
    assert_eq!(artifact.contract_name, "Sha256CompressTest");
    assert!(!artifact.script.is_empty());
}

#[test]
fn test_sha256_compress_script_size() {
    let artifact = compile_contract(
        "examples/ts/sha256-compress/Sha256CompressTest.runar.ts",
    );
    let script_bytes = artifact.script.len() / 2;
    // SHA-256 compress is ~5 KB once inlined.
    assert!(
        script_bytes > 1_000,
        "sha256-compress script too small: {} bytes",
        script_bytes
    );
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_sha256_compress_deploy() {
    skip_if_no_node();

    let artifact = compile_contract(
        "examples/ts/sha256-compress/Sha256CompressTest.runar.ts",
    );

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // The contract takes the expected state digest. Use a placeholder; the
    // regtest test exercises deploy success only.
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
        .expect("sha256-compress deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}
