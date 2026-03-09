//! ConvergenceProof integration test — stateless contract using EC point operations.
//!
//! The contract verifies that R_A - R_B = deltaO * G on secp256k1.
//! We verify compile, deploy, and spend (valid + invalid deltaO).

use crate::helpers::*;
use crate::helpers::crypto::ec_mul_gen_point;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

#[test]
#[ignore]
fn test_convergence_proof_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/convergence-proof/ConvergenceProof.runar.ts");
    assert_eq!(artifact.contract_name, "ConvergenceProof");
}

#[test]
#[ignore]
fn test_convergence_proof_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/convergence-proof/ConvergenceProof.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // R_A = 12345*G, R_B = 6789*G
    let r_a = ec_mul_gen_point(12345);
    let r_b = ec_mul_gen_point(6789);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(r_a),
        SdkValue::Bytes(r_b),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}

#[test]
#[ignore]
fn test_convergence_proof_spend_valid() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/convergence-proof/ConvergenceProof.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // a=12345, b=6789, deltaO = a - b
    let a = 12345u64;
    let b = 6789u64;
    let delta_o = (a - b) as i64;

    let r_a = ec_mul_gen_point(a);
    let r_b = ec_mul_gen_point(b);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(r_a),
        SdkValue::Bytes(r_b),
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    let (spend_txid, _tx) = contract
        .call(
            "proveConvergence",
            &[SdkValue::Int(delta_o)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("call proveConvergence failed");
    assert!(!spend_txid.is_empty());
    assert_eq!(spend_txid.len(), 64);
}

#[test]
#[ignore]
fn test_convergence_proof_spend_invalid_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/convergence-proof/ConvergenceProof.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let r_a = ec_mul_gen_point(12345);
    let r_b = ec_mul_gen_point(6789);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(r_a),
        SdkValue::Bytes(r_b),
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Wrong deltaO — should be rejected
    let result = contract.call(
        "proveConvergence",
        &[SdkValue::Int(42)],
        &mut provider,
        &*signer,
        None,
    );
    assert!(result.is_err(), "expected call with wrong delta to be rejected");
}
