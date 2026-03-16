//! MathDemo integration test — stateful contract exercising built-in math functions.

use crate::helpers::*;
use runar_lang::sdk::{CallOptions, DeployOptions, RunarContract, SdkValue};
use std::collections::HashMap;

fn wrong_state(value: i64) -> Option<CallOptions> {
    let mut state = HashMap::new();
    state.insert("value".to_string(), SdkValue::Int(value));
    Some(CallOptions {
        new_state: Some(state),
        ..Default::default()
    })
}

#[test]
#[ignore]
fn test_math_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(1000)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!txid.is_empty());
}

#[test]
#[ignore]
fn test_math_divide_by() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(1000)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // 1000 / 10 = 100
    let (txid, _tx) = contract
        .call(
            "divideBy",
            &[SdkValue::Int(10)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("divideBy failed");
    assert!(!txid.is_empty());
}

#[test]
#[ignore]
fn test_math_divide_then_clamp() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(1000)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // 1000 / 10 = 100
    contract
        .call(
            "divideBy",
            &[SdkValue::Int(10)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("divideBy failed");

    // clamp(0, 50) = 50
    contract
        .call(
            "clampValue",
            &[SdkValue::Int(0), SdkValue::Int(50)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("clampValue failed");
}

#[test]
#[ignore]
fn test_math_square_root() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(49)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // sqrt(49) = 7
    let (txid, _tx) = contract
        .call(
            "squareRoot",
            &[],
            &mut provider,
            &*signer,
            None,
        )
        .expect("squareRoot failed");
    assert!(!txid.is_empty());
}

#[test]
#[ignore]
fn test_math_exponentiate() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(2)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // 2^10 = 1024
    let (txid, _tx) = contract
        .call(
            "exponentiate",
            &[SdkValue::Int(10)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("exponentiate failed");
    assert!(!txid.is_empty());
}

#[test]
#[ignore]
fn test_math_reduce_gcd() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(100)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // gcd(100, 75) = 25
    let (txid, _tx) = contract
        .call(
            "reduceGcd",
            &[SdkValue::Int(75)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("reduceGcd failed");
    assert!(!txid.is_empty());
}

#[test]
#[ignore]
fn test_math_compute_log2() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(1024)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // log2(1024) = 10
    let (txid, _tx) = contract
        .call(
            "computeLog2",
            &[],
            &mut provider,
            &*signer,
            None,
        )
        .expect("computeLog2 failed");
    assert!(!txid.is_empty());
}

#[test]
#[ignore]
fn test_math_scale_by_ratio() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(100)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // 100 * 3 / 4 = 75
    let (txid, _tx) = contract
        .call(
            "scaleByRatio",
            &[SdkValue::Int(3), SdkValue::Int(4)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("scaleByRatio failed");
    assert!(!txid.is_empty());
}

#[test]
#[ignore]
fn test_math_divide_by_zero() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(1000)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    let result = contract.call(
        "divideBy",
        &[SdkValue::Int(0)],
        &mut provider,
        &*signer,
        wrong_state(0).as_ref(),
    );
    assert!(result.is_err(), "expected divide by zero to fail");
}

#[test]
#[ignore]
fn test_math_wrong_state() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(1000)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Claim value=999 instead of 100
    let result = contract.call(
        "divideBy",
        &[SdkValue::Int(10)],
        &mut provider,
        &*signer,
        wrong_state(999).as_ref(),
    );
    assert!(result.is_err(), "expected wrong state to fail");
}

#[test]
#[ignore]
fn test_math_normalize() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(-42)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // normalize: sign(-42) = -1
    let (txid, _tx) = contract
        .call(
            "normalize",
            &[],
            &mut provider,
            &*signer,
            None,
        )
        .expect("normalize failed");
    assert!(!txid.is_empty());
}

#[test]
#[ignore]
fn test_math_chain_operations() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(1000)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // 1000 / 10 = 100
    contract
        .call(
            "divideBy",
            &[SdkValue::Int(10)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("divideBy failed");

    // sqrt(100) = 10
    contract
        .call(
            "squareRoot",
            &[],
            &mut provider,
            &*signer,
            None,
        )
        .expect("squareRoot failed");

    // scaleByRatio(5, 1): 10 * 5 / 1 = 50
    contract
        .call(
            "scaleByRatio",
            &[SdkValue::Int(5), SdkValue::Int(1)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("scaleByRatio failed");
}
