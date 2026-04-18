//! Baby Bear field arithmetic integration tests -- inline contracts testing
//! bbFieldAdd/bbFieldInv on a real regtest node.
//!
//! Each test compiles a minimal stateless contract that exercises Baby Bear
//! built-ins, deploys it on regtest, and verifies the deployment + call succeed.
//!
//! **Gating**: all on-chain tests are gated with
//! `#[cfg_attr(not(feature = "regtest"), ignore)]`. They require a local Bitcoin
//! regtest node (see `integration/rust/README.md`). Run with:
//!     cargo test --features regtest
//! Tests without the gate (pure compile/script-size checks) run by default.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

/// Baby Bear prime: p = 2013265921
const BB_P: i64 = 2013265921;

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_bb_field_add_deploy() {
    skip_if_no_node();

    let source = r#"
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddTest extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
"#;
    let artifact = compile_source(source, "BBAddTest.runar.ts");
    assert_eq!(artifact.contract_name, "BBAddTest");

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(10)]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("verify", &[SdkValue::Int(3), SdkValue::Int(7)], &mut provider, &*signer, None)
        .expect("call verify failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_bb_field_add_wrap_around() {
    skip_if_no_node();

    let source = r#"
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddWrap extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
"#;
    let artifact = compile_source(source, "BBAddWrap.runar.ts");

    // (p-1) + 1 = 0 mod p
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("verify", &[SdkValue::Int(BB_P - 1), SdkValue::Int(1)], &mut provider, &*signer, None)
        .expect("call verify failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_bb_field_inv_identity() {
    skip_if_no_node();

    let source = r#"
import { SmartContract, assert, bbFieldInv, bbFieldMul } from 'runar-lang';

class BBInvIdentity extends SmartContract {
  constructor() { super(); }
  public verify(a: bigint) {
    const inv = bbFieldInv(a);
    assert(bbFieldMul(a, inv) === 1n);
  }
}
"#;
    let artifact = compile_source(source, "BBInvIdentity.runar.ts");
    assert_eq!(artifact.contract_name, "BBInvIdentity");

    let mut contract = RunarContract::new(artifact, vec![]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 500000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("verify", &[SdkValue::Int(42)], &mut provider, &*signer, None)
        .expect("call verify failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_bb_field_add_wrong_result_rejected() {
    skip_if_no_node();

    let source = r#"
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddReject extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
"#;
    let artifact = compile_source(source, "BBAddReject.runar.ts");

    // Wrong expected: 3+7=10, not 11
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(11)]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let result = contract
        .call("verify", &[SdkValue::Int(3), SdkValue::Int(7)], &mut provider, &*signer, None);
    assert!(result.is_err(), "expected wrong add result to be rejected on-chain");
}
