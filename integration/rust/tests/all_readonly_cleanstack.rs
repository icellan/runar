//! AllReadonlyCleanstack integration test — issue #44 / parentClass pipeline.
//!
//! ## What this proves
//!
//! `AllReadonlyCleanstack` is a `StatefulSmartContract` with ZERO mutable
//! fields (only a `readonly owner`). Its `claim(sig)` method is terminal: the
//! contract is fully spent, the user `checkSig` runs AFTER the auto-injected
//! `checkPreimage` / OP_CODESEPARATOR.
//!
//! Before the parentClass fix, the SDK derived `is_stateful` purely from
//! non-empty `state_fields`. With zero mutable fields, `state_fields` is empty,
//! so the SDK mistook the contract for stateless and SKIPPED the issue-#42/#44
//! terminal sighash subscript trim. The user `sig` was then signed over the
//! FULL locking script instead of the codesep-trimmed subscript, so the spend
//! NULLFAILed on a strict node (`acceptnonstdtxn=0`).
//!
//! The fix carries `parentClass` in the artifact and gates the trim on
//! `parent_class == "StatefulSmartContract"`. This test deploys the contract
//! and spends its terminal `claim()`, asserting the spend is ACCEPTED.
//!
//! `claim(sig)` has the `sig` user param plus the compiler-injected
//! `txPreimage` (SigHashPreimage). A zero-mutable-field stateful contract has
//! `is_stateful == false`, so the SDK does NOT strip `txPreimage` from the
//! user-facing params — hence the call passes two `Auto` args (sig, txPreimage).
//!
//! **Gating**: the on-chain test is gated with
//! `#[cfg_attr(not(feature = "regtest"), ignore)]`. It requires a local Bitcoin
//! regtest node (see `integration/rust/README.md`). Run with:
//!     cargo test --features regtest

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

const SOURCE: &str = "examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts";

#[test]
fn test_all_readonly_cleanstack_compile() {
    let artifact = compile_contract(SOURCE);
    assert_eq!(artifact.contract_name, "AllReadonlyCleanstack");
    // parentClass must be carried so the SDK can gate the terminal trim even
    // though there are no mutable state fields.
    assert_eq!(
        artifact.parent_class.as_deref(),
        Some("StatefulSmartContract"),
        "artifact must carry parentClass=StatefulSmartContract"
    );
    assert!(
        artifact.state_fields.as_ref().map_or(true, |f| f.is_empty()),
        "AllReadonlyCleanstack has zero mutable state fields"
    );
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_all_readonly_cleanstack_claim_accepted() {
    skip_if_no_node();

    let artifact = compile_contract(SOURCE);
    let mut provider = create_provider();
    // The funded wallet's pubkey IS the contract owner, so checkSig passes.
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);

    // Constructor: (owner: PubKey)
    let mut contract = RunarContract::new(
        artifact,
        vec![SdkValue::Bytes(owner_wallet.pub_key_hex.clone())],
    );

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Terminal claim(sig). Two Auto args: the declared `sig` plus the
    // compiler-injected `txPreimage` (not stripped for a zero-mutable-field
    // stateful contract). Before the parentClass fix this NULLFAILed under
    // strict policy; it MUST now be accepted.
    let (claim_txid, _tx) = contract
        .call(
            "claim",
            &[SdkValue::Auto, SdkValue::Auto],
            &mut provider,
            &*signer,
            None,
        )
        .expect("claim spend must be accepted by a strict node");
    assert!(!claim_txid.is_empty());
    assert_eq!(claim_txid.len(), 64, "expected a 64-hex-char txid");
}
