//! R-062 — the unsound-primitive deploy gate must cover the WALLET funding path.
//!
//! `RunarContract::deploy` refuses to fund an artifact the compiler marked
//! unsound unless the caller names every listed primitive, and it bounds the
//! script size first. `deploy_with_wallet` is a SECOND funding path — a BRC-100
//! wallet creates and funds the transaction via `create_action` — and it ran
//! NEITHER guard.
//!
//! Structurally, this tier could not run the gate: `deploy_with_wallet` took a
//! bare `locking_script: &str` plus a `contract_name: &str` and never saw the
//! artifact, so it had nothing to read `unsound_primitives` from. The fix
//! threads the artifact through — the signature change this test pins.
//!
//! Three cases per guard, because over-rejection here breaks every legitimate
//! wallet deploy: the refusal, an ordinary artifact, and an acknowledged
//! unsound one.

use std::cell::RefCell;

use runar_lang::sdk::{
    deploy_with_wallet, DeployWithWalletOptions, WalletActionOutput, WalletActionResult,
    WalletClient, WalletOutput, MAX_SCRIPT_BYTES,
};
use runar_lang::sdk::types::{Abi, AbiConstructor, RunarArtifact};

/// Records every `create_action` reached — proof the guards ran BEFORE it.
struct RecordingWallet {
    actions: RefCell<Vec<String>>,
}

impl RecordingWallet {
    fn new() -> Self {
        RecordingWallet { actions: RefCell::new(Vec::new()) }
    }
}

impl WalletClient for RecordingWallet {
    fn get_public_key(&self, _p: &(u32, &str), _k: &str) -> Result<String, String> {
        Ok("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string())
    }
    fn create_signature(&self, _h: &[u8], _p: &(u32, &str), _k: &str) -> Result<Vec<u8>, String> {
        Ok(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
    }
    fn create_action(
        &self,
        description: &str,
        _outputs: &[WalletActionOutput],
    ) -> Result<WalletActionResult, String> {
        self.actions.borrow_mut().push(description.to_string());
        Ok(WalletActionResult { txid: "ab".repeat(32), tx: None })
    }
    fn list_outputs(&self, _b: &str, _t: &[&str], _l: usize) -> Result<Vec<WalletOutput>, String> {
        Ok(vec![])
    }
}

fn artifact(script: &str, unsound: Option<Vec<String>>) -> RunarArtifact {
    RunarArtifact {
        version: "runar-v1.0.0-rc.1".to_string(),
        contract_name: "Sp1Rollup".to_string(),
        parent_class: None,
        abi: Abi { constructor: AbiConstructor { params: vec![] }, methods: vec![] },
        script: script.to_string(),
        asm: None,
        state_fields: None,
        constructor_slots: None,
        code_sep_index_slots: None,
        code_separator_index: None,
        code_separator_indices: None,
        anf: None,
        unsound_primitives: unsound,
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn refuses_unacknowledged_unsound_artifact() {
    let wallet = RecordingWallet::new();
    let art = artifact("51", Some(s(&["verifySP1FRI"])));
    let err = deploy_with_wallet(&wallet, "my-basket", "51", &art, None).unwrap_err();

    assert!(err.contains("verifySP1FRI"), "{err}");
    assert!(err.contains("Sp1Rollup.deploy_with_wallet"), "{err}");
    assert!(err.contains("acknowledge_unsound"), "{err}");
    assert!(
        wallet.actions.borrow().is_empty(),
        "the wallet was asked for coins before the gate ran",
    );
}

#[test]
fn control_ordinary_artifact_still_funds() {
    let wallet = RecordingWallet::new();
    let art = artifact("51", None);
    let (txid, output_index) =
        deploy_with_wallet(&wallet, "my-basket", "51", &art, None).unwrap();

    assert_eq!(txid, "ab".repeat(32));
    assert_eq!(output_index, 0);
    assert_eq!(wallet.actions.borrow().len(), 1);
}

#[test]
fn control_acknowledged_unsound_artifact_still_funds() {
    let wallet = RecordingWallet::new();
    let art = artifact("51", Some(s(&["verifySP1FRI"])));
    let opts = DeployWithWalletOptions {
        satoshis: Some(1),
        description: None,
        acknowledge_unsound: s(&["verifySP1FRI"]),
    };
    let (txid, _) = deploy_with_wallet(&wallet, "my-basket", "51", &art, Some(&opts)).unwrap();

    assert_eq!(txid, "ab".repeat(32));
    assert_eq!(wallet.actions.borrow().len(), 1);
}

#[test]
fn partial_acknowledgement_is_still_a_refusal() {
    let wallet = RecordingWallet::new();
    let art = artifact("51", Some(s(&["verifySP1FRI", "someFutureStub"])));
    let opts = DeployWithWalletOptions {
        satoshis: Some(1),
        description: None,
        acknowledge_unsound: s(&["verifySP1FRI"]),
    };
    let err = deploy_with_wallet(&wallet, "my-basket", "51", &art, Some(&opts)).unwrap_err();

    assert!(err.contains("someFutureStub"), "{err}");
    assert!(wallet.actions.borrow().is_empty());
}

/// R-062 sibling: the wallet path skipped the DoS script-size bound `deploy`
/// runs. A pathological locking script reached the wallet unchecked.
#[test]
fn refuses_oversize_script() {
    let wallet = RecordingWallet::new();
    let oversize = "51".repeat(MAX_SCRIPT_BYTES + 1);
    let art = artifact(&oversize, None);
    let err = deploy_with_wallet(&wallet, "my-basket", &oversize, &art, None).unwrap_err();

    assert!(err.contains("MAX_SCRIPT_BYTES"), "{err}");
    assert!(err.contains("Sp1Rollup.deploy_with_wallet"), "{err}");
    assert!(wallet.actions.borrow().is_empty());
}

/// CONTROL for the size bound: a script exactly at the limit still funds.
#[test]
fn control_script_at_limit_still_funds() {
    let wallet = RecordingWallet::new();
    let at_limit = "51".repeat(MAX_SCRIPT_BYTES);
    let art = artifact(&at_limit, None);
    let (txid, _) = deploy_with_wallet(&wallet, "my-basket", &at_limit, &art, None).unwrap();

    assert_eq!(txid, "ab".repeat(32));
    assert_eq!(wallet.actions.borrow().len(), 1);
}
