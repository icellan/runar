//! Issue #134 — funding inputs must be signed by `funding_signer`, not the
//! connected method/deploy signer.
//!
//! The deploy() and prepare_call() funding-signing loops signed every P2PKH
//! funding input with the connected signer and pushed that signer's pubkey, so
//! funding coins owned by a different key fail OP_EQUALVERIFY. The fix threads
//! DeployOptions.funding_signer / CallOptions.funding_signer through the funding
//! loops (funding_signer ?? signer), while the method's own Sig args keep the
//! connected signer. Defaults to the connected signer (zero behaviour change).

use std::sync::Arc;

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::{
    DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo,
};
use runar_lang::sdk::types::{
    Abi, AbiConstructor, AbiMethod, FundingSigner, RunarArtifact,
};

const METHOD_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const FUNDING_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000007";

/// A trivial stateless artifact (OP_TRUE) with a single public method.
fn trivial_artifact() -> RunarArtifact {
    RunarArtifact {
        version: "runar-v0.1.0".to_string(),
        contract_name: "Trivial".to_string(),
        parent_class: None,
        abi: Abi {
            constructor: AbiConstructor { params: vec![] },
            methods: vec![AbiMethod {
                name: "spend".to_string(),
                params: vec![],
                is_public: true,
                is_terminal: None,
                uses_code_part: None,
                sig_hash_type: None,
            }],
        },
        script: "51".to_string(),
        asm: None,
        state_fields: None,
        constructor_slots: None,
        code_sep_index_slots: None,
        code_separator_index: None,
        code_separator_indices: None,
        anf: None,
    }
}

/// Extract input 0's scriptSig hex from a raw tx hex.
fn input0_script_sig(tx_hex: &str) -> String {
    let mut off = 8; // skip version (4 bytes)
    let in_count = usize::from_str_radix(&tx_hex[off..off + 2], 16).unwrap();
    assert!(in_count >= 1);
    off += 2;
    off += 64; // prev txid (32 bytes)
    off += 8; // prev index (4 bytes)
    let script_len = usize::from_str_radix(&tx_hex[off..off + 2], 16).unwrap();
    off += 2;
    tx_hex[off..off + script_len * 2].to_string()
}

/// Deploy the trivial contract, funding from a single coin DISCOVERED under
/// the method signer's address but LOCKED to whichever key actually owns it —
/// the real-world shape issue #134 is about. Returns the deploy tx hex.
///
/// The coin's script is NOT irrelevant: the old fixture locked it to a hash
/// nobody holds ("76a914" + "11"*20 + "88ac"), which built an unspendable
/// funding input that only the pre-Phase-A5 always-ack MockProvider accepted.
fn deploy_tx(funding_signer: Option<FundingSigner>) -> (String, String, String) {
    let method_signer = LocalSigner::new(METHOD_KEY).unwrap();
    let funding_ls = LocalSigner::new(FUNDING_KEY).unwrap();
    let method_pub = method_signer.get_public_key().unwrap();
    let funding_pub = funding_ls.get_public_key().unwrap();

    let mut provider = MockProvider::testnet();
    let address = method_signer.get_address().unwrap();
    provider.add_utxo(&address, Utxo {
        txid: "a1".repeat(32),
        output_index: 0,
        satoshis: 100_000,
        script: build_p2pkh_script(if funding_signer.is_some() { &funding_pub } else { &method_pub }),
    });

    let mut contract = RunarContract::new(trivial_artifact(), Vec::<SdkValue>::new());
    contract
        .deploy(&mut provider, &method_signer, &DeployOptions {
            satoshis: 1_000,
            change_address: None,
            funding_signer,
        })
        .unwrap();
    let tx = provider.get_broadcasted_txs()[0].clone();
    (tx, method_pub, funding_pub)
}

#[test]
fn deploy_without_funding_signer_pushes_method_pubkey() {
    let (tx, method_pub, funding_pub) = deploy_tx(None);
    let script_sig = input0_script_sig(&tx);
    assert!(script_sig.contains(&method_pub), "funding input should carry the method pubkey");
    assert!(!script_sig.contains(&funding_pub), "funding input should not carry the funding pubkey");
}

#[test]
fn deploy_with_funding_signer_pushes_funding_pubkey() {
    let funding_ls = LocalSigner::new(FUNDING_KEY).unwrap();
    let fs = FundingSigner(Arc::new(funding_ls));
    let (tx, method_pub, funding_pub) = deploy_tx(Some(fs));
    let script_sig = input0_script_sig(&tx);
    assert!(script_sig.contains(&funding_pub), "funding input should carry the funding pubkey");
    assert!(!script_sig.contains(&method_pub), "funding input should not carry the method pubkey");
}
