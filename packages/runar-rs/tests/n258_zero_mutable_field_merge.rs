//! N-258 (user decision R99): a zero-mutable-field `StatefulSmartContract`
//! call that also spends `additional_contract_inputs` builds a REAL per-input
//! unlock for every extra contract input (its own OP_PUSH_TX preimage over its
//! own outpoint / scriptCode / amount, and its own Sig signed at its own input
//! index over the post-OP_CODESEPARATOR subscript), instead of refusing
//! (N-227) or shipping the sizing placeholder. Fee/change are re-derived from
//! the real unlocks.
//!
//! The scenario is the cross-tier N-258 vector: same contract, key, outpoints
//! and amounts as packages/runar-sdk/src/__tests__/n258-zero-mutable-field-
//! merge.test.ts, whose tx @bsv/sdk `Spend` accepts on every input.
//!
//! What this test proves: the Rust SDK's merge tx is byte-identical to the
//! TS-produced vector (so it is exactly the tx Spend accepts in TS, and the go-
//! sdk interpreter and Python bsv-sdk Spend accept in their tiers). The Rust
//! `bsv-sdk` crate cannot execute this covenant (its pre-Chronicle policy
//! refuses OP_2MUL), so script validity in this tier rests on that parity, not
//! on a local interpreter run.
//!
//! What this test does not prove: merges on a zero-mutable-field contract
//! with more than one public method (the stateless branch derives OP_PUSH_TX
//! from the primary's code-separator index), allPrevouts auto-resolution on
//! this branch, or the terminal-outputs path.

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{CallOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};

const SIGNER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";

const N258_MERGE_TX_HEX: &str = "0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdea02473044022033b20ee497b244a5f44ea460cbeb66c867d72ee622cf6e8163651998b66da33d02200b7580e4c31b3bf66410bbd033e935bcf41449fcabfdf90275cc2a7df78f8911414d9f0201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fd000276aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac778813000000000000ffffffffe0fb8d8fe33024ae55861c19ec7c3056e7ba656aa6623274dc5d6140edcd3d370000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdea0247304402203b86795685f996d25ad0c7db76fb2b1d3ba6e1127332ba7806f9786e6ef03d0602201eca36661b0bb5e080c43fe881cae23d59194a557a76fdbca879995aaabc2314414d9f0201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fd000276aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac77581b000000000000ffffffffe0fb8d8fe33024ae55861c19ec7c3056e7ba656aa6623274dc5d6140edcd3d370000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006b483045022100fe183c7919d2e06724b2134fa072fa1d6a698eb1b6cc07dd42341eeff238c11f02200abfed215d06dcaae1226e0497cff4ef3834ea7043cdbb76af44104c630b7c25412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01ceb40100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000";

fn artifact() -> RunarArtifact {
    let src = include_str!("../../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts");
    let a = runar_compiler_rust::compile_from_source_str(src, Some("AllReadonlyCleanstack.runar.ts"))
        .expect("compile AllReadonlyCleanstack");
    serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap()
}

#[test]
fn zero_mutable_field_merge_is_spend_valid_and_matches_vector() {
    let art = artifact();
    assert_eq!(art.parent_class.as_deref(), Some("StatefulSmartContract"));
    assert!(art.state_fields.as_ref().map(|v| v.is_empty()).unwrap_or(true));

    let signer = LocalSigner::new(SIGNER_KEY).unwrap();
    let address = signer.get_address().unwrap();
    let pub_key = signer.get_public_key().unwrap();
    let locking_hex = RunarContract::new(art.clone(), vec![SdkValue::Bytes(pub_key)]).get_locking_script();

    let primary = Utxo { txid: "aa".repeat(32), output_index: 0, satoshis: 5_000, script: locking_hex.clone() };
    let extra = Utxo { txid: "cc".repeat(32), output_index: 1, satoshis: 7_000, script: locking_hex.clone() };

    let mut provider = MockProvider::testnet(); // broadcast validation default-on
    provider.add_utxo(&address, Utxo {
        txid: "bb".repeat(32),
        output_index: 0,
        satoshis: 100_000,
        script: build_p2pkh_script(&address),
    });
    provider.add_contract_utxo(&locking_hex, primary.clone());
    provider.add_contract_utxo(&format!("{}:extra", locking_hex), extra.clone());

    let mut contract = RunarContract::from_utxo(art, &primary).expect("from_utxo");
    let opts = CallOptions {
        additional_contract_inputs: Some(vec![extra]),
        ..Default::default()
    };
    contract
        .call("claim", &[SdkValue::Auto, SdkValue::Auto], &mut provider, &signer, Some(&opts))
        .expect("merge call");

    // Byte parity with the TS vector is the proof of script validity here:
    // the bsv-sdk crate's pre-Chronicle opcode policy refuses the push-tx
    // covenant's OP_2MUL, so MockProvider records both contract inputs as
    // "unvalidatable" (never as passed) and executes only the P2PKH funding
    // input. Pin that split so a future change in either direction is seen.
    assert_eq!(provider.get_broadcasted_txs().last().unwrap(), N258_MERGE_TX_HEX);
    let report = provider.last_validation_report();
    assert_eq!((report.validated, report.unvalidatable), (1, 2));
}
