//! N-270: the "stateless branch" of `prepare_call` (taken whenever
//! `is_stateful` — derived from a non-empty `state_fields` — is false, which
//! includes a zero-mutable-field `StatefulSmartContract`) computes the REAL
//! method index unconditionally (`self.find_method_index(method_name)`,
//! `self.get_code_sep_index(method_index)`), never gated on `is_stateful`.
//! This is the behaviour TS and Go's `prepareCall` lacked (see
//! `packages/runar-sdk/src/__tests__/n270-stateless-branch-codesep-index.test.ts`
//! and `packages/runar-go/sdk_n270_stateless_branch_codesep_index_test.go`,
//! each fixed alongside this item).
//!
//! `two_method_readonly_source` has ZERO mutable fields but two public
//! methods, each with its own auto-injected checkPreimage and its own
//! OP_CODESEPARATOR at a DIFFERENT byte offset.
//!
//! What this test proves: the Rust SDK's tx for calling `methodB` (real
//! index 1) is byte-identical to the TS SDK's (and the never-buggy Python
//! SDK's, used as an independent oracle before this value was pinned here)
//! vector for the same call — i.e. Rust was never buggy here. The Rust
//! `bsv-sdk` crate cannot execute this covenant's checkPreimage machinery
//! (its pre-Chronicle opcode policy), so — as with N-258 — script validity
//! in this tier rests on that cross-tier byte parity, not on a local
//! interpreter run.
//!
//! What this test does not prove: the terminal-call branch, a merge
//! (`additional_contract_inputs`) on this fixture, or any tier besides
//! TS/Go/Python (this file is a parity pin, not a TDD red/green item — Rust
//! had no bug to fix).

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};

const SIGNER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";

const TWO_METHOD_READONLY_SOURCE: &str = r#"import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';
class TwoMethodReadonly extends StatefulSmartContract {
  readonly owner: PubKey;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  public methodA(sig: Sig): void { assert(checkSig(sig, this.owner)); }
  public methodB(sig: Sig): void { assert(checkSig(sig, this.owner)); }
}
"#;

const N270_METHOD_B_TX_HEX: &str = "0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc802473044022061c3519e6e4cfa60f9dde9c5f0d4e460e5ef60197ba44c0e71cca562c47c4a71022010e5eab8367b1acf7fd6ec54818e4dda8e47660e53190564d41e0b4904b37f49414d7c0201000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fddd0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffffb80a35939e20ceea1e5b24188c0630fdc61fad29e98ab26a0a7546b96748de06000000004100000051ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a47304402200274b1644d07fe4be16d71199ab51edb6c62666285ae09526a0badb16bbc815c022019c1ea6f05f733859e15312ef965dd2cb0fb9d6f8c4632828763fc7a1fad2238412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01c9990100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000";

fn artifact() -> RunarArtifact {
    let a = runar_compiler_rust::compile_from_source_str(TWO_METHOD_READONLY_SOURCE, Some("TwoMethodReadonly.runar.ts"))
        .expect("compile TwoMethodReadonly");
    serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap()
}

#[test]
fn fixture_has_distinct_per_method_code_separators() {
    let art = artifact();
    assert_eq!(art.parent_class.as_deref(), Some("StatefulSmartContract"));
    assert!(art.state_fields.as_ref().map(|v| v.is_empty()).unwrap_or(true));
    let indices = art.code_separator_indices.clone().expect("codeSeparatorIndices");
    assert_eq!(indices.len(), 2);
    assert_ne!(indices[0], indices[1]);
}

#[test]
fn method_b_tx_matches_cross_tier_vector() {
    let art = artifact();

    let signer = LocalSigner::new(SIGNER_KEY).unwrap();
    let address = signer.get_address().unwrap();
    let pub_key = signer.get_public_key().unwrap();
    let locking_hex = RunarContract::new(art.clone(), vec![SdkValue::Bytes(pub_key)]).get_locking_script();

    let primary = Utxo { txid: "aa".repeat(32), output_index: 0, satoshis: 5_000, script: locking_hex.clone() };

    let mut provider = MockProvider::testnet(); // broadcast validation default-on
    provider.add_utxo(&address, Utxo {
        txid: "bb".repeat(32),
        output_index: 0,
        satoshis: 100_000,
        script: build_p2pkh_script(&address),
    });
    provider.add_contract_utxo(&locking_hex, primary.clone());

    let mut contract = RunarContract::from_utxo(art, &primary).expect("from_utxo");
    contract
        .call("methodB", &[SdkValue::Auto, SdkValue::Auto], &mut provider, &signer, None)
        .expect("methodB call");

    assert_eq!(provider.get_broadcasted_txs().last().unwrap(), N270_METHOD_B_TX_HEX);
}
