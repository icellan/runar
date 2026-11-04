//! N-433: the stateless / zero-mutable-field `prepare_call` branch and the
//! stateless terminal branch computed a k=1 OP_PUSH_TX ECDSA signature through
//! `compute_op_push_tx_with_code_sep_sighash` and never put it in any output
//! (`build_stateful_prefix` ignores its argument; the only reader of the value
//! was a `!final_op_push_tx_sig.is_empty()` flag that is true exactly when
//! `needs_op_push_tx` is). They now use the preimage-only helper (N-253).
//!
//! Proves: on each stateless path (zero-mutable merge with an extra contract
//! input, single-input call, terminal call) zero OP_PUSH_TX signs happen,
//! counted through `OP_PUSH_TX_SIGN_COUNT`, and the broadcast bytes equal the
//! pinned pre-change cross-tier vectors (N-258 merge, N-270 methodB, terminal
//! vector captured at base). Does not prove anything on-chain: the Rust
//! `bsv-sdk` cannot execute this covenant (see n258). One test fn: the counter
//! is process-global.

use std::sync::atomic::Ordering;

use runar_lang::sdk::oppushtx::OP_PUSH_TX_SIGN_COUNT;
use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::{RunarArtifact, TerminalOutput};
use runar_lang::sdk::{CallOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};

const SIGNER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";

const TWO_METHOD_READONLY_SOURCE: &str = r#"import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';
class TwoMethodReadonly extends StatefulSmartContract {
  readonly owner: PubKey;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  public methodA(sig: Sig): void { assert(checkSig(sig, this.owner)); }
  public methodB(sig: Sig): void { assert(checkSig(sig, this.owner)); }
}
"#;

const N258_MERGE_TX_HEX: &str = "0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fde502483045022100ade686ada1bdadb2468b07f0699412c9d7016ca589633ac0730ea806c47437db022073f4f2a4e1bc2def562624d3ac86e4233410ca8aa84e102615ea3176fd84bb85414d990201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdfa0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac778813000000000000ffffffffbeeb1fa51feba41db76fb4b7c36a128ec3bec67bada65fbf951be782f1d1c09e0000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fde5024830450221009a9a66120d3a5e7f7d936b6b3c5a50116922b0eb6ae6255cc2c4280bab7b2f8b02200cb7382c58409af60b09bde18c241316f68dd95f2d1326109142f7794953704a414d990201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdfa0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac77581b000000000000ffffffffbeeb1fa51feba41db76fb4b7c36a128ec3bec67bada65fbf951be782f1d1c09e0000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000069463043021f10b0ce2db56a17ad04c53de15da45671cd370f10aef72f52f1b07d41c9c4c102206ccf57f5b8e81448179f0882f269ffca5baddf87066c7c2cbf48fa4a6c0b7e7c412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01d0b40100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000";
const N270_METHOD_B_TX_HEX: &str = "0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc202473044022025bdb788c88800da0e122ee07bd7e7cf108c4c6d53ebf09ed2ed7f37e4ab1ec3022012880daf6cb232de74f645e6c69e69b74e7096257735aea1ff394d87d6309fcf414d760201000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd70176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffffb80a35939e20ceea1e5b24188c0630fdc61fad29e98ab26a0a7546b96748de06000000004100000051ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a47304402200274b1644d07fe4be16d71199ab51edb6c62666285ae09526a0badb16bbc815c022019c1ea6f05f733859e15312ef965dd2cb0fb9d6f8c4632828763fc7a1fad2238412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01c9990100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000";
const N433_TERMINAL_TX_HEX: &str = "0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc302483045022100923a5fee18fb37ef44a838f67ddf578473ec3ac72becc46c99e78caa1a11423f022038c8f6f613e9b1b6c61a200f443ee6987755170a43ff9c2056e0dccc8ca84953414d7602010000006324e33631b1cb491f73dac8baa476a642eaeccfc7e00c2708764468c82a4e6c3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd70176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffff5a1ddad12332f96e1d310e510254be705e6fea5b749df0e0192092b1d56a4c14000000004100000051ffffffff01a00f0000000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000";

fn compile(src: &str, name: &str) -> RunarArtifact {
    let a = runar_compiler_rust::compile_from_source_str(src, Some(name)).expect("compile");
    serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap()
}

fn setup(art: &RunarArtifact) -> (LocalSigner, String, Utxo, MockProvider, String) {
    let signer = LocalSigner::new(SIGNER_KEY).unwrap();
    let address = signer.get_address().unwrap();
    let pub_key = signer.get_public_key().unwrap();
    let locking_hex = RunarContract::new(art.clone(), vec![SdkValue::Bytes(pub_key)]).get_locking_script();
    let primary = Utxo { txid: "aa".repeat(32), output_index: 0, satoshis: 5_000, script: locking_hex.clone() };
    let mut provider = MockProvider::testnet();
    provider.add_utxo(&address, Utxo {
        txid: "bb".repeat(32),
        output_index: 0,
        satoshis: 100_000,
        script: build_p2pkh_script(&address),
    });
    provider.add_contract_utxo(&locking_hex, primary.clone());
    (signer, address, primary, provider, locking_hex)
}

fn signs() -> usize {
    OP_PUSH_TX_SIGN_COUNT.load(Ordering::Relaxed)
}

#[test]
fn n433_stateless_paths_compute_no_op_push_tx_signature() {
    // 1. zero-mutable merge (extra contract input).
    let src = include_str!("../../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts");
    let art = compile(src, "AllReadonlyCleanstack.runar.ts");
    let (signer, _addr, primary, mut provider, locking_hex) = setup(&art);
    let extra = Utxo { txid: "cc".repeat(32), output_index: 1, satoshis: 7_000, script: locking_hex.clone() };
    provider.add_contract_utxo(&format!("{}:extra", locking_hex), extra.clone());
    let mut contract = RunarContract::from_utxo(art, &primary).expect("from_utxo");
    let opts = CallOptions { additional_contract_inputs: Some(vec![extra]), ..Default::default() };
    let before = signs();
    contract
        .call("claim", &[SdkValue::Auto, SdkValue::Auto], &mut provider, &signer, Some(&opts))
        .expect("merge call");
    assert_eq!(signs() - before, 0, "zero-mutable merge computed OP_PUSH_TX signature(s)");
    assert_eq!(provider.get_broadcasted_txs().last().unwrap(), N258_MERGE_TX_HEX);

    // 2. single-input stateless call.
    let art = compile(TWO_METHOD_READONLY_SOURCE, "TwoMethodReadonly.runar.ts");
    let (signer, _addr, primary, mut provider, _l) = setup(&art);
    let mut contract = RunarContract::from_utxo(art.clone(), &primary).expect("from_utxo");
    let before = signs();
    contract
        .call("methodB", &[SdkValue::Auto, SdkValue::Auto], &mut provider, &signer, None)
        .expect("methodB call");
    assert_eq!(signs() - before, 0, "stateless call computed OP_PUSH_TX signature(s)");
    assert_eq!(provider.get_broadcasted_txs().last().unwrap(), N270_METHOD_B_TX_HEX);

    // 3. stateless terminal call.
    let (signer, address, primary, mut provider, _l) = setup(&art);
    let mut contract = RunarContract::from_utxo(art, &primary).expect("from_utxo");
    let opts = CallOptions {
        terminal_outputs: Some(vec![TerminalOutput { script_hex: build_p2pkh_script(&address), satoshis: 4_000 }]),
        ..Default::default()
    };
    let before = signs();
    contract
        .call("methodB", &[SdkValue::Auto, SdkValue::Auto], &mut provider, &signer, Some(&opts))
        .expect("terminal call");
    assert_eq!(signs() - before, 0, "stateless terminal computed OP_PUSH_TX signature(s)");
    assert_eq!(provider.get_broadcasted_txs().last().unwrap(), N433_TERMINAL_TX_HEX);
}
