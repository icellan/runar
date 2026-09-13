//! Deep-review follow-on (SDK funds bug, separate from the C20/C27 compiler
//! cluster): the stateful CALL path must build the state continuation at the
//! amount an explicit `this.addOutput(<sats>, ...)` specifies — NOT default it
//! to the spent input's value.
//!
//! The ANF interpreter already records the addOutput satoshis (finding G1 reads
//! it, but ONLY on the raw-output-present branch). A stateful method whose sole
//! output is `addOutput(1000, this.count)` therefore had its continuation built
//! at the input value (e.g. 1 sat), so the covenant's hashOutputs binding
//! rejected the spend — funds stranded. This test mirrors the TS reference
//! `continuation-satoshis.test.ts` (SatCounter).
//!
//! # Verification strategy (no ScriptVM replay)
//!
//! The Rust tier's `ScriptVm` wraps `bsv-sdk`'s `Spend`, which cannot validate a
//! Rúnar OP_PUSH_TX continuation covenant (it hard-disables the `OP_2MUL` the
//! push-tx machinery emits — see `g1_raw_outputs_spend.rs` for the full
//! write-up).
//! We therefore assert the byte-level output layout the covenant's hashOutputs
//! check requires: continuation output (index 0) must carry exactly the
//! addOutput amount. RED (pre-fix) emits the input value (1 sat); GREEN
//! (post-fix) emits 1000.

use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::{
    DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo,
};

const SIGNER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";

/// A stateful method whose ONLY output is `this.addOutput(1000, this.count)`.
/// The Rust frontend parses `.runar.ts` sources, so we reuse the exact source
/// the TS reference test compiles.
const SRC: &str = r#"
    class SatCounter extends StatefulSmartContract {
      count: bigint;
      constructor(count: bigint) { super(count); this.count = count; }
      public inc() {
        this.count = this.count + 1n;
        this.addOutput(1000n, this.count);
      }
    }
"#;

/// Compile the SatCounter source into an SDK artifact. The compiler crate and
/// SDK crate each own a distinct `RunarArtifact` type, so we round-trip through
/// the canonical artifact JSON (same pattern as `g1_raw_outputs_spend.rs`).
fn compile_sat_counter() -> RunarArtifact {
    let compiler_art =
        runar_compiler_rust::compile_from_source_str(SRC, Some("SatCounter.runar.ts"))
            .expect("SatCounter source should compile");
    let json = serde_json::to_string(&compiler_art).expect("serialize compiler artifact");
    serde_json::from_str(&json).expect("deserialize into SDK RunarArtifact")
}

/// Deploy SatCounter (count = 5) at the DEFAULT 1 sat. The call's
/// `addOutput(1000)` must OVERRIDE that input value for the continuation.
/// A separate call-provider is seeded with a spare coin so the call can fund
/// the 1000-sat continuation shortfall out of the wallet.
fn deploy() -> (RunarContract, MockProvider, LocalSigner) {
    let signer = LocalSigner::new(SIGNER_KEY).unwrap();
    let address = signer.get_address().unwrap();

    let mut deploy_provider = MockProvider::testnet();
    deploy_provider.add_utxo(&address, Utxo {
        txid: "aa".repeat(32),
        output_index: 0,
        satoshis: 500_000,
        script: build_p2pkh_script(&address),
    });

    let mut contract = RunarContract::new(compile_sat_counter(), vec![SdkValue::Int(5)]);
    contract
        .deploy(&mut deploy_provider, &signer, &DeployOptions {
            satoshis: 1, // default dust value; continuation must NOT inherit this
            change_address: None,
            funding_signer: None,
            acknowledge_unsound: vec![],
        })
        .expect("deploy should succeed");

    // Fresh provider for the call, seeded with a spare coin to cover the
    // 1000-sat continuation + fee (call() spends the tracked contract UTXO plus
    // coin-selected funding).
    let mut call_provider = MockProvider::testnet();
    call_provider.add_utxo(&address, Utxo {
        txid: "bb".repeat(32),
        output_index: 1,
        satoshis: 500_000,
        script: build_p2pkh_script(&address),
    });
    // The call spends the deploy's contract output. Teach the FRESH call
    // provider about that outpoint, otherwise its fail-closed broadcast gate
    // would have nothing to check and would (correctly) refuse the ack.
    let contract_utxo = contract.get_utxo().expect("deploy tracks a contract UTXO").clone();
    call_provider.add_contract_utxo(&contract_utxo.script.clone(), contract_utxo);

    (contract, call_provider, signer)
}

/// Parse a raw tx hex into its `(satoshis, locking_script_hex)` outputs.
fn parse_outputs(tx_hex: &str) -> Vec<(i64, String)> {
    let bytes: Vec<u8> = (0..tx_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&tx_hex[i..i + 2], 16).unwrap())
        .collect();
    let mut p = 0usize;

    fn read_varint(bytes: &[u8], p: &mut usize) -> u64 {
        let first = bytes[*p];
        *p += 1;
        match first {
            0xfd => {
                let v = (bytes[*p] as u64) | ((bytes[*p + 1] as u64) << 8);
                *p += 2;
                v
            }
            0xfe => {
                let v = (bytes[*p] as u64)
                    | ((bytes[*p + 1] as u64) << 8)
                    | ((bytes[*p + 2] as u64) << 16)
                    | ((bytes[*p + 3] as u64) << 24);
                *p += 4;
                v
            }
            0xff => panic!("8-byte varint not expected"),
            n => n as u64,
        }
    }

    p += 4; // version
    let input_count = read_varint(&bytes, &mut p);
    for _ in 0..input_count {
        p += 32 + 4; // prev txid + index
        let slen = read_varint(&bytes, &mut p) as usize;
        p += slen; // scriptSig
        p += 4; // sequence
    }

    let output_count = read_varint(&bytes, &mut p);
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let mut sats: i64 = 0;
        for i in 0..8 {
            sats |= (bytes[p + i] as i64) << (8 * i);
        }
        p += 8;
        let slen = read_varint(&bytes, &mut p) as usize;
        let script: String = bytes[p..p + slen].iter().map(|b| format!("{:02x}", b)).collect();
        p += slen;
        outputs.push((sats, script));
    }
    outputs
}

#[test]
fn continuation_uses_explicit_addoutput_amount_not_input_value() {
    let (mut contract, mut provider, signer) = deploy();

    // NO options.satoshis — the SDK must derive 1000 from the addOutput.
    contract
        .call("inc", &[], &mut provider, &signer, None)
        .expect("call(inc) should build + broadcast");

    let call_tx = provider.get_broadcasted_txs()[0].clone();
    let outputs = parse_outputs(&call_tx);

    // Continuation output (index 0) must carry the addOutput amount (1000),
    // NOT the spent input's 1-sat value.
    assert_eq!(
        outputs[0].0, 1000,
        "continuation must be built at the explicit addOutput(1000) amount, \
         not the input UTXO value; got {:?}",
        outputs,
    );
    // The continuation is the contract's own state script (codePart + OP_RETURN).
    assert!(
        outputs[0].1.contains("6a"),
        "output 0 (state continuation) must contain an OP_RETURN separator, got {}",
        outputs[0].1,
    );

    // The SDK must track the continuation UTXO at 1000 sats too.
    let cont = contract.get_utxo().expect("continuation UTXO must be tracked");
    assert_eq!(cont.satoshis, 1000, "tracked continuation value must be 1000 sats");
}
