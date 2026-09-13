//! Deep-review finding G1 (P1) — spending a method that calls
//! `this.addRawOutput(...)` via the SDK must build a transaction whose outputs
//! match the covenant's `hashOutputs` continuation, or input 0's OP_VERIFY
//! fails and the funds are stuck.
//!
//! The shipped example `RawOutputTest.sendToScript` emits, in SOURCE order:
//!
//!     self.add_raw_output(1000, script_bytes);  // raw output FIRST
//!     self.count = self.count + 1;
//!     self.add_output(0, self.count);           // state continuation SECOND (0 sats)
//!
//! The compiler folds BOTH into the continuation `hashOutputs` in that order,
//! so the on-chain output layout the covenant reconstructs — and its
//! auto-injected state-check OP_VERIFY enforces — is
//! `[raw(1000, scriptBytes)] [stateContinuation(0)] [change]`. The pre-fix SDK
//! dropped the raw output entirely and emitted only the state continuation at
//! output 0, mismatching hashOutputs (finding G1).
//!
//! # Why this test asserts the output layout instead of replaying ScriptVM
//!
//! The Rust tier's `ScriptVm` (`packages/runar-rs/src/sdk/script_vm.rs`) wraps
//! `bsv-sdk`'s `Spend`. That interpreter **cannot validate any Rúnar OP_PUSH_TX
//! continuation covenant**: Rúnar targets Chronicle, whose re-enabled `OP_2MUL`
//! (0x8d) the OP_PUSH_TX low-S normalisation emits as a real opcode, and
//! `bsv-sdk` implements the pre-Chronicle policy that hard-disables it with no
//! config escape — so the spend aborts with `DisabledOpcode("OP_2MUL")`. (This
//! is an opcode-profile mismatch, not the "parser desync" an earlier write-up
//! claimed; see `docs/audit/upstream-bsv-sdk-op2mul-chronicle.md`.) It
//! reproduces for a PLAIN continuation with NO raw output (e.g.
//! `MessageBoard.post`), so it is a standing library limitation entirely
//! independent of G1, not something this fix can influence. The Rust `Spend`
//! therefore cannot distinguish the pre-fix (broken) tx from the post-fix
//! (valid) one — both abort on that opcode.
//!
//! We instead assert the exact byte-level output layout the covenant's
//! hashOutputs check requires — the same verification the spec prescribes for
//! tiers without a usable ScriptVM. The compiler folds these outputs into
//! hashOutputs in this precise order, so `[raw(1000, scriptBytes)]
//! [stateContinuation(0)] [change]` with the continuation carrying exactly 0
//! sats IS the covenant condition. RED (pre-fix) emits only the state
//! continuation; GREEN (post-fix) emits the full source-ordered layout.

use std::path::Path;

use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::{DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};

const DEPLOYER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const CONTRACT_SATS: i64 = 50_000;

/// The caller-supplied raw locking script: a plain P2PKH (76a914 <20 bytes> 88ac).
fn raw_script() -> String {
    format!("76a914{}88ac", "ab".repeat(20))
}

/// Compile the shipped `RawOutputTest.runar.rs` example into an SDK artifact.
/// The compiler crate and SDK crate each own a distinct `RunarArtifact` type,
/// so we round-trip through the canonical artifact JSON.
fn compile_example() -> RunarArtifact {
    let src_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust/add-raw-output/RawOutputTest.runar.rs");
    let compiler_art = runar_compiler_rust::compile_from_source(&src_path)
        .expect("RawOutputTest.runar.rs should compile");
    let json = serde_json::to_string(&compiler_art).expect("serialize compiler artifact");
    serde_json::from_str(&json).expect("deserialize into SDK RunarArtifact")
}

/// Deploy a fresh RawOutputTest (count = 0) funded by the deployer.
/// Returns (contract, provider, signer).
fn deploy() -> (RunarContract, MockProvider, LocalSigner) {
    let signer = LocalSigner::new(DEPLOYER_KEY).unwrap();
    let mut provider = MockProvider::testnet();
    let address = signer.get_address().unwrap();
    provider.add_utxo(&address, Utxo {
        txid: "cc".repeat(32),
        output_index: 0,
        satoshis: 500_000,
        script: build_p2pkh_script(&address),
    });

    let mut contract = RunarContract::new(compile_example(), vec![SdkValue::Int(0)]);
    contract
        .deploy(&mut provider, &signer, &DeployOptions {
            satoshis: CONTRACT_SATS,
            change_address: None,
            funding_signer: None,
            acknowledge_unsound: vec![],
        })
        .expect("deploy should succeed");
    (contract, provider, signer)
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
fn send_to_script_outputs_are_raw_state_change_in_source_order() {
    let (mut contract, mut provider, signer) = deploy();
    let raw = raw_script();

    contract
        .call("sendToScript", &[SdkValue::Bytes(raw.clone())], &mut provider, &signer, None)
        .expect("call(sendToScript) should build + broadcast");

    let call_tx = provider.get_broadcasted_txs()[1].clone();

    // --- Output ordering: [0] raw, [1] state continuation, [2] change. ---
    // This layout is exactly what the covenant folds into hashOutputs; the
    // pre-fix SDK dropped output [0] and emitted only the state continuation.
    let outputs = parse_outputs(&call_tx);
    assert_eq!(
        outputs.len(),
        3,
        "expected [raw][state][change] in source order, got {:?}",
        outputs,
    );

    // [0] raw output: 1000 sats, script === the caller-supplied bytes.
    assert_eq!(outputs[0].0, 1000, "output 0 (raw) must carry 1000 sats");
    assert_eq!(
        outputs[0].1, raw,
        "output 0 (raw) script must be the caller-supplied bytes",
    );

    // [1] state continuation: 0 sats, codePart + OP_RETURN (6a) + serialized count.
    assert_eq!(
        outputs[1].0, 0,
        "output 1 (state continuation) must carry 0 sats (addOutput(0, ...))",
    );
    assert_ne!(outputs[1].1, raw, "output 1 must be the state continuation, not the raw script");
    assert!(
        outputs[1].1.contains("6a"),
        "output 1 (state continuation) must contain an OP_RETURN separator",
    );

    // The SDK must track the continuation as the next spendable UTXO at its REAL
    // index (1 — the raw output precedes it), at its real (0-sat) value.
    let cont = contract.get_utxo().expect("continuation UTXO must be tracked");
    assert_eq!(cont.output_index, 1, "continuation must be tracked at index 1, not 0");
    assert_eq!(cont.satoshis, 0, "tracked continuation value must be 0 sats");
    assert_eq!(cont.script, outputs[1].1, "tracked continuation script must equal output 1");

    // [2] change: a P2PKH output carrying the remainder.
    assert!(outputs[2].1.starts_with("76a914"), "output 2 (change) must be P2PKH");
    assert!(outputs[2].1.ends_with("88ac"), "output 2 (change) must be P2PKH");
    assert!(outputs[2].0 > 0, "output 2 (change) must carry the remainder");
}
