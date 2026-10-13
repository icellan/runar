//! N-227 (port of sdk:ts N-085): a zero-mutable-field `StatefulSmartContract`
//! call underpays MockProvider's 100 sat/KB fee floor.
//!
//! `AllReadonlyCleanstack` has ZERO mutable fields, so its `state_fields` is
//! empty and `call`'s `is_stateful` is `false` — even though the contract IS
//! `parent_stateful` (parent_class == "StatefulSmartContract") and still
//! auto-injects `checkPreimage` / OP_CODESEPARATOR at method entry (its
//! `claim` method carries a visible `txPreimage` ABI param, so
//! `needs_op_push_tx` is true via `preimage_index.is_some()`). That routes
//! the call through the "stateless" branch (`else if needs_op_push_tx ||
//! !sig_indices.is_empty()`), which — before this fix — never recomputed
//! fee/change from the REAL (final) unlocking script the way the
//! `is_stateful` branch's rebuild does.
//!
//! The injected OP_CODESEPARATOR sits right at method entry, so the BIP-143
//! scriptCode (everything after it) is almost the WHOLE locking script — far
//! bigger than the generic placeholder preimage the earlier sizing pass
//! assumed. The real unlocking script ends up hundreds of bytes bigger than
//! what fee/change were computed against, so the broadcast tx pays less than
//! the fee its own (larger) byte size requires.
//!
//! What this test proves: the Rust SDK's `claim()` call on a
//! zero-mutable-field StatefulSmartContract broadcasts a tx whose actual fee
//! (computed from the REAL broadcast bytes this test parses itself: sum of
//! known input satoshis minus sum of output satoshis) meets the 100 sat/KB
//! floor `MockProvider`'s fee rate reports. It also relies on
//! `MockProvider::broadcast`'s default-on `spend.validate()` check (see
//! `provider.rs`) to prove the rebuilt unlock is still a VALID spend of the
//! locking script — not just correctly sized.
//!
//! What this test does NOT prove: the same fix in TypeScript (already fixed,
//! N-085), Go, Python, Zig, Ruby or Java — each tier is a separate item
//! slot. It also does not prove anything about continuation-bearing
//! (non-empty `state_fields`) stateful calls, which already take the
//! `is_stateful` branch and were unaffected by this bug, nor about a
//! zero-mutable-field call that also merges `additional_contract_inputs`
//! (N-227 Part 2 — a separate fail-closed guard, covered by the sibling test
//! in this file).

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{CallOptions, DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};

const SIGNER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";

const SRC: &str = r#"
class AllReadonlyCleanstack extends StatefulSmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public claim(sig: Sig): void {
    const ownerCopy = this.owner;
    assert(checkSig(sig, this.owner));
  }
}
"#;

fn artifact() -> RunarArtifact {
    let a = runar_compiler_rust::compile_from_source_str(SRC, Some("AllReadonlyCleanstack.runar.ts"))
        .expect("compile AllReadonlyCleanstack");
    serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap()
}

/// Minimal raw-tx hex parser: just enough to sum output satoshis and count
/// inputs. Deliberately independent of the `bsv-sdk` crate's internal types
/// so this test does not depend on which fields that crate happens to expose
/// publicly — it reads the standard non-segwit Bitcoin tx wire format
/// directly off the bytes the SDK broadcast.
struct ParsedTx {
    input_count: usize,
    total_output_satoshis: i64,
}

fn decode_hex(hex_str: &str) -> Vec<u8> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

fn parse_tx(hex_str: &str) -> ParsedTx {
    let bytes = decode_hex(hex_str);
    let mut pos = 0usize;

    fn read_varint(bytes: &[u8], pos: &mut usize) -> u64 {
        let first = bytes[*pos];
        *pos += 1;
        match first {
            0xfd => {
                let v = u16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]) as u64;
                *pos += 2;
                v
            }
            0xfe => {
                let v = u32::from_le_bytes([
                    bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3],
                ]) as u64;
                *pos += 4;
                v
            }
            0xff => {
                let v = u64::from_le_bytes([
                    bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3],
                    bytes[*pos + 4], bytes[*pos + 5], bytes[*pos + 6], bytes[*pos + 7],
                ]);
                *pos += 8;
                v
            }
            n => n as u64,
        }
    }

    pos += 4; // version
    let input_count = read_varint(&bytes, &mut pos) as usize;
    for _ in 0..input_count {
        pos += 32 + 4; // prev txid + prev index
        let script_len = read_varint(&bytes, &mut pos) as usize;
        pos += script_len;
        pos += 4; // sequence
    }
    let output_count = read_varint(&bytes, &mut pos) as usize;
    let mut total_output_satoshis: i64 = 0;
    for _ in 0..output_count {
        let sats = i64::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
            bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7],
        ]);
        total_output_satoshis += sats;
        pos += 8;
        let script_len = read_varint(&bytes, &mut pos) as usize;
        pos += script_len;
    }

    ParsedTx { input_count, total_output_satoshis }
}

#[test]
fn claim_on_all_readonly_cleanstack_pays_fee_floor() {
    let art = artifact();

    // Sanity on the premise: zero mutable state fields, but still a real
    // StatefulSmartContract (auto-injects checkPreimage).
    assert_eq!(art.parent_class.as_deref(), Some("StatefulSmartContract"));
    assert!(art.state_fields.as_ref().map(|v| v.is_empty()).unwrap_or(true));

    let signer = LocalSigner::new(SIGNER_KEY).unwrap();
    let address = signer.get_address().unwrap();
    let mut provider = MockProvider::testnet(); // broadcast validation default-on
    provider.add_utxo(&address, Utxo {
        txid: "aa".repeat(32),
        output_index: 0,
        satoshis: 100_000,
        script: build_p2pkh_script(&address),
    });

    let mut contract = RunarContract::new(art, vec![SdkValue::Bytes(signer.get_public_key().unwrap())]);
    contract
        .deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 5_000,
            change_address: Some(address.clone()),
            funding_signer: None,
            acknowledge_unsound: vec![],
        })
        .expect("deploy");

    // claim(sig, txPreimage): both auto-resolved. is_stateful is false here,
    // so neither param is hidden from the caller — mirrors the TS N-085
    // repro's [null, null].
    let (_, _tx) = contract
        .call("claim", &[SdkValue::Auto, SdkValue::Auto], &mut provider, &signer, None)
        .expect("call claim");

    let txs = provider.get_broadcasted_txs();
    let call_hex = txs.last().expect("a broadcast happened");
    let parsed = parse_tx(call_hex);

    // Total input value: the contract's own deployed UTXO (5000 sats) plus,
    // if more than one input is present, the ONE funding UTXO this test
    // registered (100000 sats) — this test controls the entire UTXO
    // universe, so the input count alone determines which UTXOs were spent.
    let mut total_in: i64 = 5_000;
    if parsed.input_count > 1 {
        total_in += 100_000;
    }

    let actual_fee = total_in - parsed.total_output_satoshis;
    let fee_rate = 100i64; // MockProvider::testnet() default fee rate
    let tx_size_bytes = (call_hex.len() / 2) as i64;
    let required_fee = ((tx_size_bytes * fee_rate) as f64 / 1000.0).ceil() as i64;

    assert!(
        actual_fee >= required_fee,
        "fee too low: paid {} sats, required >= {} sats (tx size {} bytes, fee rate {} sat/KB)",
        actual_fee, required_fee, tx_size_bytes, fee_rate,
    );
}

/// N-227 Part 2: a zero-mutable-field StatefulSmartContract call that also
/// merges `additional_contract_inputs` must fail closed rather than
/// broadcast an invalid tx. The `is_stateful` branch builds a REAL per-input
/// unlock for every extra contract input; the non-stateful ("stateless")
/// branch this contract's `claim()` takes has no equivalent — it would ship
/// the SIZING placeholder unlock as the FINAL unlocking script for the extra
/// input, which does not validate on-chain.
#[test]
fn claim_with_additional_contract_inputs_is_refused() {
    let art = artifact();
    assert!(art.state_fields.as_ref().map(|v| v.is_empty()).unwrap_or(true));

    let signer = LocalSigner::new(SIGNER_KEY).unwrap();
    let address = signer.get_address().unwrap();
    let mut provider = MockProvider::testnet();
    provider.add_utxo(&address, Utxo {
        txid: "aa".repeat(32),
        output_index: 0,
        satoshis: 100_000,
        script: build_p2pkh_script(&address),
    });

    let mut contract = RunarContract::new(art, vec![SdkValue::Bytes(signer.get_public_key().unwrap())]);
    contract
        .deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 5_000,
            change_address: Some(address.clone()),
            funding_signer: None,
            acknowledge_unsound: vec![],
        })
        .expect("deploy");

    // The "extra" merge input's content is irrelevant — the guard must fire
    // before any unlock is built for it. Reuse the deployed contract's own
    // locking script so it is at least well-formed hex.
    let locking_script_hex = contract.get_utxo().expect("current utxo after deploy").script.clone();
    let extra = Utxo {
        txid: "cc".repeat(32),
        output_index: 0,
        satoshis: 5_000,
        script: locking_script_hex,
    };

    let opts = CallOptions {
        additional_contract_inputs: Some(vec![extra]),
        ..Default::default()
    };

    let result = contract.call(
        "claim",
        &[SdkValue::Auto, SdkValue::Auto],
        &mut provider,
        &signer,
        Some(&opts),
    );
    assert!(
        result.is_err(),
        "expected call to refuse additional_contract_inputs on a zero-mutable-field contract, but it succeeded"
    );
}
