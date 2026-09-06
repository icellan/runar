//! Issue #118 — a terminal call can pay a miner fee via CallOptions.fee_utxo.
//!
//! A true terminal method pays out the full contract balance, so fee == 0 and
//! ARC rejects; the covenant asserts its exact output set, so no change output
//! can absorb a fee. fee_utxo adds a plain P2PKH input to the terminal tx BEFORE
//! the OP_PUSH_TX preimage is computed (so hashPrevouts covers it), consumed
//! entirely as fee with no change output. Signed with funding_signer ?? signer.

use std::sync::Arc;

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::{
    CallOptions, DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo,
};
use runar_lang::sdk::types::{
    Abi, AbiConstructor, AbiMethod, FundingSigner, RunarArtifact, TerminalOutput,
};

const METHOD_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const FUNDING_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000007";
const CONTRACT_SATS: i64 = 50_000;
const FEE_SATS: i64 = 5_000;

/// Trivial OP_TRUE covenant with a single terminal method.
fn trivial_artifact() -> RunarArtifact {
    RunarArtifact {
        version: "runar-v0.1.0".to_string(),
        contract_name: "Escrow".to_string(),
        parent_class: None,
        abi: Abi {
            constructor: AbiConstructor { params: vec![] },
            methods: vec![AbiMethod {
                name: "settle".to_string(),
                params: vec![],
                is_public: true,
                is_terminal: None,
                uses_code_part: None,
                sig_hash_type: None,
            }],
        },
        script: "51".to_string(), // OP_TRUE
        asm: None,
        state_fields: None,
        constructor_slots: None,
        code_sep_index_slots: None,
        code_separator_index: None,
        code_separator_indices: None,
        anf: None,
    }
}

/// Walk a raw tx hex: returns (num_inputs, num_outputs, output_sum, scriptSig of
/// each input).
fn walk_tx(tx_hex: &str) -> (usize, usize, i64, Vec<String>) {
    let bytes: Vec<u8> = (0..tx_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&tx_hex[i..i + 2], 16).unwrap())
        .collect();
    let mut p = 4usize; // version
    let read_varint = |b: &[u8], p: &mut usize| -> u64 {
        let first = b[*p];
        *p += 1;
        match first {
            0xfd => { let v = u16::from_le_bytes([b[*p], b[*p + 1]]) as u64; *p += 2; v }
            0xfe => { let v = u32::from_le_bytes([b[*p], b[*p + 1], b[*p + 2], b[*p + 3]]) as u64; *p += 4; v }
            0xff => { let mut a = [0u8; 8]; a.copy_from_slice(&b[*p..*p + 8]); *p += 8; u64::from_le_bytes(a) }
            n => n as u64,
        }
    };
    let in_count = read_varint(&bytes, &mut p) as usize;
    let mut script_sigs = Vec::new();
    for _ in 0..in_count {
        p += 32; // prev txid
        p += 4; // prev index
        let slen = read_varint(&bytes, &mut p) as usize;
        let ss: String = bytes[p..p + slen].iter().map(|b| format!("{:02x}", b)).collect();
        script_sigs.push(ss);
        p += slen;
        p += 4; // sequence
    }
    let out_count = read_varint(&bytes, &mut p) as usize;
    let mut out_sum = 0i64;
    for _ in 0..out_count {
        let mut a = [0u8; 8];
        a.copy_from_slice(&bytes[p..p + 8]);
        out_sum += i64::from_le_bytes(a);
        p += 8;
        let slen = read_varint(&bytes, &mut p) as usize;
        p += slen;
    }
    (in_count, out_count, out_sum, script_sigs)
}

fn deploy() -> (RunarContract, MockProvider, LocalSigner) {
    let method_signer = LocalSigner::new(METHOD_KEY).unwrap();
    let mut provider = MockProvider::testnet();
    let address = method_signer.get_address().unwrap();
    provider.add_utxo(&address, Utxo {
        txid: "cc".repeat(32),
        output_index: 0,
        satoshis: 200_000,
        script: build_p2pkh_script(&address),
    });
    let mut contract = RunarContract::new(trivial_artifact(), Vec::<SdkValue>::new());
    contract
        .deploy(&mut provider, &method_signer, &DeployOptions {
            satoshis: CONTRACT_SATS,
            change_address: None,
            funding_signer: None,
        })
        .unwrap();
    (contract, provider, method_signer)
}

const PAYOUT: &str = "76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac";

#[test]
fn terminal_without_fee_utxo_has_one_input_and_zero_fee() {
    let (mut contract, mut provider, method_signer) = deploy();
    let opts = CallOptions {
        terminal_outputs: Some(vec![TerminalOutput {
            script_hex: PAYOUT.to_string(),
            satoshis: CONTRACT_SATS,
        }]),
        ..Default::default()
    };
    contract
        .call("settle", &[], &mut provider, &method_signer, Some(&opts))
        .unwrap();
    let term_tx = &provider.get_broadcasted_txs()[1];
    let (n_in, _n_out, out_sum, _) = walk_tx(term_tx);
    assert_eq!(n_in, 1, "only the contract input");
    assert_eq!(CONTRACT_SATS - out_sum, 0, "full-balance payout leaves fee 0");
}

#[test]
fn terminal_with_fee_utxo_adds_signed_fee_input_and_positive_fee() {
    let (mut contract, mut provider, method_signer) = deploy();
    let funding_signer = LocalSigner::new(FUNDING_KEY).unwrap();
    let funding_pub = funding_signer.get_public_key().unwrap();
    let fee_script = format!("76a914{}88ac", "22".repeat(20));

    let opts = CallOptions {
        terminal_outputs: Some(vec![TerminalOutput {
            script_hex: PAYOUT.to_string(),
            satoshis: CONTRACT_SATS,
        }]),
        fee_utxo: Some(Utxo {
            txid: "ee".repeat(32),
            output_index: 1,
            satoshis: FEE_SATS,
            script: fee_script,
        }),
        funding_signer: Some(FundingSigner(Arc::new(LocalSigner::new(FUNDING_KEY).unwrap()))),
        ..Default::default()
    };
    contract
        .call("settle", &[], &mut provider, &method_signer, Some(&opts))
        .unwrap();
    let term_tx = &provider.get_broadcasted_txs()[1];
    let (n_in, n_out, out_sum, script_sigs) = walk_tx(term_tx);

    assert_eq!(n_in, 2, "contract input + fee input");
    // Covenant output side is untouched: still exactly the payout.
    assert_eq!(n_out, 1);
    assert_eq!(out_sum, CONTRACT_SATS);
    // Fee input (index 1) is signed by the funding signer.
    assert!(script_sigs[1].contains(&funding_pub), "fee input must carry the funding pubkey");
    // fee = sum(inputs) - sum(outputs) == FEE_SATS > 0
    let fee = (CONTRACT_SATS + FEE_SATS) - out_sum;
    assert_eq!(fee, FEE_SATS);
    assert!(fee > 0);
}
