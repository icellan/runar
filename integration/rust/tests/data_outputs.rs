//! addDataOutput end-to-end integration test — uses MockProvider to drive a
//! deploy + call cycle for a stateful contract that emits a data output via
//! `this.addDataOutput(...)`.
//!
//! Acceptance test for BSVM R9: data outputs must appear in declaration
//! order between state outputs and change so the compile-time
//! continuation-hash check matches at spend time.
//!
//! Mirrors `integration/go/data_outputs_test.go`. Does NOT require regtest
//! — runs purely against MockProvider.

use crate::helpers::*;
use runar_lang::sdk::{
    DeployOptions, MockProvider, MockSigner, RunarContract, SdkValue, Signer, Utxo,
};

const SOURCE: &str = r#"
import { StatefulSmartContract } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class DataEmitter extends StatefulSmartContract {
    counter: bigint;

    constructor(counter: bigint) {
        super(counter);
        this.counter = counter;
    }

    public emit(payload: ByteString) {
        this.counter = this.counter + 1n;
        this.addDataOutput(0n, payload);
    }
}
"#;

#[test]
fn test_add_data_output_compiles() {
    let artifact = compile_source(SOURCE, "DataEmitter.runar.ts");
    assert_eq!(artifact.contract_name, "DataEmitter");
    assert!(!artifact.script.is_empty());
}

#[test]
fn test_add_data_output_end_to_end_via_mock_provider() {
    let artifact = compile_source(SOURCE, "DataEmitter.runar.ts");

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);

    let signer = MockSigner::new();
    let mut provider = MockProvider::testnet();
    let address = signer.get_address().expect("get_address");

    // Fund the mock signer's address.
    provider.add_utxo(&address, Utxo {
        txid: "aa".repeat(32),
        output_index: 0,
        satoshis: 1_000_000,
        script: format!("76a914{}88ac", "00".repeat(20)),
    });

    contract
        .deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 10_000,
            change_address: None,
        })
        .expect("deploy");

    // OP_RETURN-style 7-byte ASCII payload (matches the Go test).
    let payload = "6a09" .to_string() + "6273766d2d74657374";
    let (call_txid, _tx) = contract
        .call(
            "emit",
            &[SdkValue::Bytes(payload.clone())],
            &mut provider,
            &signer,
            None,
        )
        .expect("call emit");
    assert!(!call_txid.is_empty());

    // Inspect broadcasted txs: deploy + call.
    let broadcasted = provider.get_broadcasted_txs();
    assert!(
        broadcasted.len() >= 2,
        "expected >= 2 broadcasted txs (deploy + call), got {}",
        broadcasted.len()
    );

    // Parse the call tx and assert output[1] carries our payload (output[0]
    // is the stateful continuation, output[2] is change).
    let call_tx_hex = &broadcasted[broadcasted.len() - 1];
    let outputs = parse_outputs_from_raw_tx_hex(call_tx_hex)
        .expect("parse outputs from call tx hex");

    assert!(
        outputs.len() >= 2,
        "expected >= 2 outputs (state + data), got {}: {:?}",
        outputs.len(),
        outputs
    );
    assert_eq!(
        outputs[1].script, payload,
        "expected data output at index 1 to match payload"
    );
    assert_eq!(
        outputs[1].satoshis, 0,
        "expected data output satoshis to be 0"
    );
}

// ---------------------------------------------------------------------------
// Minimal raw tx output parser — matches `integration/go/data_outputs_test.go`.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ParsedOutput {
    satoshis: i64,
    script: String,
}

fn parse_hex_byte(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s, 16).map_err(|e| format!("bad hex byte {}: {}", s, e))
}

fn read_var_int_hex(hex: &str, pos: usize) -> (usize, usize) {
    let first = parse_hex_byte(&hex[pos..pos + 2]).unwrap_or(0);
    if first < 0xfd {
        return (first as usize, 2);
    }
    if first == 0xfd {
        let lo = parse_hex_byte(&hex[pos + 2..pos + 4]).unwrap_or(0);
        let hi = parse_hex_byte(&hex[pos + 4..pos + 6]).unwrap_or(0);
        return ((lo as usize) | ((hi as usize) << 8), 6);
    }
    if first == 0xfe {
        let b0 = parse_hex_byte(&hex[pos + 2..pos + 4]).unwrap_or(0);
        let b1 = parse_hex_byte(&hex[pos + 4..pos + 6]).unwrap_or(0);
        let b2 = parse_hex_byte(&hex[pos + 6..pos + 8]).unwrap_or(0);
        let b3 = parse_hex_byte(&hex[pos + 8..pos + 10]).unwrap_or(0);
        return (
            (b0 as usize) | ((b1 as usize) << 8) | ((b2 as usize) << 16) | ((b3 as usize) << 24),
            10,
        );
    }
    // 0xff varint (8-byte) — only 4 bytes needed for our test sizes.
    let b0 = parse_hex_byte(&hex[pos + 2..pos + 4]).unwrap_or(0);
    let b1 = parse_hex_byte(&hex[pos + 4..pos + 6]).unwrap_or(0);
    let b2 = parse_hex_byte(&hex[pos + 6..pos + 8]).unwrap_or(0);
    let b3 = parse_hex_byte(&hex[pos + 8..pos + 10]).unwrap_or(0);
    (
        (b0 as usize) | ((b1 as usize) << 8) | ((b2 as usize) << 16) | ((b3 as usize) << 24),
        18,
    )
}

fn parse_outputs_from_raw_tx_hex(hex: &str) -> Result<Vec<ParsedOutput>, String> {
    let mut pos = 0usize;
    pos += 8; // version
    let (n_in, w) = read_var_int_hex(hex, pos);
    pos += w;
    for _ in 0..n_in {
        pos += 64 + 8; // prev txid + prevout index
        let (script_len, slw) = read_var_int_hex(hex, pos);
        pos += slw + script_len * 2 + 8; // script + sequence
    }
    let (n_out, w) = read_var_int_hex(hex, pos);
    pos += w;
    let mut outs = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        // satoshis: 8-byte little-endian
        let mut sats: i64 = 0;
        for j in 0..8 {
            let b = parse_hex_byte(&hex[pos..pos + 2])? as i64;
            sats |= b << (8 * j);
            pos += 2;
        }
        let (script_len, slw) = read_var_int_hex(hex, pos);
        pos += slw;
        let script = hex[pos..pos + script_len * 2].to_string();
        pos += script_len * 2;
        outs.push(ParsedOutput { satoshis: sats, script });
    }
    Ok(outs)
}
