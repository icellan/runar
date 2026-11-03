//! N-073: a fixed-width ByteString-family constructor arg must have its
//! declared width (Addr/Ripemd160 20, Sha256 32, PubKey 33, Point/P256Point 64,
//! P384Point 96), with N-045's message. `from_utxo`'s internal restore path is
//! unaffected.
//!
//! Proves: a 33-byte Sha256 and a 19-byte Addr (scalar and FixedArray leaf)
//! panic with the N-045 wording; correct widths are accepted; ByteString takes
//! any length; `from_utxo` restores.
//! Does NOT prove: method-call or state value widths (N-045), on-chain
//! spendability, or that the restore bypass is unreachable by user input.

use runar_lang::sdk::types::{RunarArtifact, SdkValue};
use runar_lang::sdk::RunarContract;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn artifact(param_type: &str) -> RunarArtifact {
    serde_json::from_value(serde_json::json!({
        "version": "runar-v0.1.0",
        "compilerVersion": "0.1.0",
        "contractName": "N073",
        "abi": {
            "constructor": { "params": [{ "name": "owner", "type": param_type }] },
            "methods": [{ "name": "noop", "params": [], "isPublic": true }]
        },
        "script": "00",
        "asm": "",
        "buildTimestamp": "2026-03-02T00:00:00.000Z",
        "constructorSlots": [{ "paramIndex": 0, "byteOffset": 0 }]
    }))
    .expect("artifact")
}

fn construct(param_type: &str, arg: SdkValue) -> Result<RunarContract, String> {
    match catch_unwind(AssertUnwindSafe(|| RunarContract::new(artifact(param_type), vec![arg]))) {
        Ok(c) => Ok(c),
        Err(payload) => match payload.downcast::<String>() {
            Ok(msg) => Err(*msg),
            Err(other) => std::panic::resume_unwind(other),
        },
    }
}

fn hex(n: usize) -> SdkValue {
    SdkValue::Bytes("ab".repeat(n))
}

#[test]
fn wrong_width_sha256_is_refused_with_n045_message() {
    let err = construct("Sha256", hex(33)).err().expect("must be refused");
    assert!(
        err.contains("constructor arg 'owner' (Sha256) must be exactly 32 bytes of hex, got 33 bytes"),
        "{err}"
    );
}

#[test]
fn wrong_width_addr_is_refused() {
    assert!(construct("Addr", hex(19)).is_err());
}

#[test]
fn wrong_width_fixed_array_leaf_is_refused() {
    let arg = SdkValue::Array(vec![hex(20), hex(19)]);
    assert!(construct("FixedArray<Addr, 2>", arg).is_err());
}

#[test]
fn correct_width_accepted_and_one_less_refused() {
    for (ty, n) in [
        ("Addr", 20), ("Ripemd160", 20), ("Sha256", 32), ("PubKey", 33),
        ("Point", 64), ("P256Point", 64), ("P384Point", 96),
    ] {
        assert!(construct(ty, hex(n)).is_ok(), "{ty} {n}");
        assert!(construct(ty, hex(n - 1)).is_err(), "{ty} {}", n - 1);
    }
    assert!(construct("ByteString", hex(3)).is_ok());
}

#[test]
fn from_utxo_still_restores() {
    let art = artifact("Addr");
    let script = construct("Addr", hex(20)).unwrap().get_locking_script();
    let utxo = runar_lang::sdk::types::Utxo {
        txid: "00".repeat(32),
        output_index: 0,
        satoshis: 1,
        script: script.clone(),
    };
    let c = RunarContract::from_utxo(art, &utxo).expect("from_utxo");
    assert_eq!(c.get_locking_script(), script);
}
