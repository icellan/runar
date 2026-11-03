//! N-329: a ByteString-family constructor arg that is not an even-length hex
//! string must be refused at construction with a typed error, not spliced into
//! the locking script as raw text (a push header sized for the raw bytes
//! followed by non-hex characters, with no error).
//!
//! Proves: `RunarContract::new` panics (this tier's refusal style, like its
//! arg-count check) with the shared diagnostic as the panic message for raw non-hex Addr text, odd-length hex and a
//! non-hex leaf inside an `SdkValue::Array` for a `FixedArray<Addr, 2>` param;
//! valid hex (either case, empty) is accepted and `get_locking_script()` is
//! hex-only.
//! Does NOT prove: width checks (a 3-byte Addr is accepted here) or on-chain
//! spendability.

use runar_lang::sdk::types::{RunarArtifact, SdkValue};
use runar_lang::sdk::RunarContract;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn artifact(param_type: &str) -> RunarArtifact {
    serde_json::from_value(serde_json::json!({
        "version": "runar-v0.1.0",
        "compilerVersion": "0.1.0",
        "contractName": "N329",
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

#[test]
fn non_hex_bytestring_ctor_arg_is_refused_n329() {
    let raw_addr: String = (0x80u8..0x94).map(|b| b as char).collect();
    for (ty, arg) in [("Addr", raw_addr.as_str()), ("ByteString", "abc"), ("PubKey", "zz")] {
        let err = construct(ty, SdkValue::Bytes(arg.to_string()))
            .err()
            .unwrap_or_else(|| panic!("{} {:?} must be refused", ty, arg));
        assert_eq!(
            err,
            format!("RunarContract: constructor arg 'owner' ({}) of N329 must be an even-length hex string", ty)
        );
    }
}

#[test]
fn non_hex_fixed_array_leaf_is_refused_n329() {
    let arg = SdkValue::Array(vec![SdkValue::Bytes("aabb".into()), SdkValue::Bytes("not-hex!".into())]);
    assert!(construct("FixedArray<Addr, 2>", arg).is_err());
}

#[test]
fn hex_bytestring_ctor_arg_is_accepted_n329() {
    for arg in ["9a1c78a5", "9A1C78A5", ""] {
        let c = construct("ByteString", SdkValue::Bytes(arg.to_string())).expect("hex must be accepted");
        let script = c.get_locking_script();
        assert!(script.len() % 2 == 0 && script.bytes().all(|b| b.is_ascii_hexdigit()), "{}", script);
    }
}
