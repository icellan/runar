//! N-330: a ByteString-family constructor arg whose `SdkValue` is not
//! `Bytes` must be refused with the N-329 diagnostic. `SdkValue` has no
//! raw-bytes variant (`Bytes` already carries hex), so there is nothing to
//! convert in this tier. Before, `encode_arg` encoded `Int`/`BigInt`/`Bool` as
//! script numbers / OP_1 / OP_0 for a ByteString param, silently producing a
//! different script from the hex string the developer meant.
//!
//! Proves: `RunarContract::new` panics with the shared diagnostic for `Int`,
//! `BigInt`, `Bool`, `Auto`, `EmptySig`, and an `Array` for a non-FixedArray
//! param, and for an `Int` leaf inside an `Array` for a `FixedArray<Addr, 2>`.
//! Does NOT prove: width checks, method-call args or on-chain spendability.

use runar_lang::sdk::types::{RunarArtifact, SdkValue};
use runar_lang::sdk::RunarContract;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn artifact(param_type: &str) -> RunarArtifact {
    serde_json::from_value(serde_json::json!({
        "version": "runar-v0.1.0",
        "compilerVersion": "0.1.0",
        "contractName": "N330",
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
fn non_bytes_bytestring_ctor_arg_is_refused_n330() {
    let args = vec![
        SdkValue::Int(5),
        SdkValue::BigInt(num_bigint::BigInt::from(5)),
        SdkValue::Bool(true),
        SdkValue::Auto,
        SdkValue::EmptySig,
        SdkValue::Array(vec![SdkValue::Bytes("aabb".into())]),
    ];
    for arg in args {
        let err = construct("ByteString", arg.clone())
            .err()
            .unwrap_or_else(|| panic!("{:?} must be refused", arg));
        assert_eq!(
            err,
            "RunarContract: constructor arg 'owner' (ByteString) of N330 must be an even-length hex string"
        );
    }
}

#[test]
fn non_bytes_fixed_array_leaf_is_refused_n330() {
    let arg = SdkValue::Array(vec![SdkValue::Bytes("aabb".into()), SdkValue::Int(7)]);
    assert!(construct("FixedArray<Addr, 2>", arg).is_err());
}
