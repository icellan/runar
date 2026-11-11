//! `matches_artifact` must check what sits at each constructor slot, not only
//! the template bytes between slots: a push or small-integer opcode, the same
//! bytes at every reference of one param, and exactly `fixedValueByteLength`
//! bytes where the slot declares it. A stateful artifact's script must carry
//! an OP_RETURN after its code part.
//!
//! Replays the shared cross-tier vector
//! `conformance/sdk-matches-artifact/slot-values.json` (also replayed by the
//! TS, Go, Python, Zig, Ruby and Java SDKs), plus the TS unit cases for hex
//! case, `extract_constructor_args` refusing a non-push opcode, and
//! `extract_constructor_args` after a codeSepIndex slot wider than one byte.
//!
//! Proves: honest deployments match; the forgeries in the vector do not;
//! `extract_constructor_args` errs on a non-push opcode at any reference of a
//! param and reads an arg after a wide codeSep slot from its deployed position.
//! Does NOT prove: that a slot push is minimally encoded, nor anything about
//! the length of the state after the OP_RETURN.

use runar_lang::sdk::script_utils::extract_constructor_args;
use runar_lang::sdk::matches_artifact;
use runar_lang::sdk::types::{RunarArtifact, SdkValue};
use serde_json::{json, Value};
use std::path::PathBuf;

const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn fixture() -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../conformance/sdk-matches-artifact/slot-values.json");
    serde_json::from_slice(&std::fs::read(p).expect("read fixture")).expect("parse fixture")
}

fn artifact(fx: &Value, key: &str) -> RunarArtifact {
    serde_json::from_value(fx["artifacts"][key].clone()).expect("artifact")
}

#[test]
fn matches_artifact_slot_values_vector() {
    let fx = fixture();
    let cases = fx["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    let mut wrong = Vec::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let art = artifact(&fx, c["artifact"].as_str().unwrap());
        let got = matches_artifact(&art, c["script_hex"].as_str().unwrap()).expect(name);
        if got != c["expected"].as_bool().unwrap() {
            wrong.push(format!("{} (got {})", name, got));
        }
    }
    assert!(wrong.is_empty(), "{} of {} case(s) wrong: {:?}", wrong.len(), cases.len(), wrong);
}

#[test]
fn matches_artifact_slot_values_ignore_hex_case() {
    let fx = fixture();
    let owner2 = artifact(&fx, "owner2");
    let script = format!("21{}ad21{}ac", G, G.to_uppercase());
    assert!(matches_artifact(&owner2, &script).unwrap());
}

#[test]
fn extract_constructor_args_refuses_non_push_at_slot() {
    let fx = fixture();
    let owner2 = artifact(&fx, "owner2");
    let slot_matrix = artifact(&fx, "slotMatrix");
    let cases = [
        ("first reference", &owner2, format!("acad21{}ac", G)),
        ("later reference", &owner2, format!("21{}adacac", G)),
        ("SlotMatrix", &slot_matrix, format!("ac7b8801117c9dac21{}87916921{}ac", G, G)),
    ];
    let mut wrong = Vec::new();
    for (name, art, script) in cases.iter() {
        if extract_constructor_args(art, script).is_ok() {
            wrong.push(*name);
        }
    }
    assert!(wrong.is_empty(), "accepted a non-push opcode: {:?}", wrong);
}

#[test]
fn extract_constructor_args_honest_deployments() {
    let fx = fixture();
    let slot_matrix = artifact(&fx, "slotMatrix");
    let owner2 = artifact(&fx, "owner2");
    for c in fx["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let script = c["script_hex"].as_str().unwrap();
        if c["expected"].as_bool().unwrap() && c["artifact"] == "slotMatrix" {
            let args = extract_constructor_args(&slot_matrix, script).expect(name);
            assert_eq!(args["count"], SdkValue::Int(17), "{}", name);
            assert_eq!(args["owner"], SdkValue::Bytes(G.to_string()), "{}", name);
        }
        if name == "owner2-honest" {
            let args = extract_constructor_args(&owner2, script).expect(name);
            assert_eq!(args.len(), 1);
            assert_eq!(args["owner"], SdkValue::Bytes(G.to_string()));
        }
    }
}

#[test]
fn extract_constructor_args_after_wide_codesep_slot() {
    // Hand-built: a codeSepIndex slot at byte 1 with codeSepIndex 140, baked
    // as 143 (`02 8f00`), then a constructor slot at byte 3. Script pinned by
    // the TS SDK's RunarContract.getLockingScript().
    let art: RunarArtifact = serde_json::from_value(json!({
        "version": "runar-v1.0.0-rc.1",
        "compilerVersion": "1.0.0-rc.1",
        "contractName": "CodeSepBeforeSlot",
        "abi": { "constructor": { "params": [{ "name": "x", "type": "ByteString" }] }, "methods": [] },
        "script": "5100520053",
        "constructorSlots": [{ "paramIndex": 0, "byteOffset": 3 }],
        "codeSepIndexSlots": [{ "byteOffset": 1, "codeSepIndex": 140 }]
    }))
    .expect("artifact");
    let script = "51028f005203aabbcc53";
    assert!(matches_artifact(&art, script).unwrap());
    let args = extract_constructor_args(&art, script).expect("extract");
    assert_eq!(args.len(), 1);
    assert_eq!(args["x"], SdkValue::Bytes("aabbcc".to_string()));
}
