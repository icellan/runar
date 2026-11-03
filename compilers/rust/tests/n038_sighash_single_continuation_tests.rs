//! N-038 (R64): a stateful `@sighash SINGLE|FORKID` method's continuation
//! hashes only the method's own output (BIP-143 SINGLE commits hashOutputs to
//! hash256(output[inputIndex]) alone) and declares no `_changePKH` /
//! `_changeAmount`.
//!
//! Proves the Rust tier's fold-OFF IR and script for the
//! N-038 contract are byte-identical to the TS-stamped sdk-call pins
//! (`conformance/sdk-call/expected-{ir.json,script.hex}`), that `bump`'s ABI params are exactly `[txPreimage]` while it stays
//! non-terminal, and that `reset` (default ALL|FORKID) keeps its change params.
//! Does not prove on-chain acceptance — that is the sdk-call vector Spend
//! replay (`conformance/sdk-call/sdk-call.test.ts`).

use runar_compiler_rust::{
    compile_from_source_str_with_options, compile_source_str_to_ir_with_options, CompileOptions,
};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn canon(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().filter(|k| k.as_str() != "sourceLoc").collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canon(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canon).collect()),
        other => other.clone(),
    }
}

#[test]
fn n038_sighash_single_stateful_matches_golden_and_drops_change_params() {
    let src_path = root().join("conformance/sdk-call/SingleCounter.runar.ts");
    let fixture = root().join("conformance/sdk-call");
    let source = fs::read_to_string(&src_path).unwrap();
    let opts = CompileOptions { disable_constant_folding: true, ..Default::default() };

    let anf = compile_source_str_to_ir_with_options(&source, Some("SingleCounter.runar.ts"), &opts).unwrap();
    let got_ir = canon(&serde_json::to_value(&anf).unwrap());
    let want_ir: Value = serde_json::from_str(&fs::read_to_string(fixture.join("expected-ir.json")).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_string_pretty(&got_ir).unwrap(),
        serde_json::to_string_pretty(&canon(&want_ir)).unwrap(),
        "IR differs from the golden"
    );

    let art = compile_from_source_str_with_options(&source, Some("SingleCounter.runar.ts"), &opts).unwrap();
    let want_hex: String = fs::read_to_string(fixture.join("expected-script.hex"))
        .unwrap()
        .split_whitespace()
        .collect::<String>()
        .to_lowercase();
    assert_eq!(art.script, want_hex, "script differs from the golden");

    for m in &art.abi.methods {
        let names: Vec<&str> = m.params.iter().map(|p| p.name.as_str()).collect();
        match m.name.as_str() {
            "bump" => {
                assert_eq!(names, vec!["txPreimage"], "bump params");
                assert_ne!(m.is_terminal, Some(true), "bump must stay non-terminal");
            }
            "reset" => assert_eq!(
                names,
                vec!["_changePKH", "_changeAmount", "_newAmount", "txPreimage"],
                "reset params"
            ),
            _ => {}
        }
    }
}
