//! N-318: `matches_artifact` must check the VALUE at every codeSepIndex slot.
//! Deploy bakes encodeScriptNumber(codeSepIndex + shift) there (shift = growth
//! of every constructor slot, and every earlier codeSep slot, before
//! codeSepIndex); the matcher used to accept any element at the slot.
//!
//! Replays the shared cross-tier vector
//! `conformance/sdk-matches-artifact/codesep.json` (also replayed by the TS,
//! Go, Python, Zig, Ruby and Java SDKs): honest TS-SDK deployments of a real
//! compiled artifact and of a synthetic artifact whose baked values depend on
//! a variable-length constructor arg, plus forgeries differing only in the
//! number pushed at a codeSep slot.
//!
//! Proves: honest deployments match whatever the constructor-arg width, and a
//! forged separator index (OP_0, off by one, non-minimal, unshifted) does not.
//! Does NOT prove: on-chain spendability of the honest scripts.

use runar_lang::sdk::matches_artifact;
use runar_lang::sdk::types::RunarArtifact;
use serde_json::Value;
use std::path::PathBuf;

#[test]
fn matches_artifact_checks_codesep_value_n318() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../conformance/sdk-matches-artifact/codesep.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(p).expect("read fixture")).expect("parse fixture");
    let cases = fixture["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    let mut wrong = Vec::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let key = c["artifact"].as_str().unwrap();
        let artifact: RunarArtifact =
            serde_json::from_value(fixture["artifacts"][key].clone()).expect("artifact");
        let got = matches_artifact(&artifact, c["script_hex"].as_str().unwrap()).expect(name);
        if got != c["expected"].as_bool().unwrap() {
            wrong.push(format!("{} (got {})", name, got));
        }
    }
    assert!(wrong.is_empty(), "{} case(s) wrong: {:?}", wrong.len(), wrong);
}
