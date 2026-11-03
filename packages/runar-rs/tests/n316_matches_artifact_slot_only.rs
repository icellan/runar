//! N-316: `matches_artifact` must treat codeSepIndexSlots and codePartLenSlots
//! as variable script elements even when `constructorSlots` is empty.
//!
//! Replays the shared cross-tier fixture
//! `conformance/sdk-matches-artifact/fixtures.json` (also replayed by the TS,
//! Go, Python, Zig, Ruby and Java SDKs). Its first artifact is real compiler
//! output for a stateful contract with no constructor args.
//!
//! Proves: an honest deployment of such an artifact matches it, and a script
//! differing in one code byte before/after the slot does not.
//! Does NOT prove: on-chain spendability, or slot layouts beyond the fixture.

use runar_lang::sdk::matches_artifact;
use runar_lang::sdk::types::RunarArtifact;
use serde_json::Value;
use std::path::PathBuf;

#[test]
fn matches_artifact_slot_only_artifacts_n316() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../conformance/sdk-matches-artifact/fixtures.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(p).expect("read fixture")).expect("parse fixture");
    let cases = fixture["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let artifact: RunarArtifact = serde_json::from_value(c["artifact"].clone()).expect("artifact");
        let got = matches_artifact(&artifact, c["script_hex"].as_str().unwrap()).expect(name);
        assert_eq!(got, c["expected"].as_bool().unwrap(), "case {}", name);
    }
}
