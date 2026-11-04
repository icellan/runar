//! N-051 (TaffyTail), SDK side — deploy-time `codePartLenSlots`.
//!
//! The compiler now always pins `SIZE(_codePart)` with OP_NUMEQUAL. When a
//! readonly constructor arg of variable width is baked into the code, it cannot
//! know the deployed length, so it records the pin's 4-byte little-endian
//! length field as a `codePartLenSlots` entry and the SDK writes the real
//! deployed code-part length (inscription envelope included) into it.
//!
//! Reference data is the TS-compiled artifact (fold OFF) and the TS SDK's
//! build of it (tests/fixtures/n051-taffytail-vault-*.json). The on-chain proof
//! (strict @bsv/sdk Spend) is
//! packages/runar-testing/src/__tests__/n051-codepart-length-exact-spend.test.ts.

use std::panic::{catch_unwind, AssertUnwindSafe};

use runar_lang::sdk::types::{CodePartLenSlot, DeployOptions, RunarArtifact};
use runar_lang::sdk::{matches_artifact, Inscription, MockProvider, MockSigner, RunarContract, SdkValue};

const ARTIFACT_JSON: &str = include_str!("fixtures/n051-taffytail-vault-artifact.json");
const EXPECTED_JSON: &str = include_str!("fixtures/n051-taffytail-vault-expected.json");

const TAFFYTAIL_SRC: &str = r#"import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

class TaffyTailVault extends StatefulSmartContract {
  message: ByteString;
  readonly tag: ByteString;
  readonly owner: PubKey;

  constructor(message: ByteString, tag: ByteString, owner: PubKey) {
    super(message, tag, owner);
    this.message = message;
    this.tag = tag;
    this.owner = owner;
  }

  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }

  public post(next: ByteString, claimedTag: ByteString) {
    assert(claimedTag === this.tag);
    this.addOutput(extractAmount(this.txPreimage), next);
  }
}
"#;

/// Same variable-length state, but every baked readonly arg is fixed-width:
/// the pin is exact at compile time and carries no slot.
const FIXED_WIDTH_SRC: &str = r#"import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

class FixedWidthVault extends StatefulSmartContract {
  message: ByteString;
  readonly owner: PubKey;

  constructor(message: ByteString, owner: PubKey) {
    super(message, owner);
    this.message = message;
    this.owner = owner;
  }

  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }

  public post(next: ByteString) {
    this.addOutput(extractAmount(this.txPreimage), next);
  }
}
"#;

fn expected() -> serde_json::Value {
    serde_json::from_str(EXPECTED_JSON).unwrap()
}

fn artifact() -> RunarArtifact {
    serde_json::from_str(ARTIFACT_JSON).expect("reference artifact parses")
}

fn args() -> Vec<SdkValue> {
    expected()["constructorArgs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| SdkValue::Bytes(v.as_str().unwrap().to_string()))
        .collect()
}

fn le32(n: usize) -> String {
    (0..4).map(|i| format!("{:02x}", (n >> (8 * i)) & 0xff)).collect()
}

fn panic_message<F: FnOnce() -> R, R>(f: F) -> Option<String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => None,
        Err(e) => Some(
            e.downcast_ref::<String>().cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default(),
        ),
    }
}

/// Hex offset of the pin's length field in the BUILT script: the slot offset
/// plus the growth of the one constructor slot before it (owner, 1 -> 34 bytes).
fn built_len_field_hex(a: &RunarArtifact) -> usize {
    let slot = a.code_part_len_slots.as_ref().expect("slots parsed")[0].byte_offset;
    (slot + 33) * 2
}

#[test]
fn n051_artifact_parses_code_part_len_slots() {
    let a = artifact();
    let slots = a.code_part_len_slots.as_ref().expect("codePartLenSlots parsed");
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].byte_offset, 947);
}

#[test]
fn n051_built_code_part_and_locking_script_match_ts_reference() {
    let e = expected();
    let contract = RunarContract::new(artifact(), args());
    let ls = contract.get_locking_script();
    assert_eq!(ls, e["lockingScriptHex"].as_str().unwrap(), "locking script differs from the TS SDK");
    let code_len = e["codePartLen"].as_u64().unwrap() as usize;
    assert_eq!(&ls[..code_len * 2], e["codePartHex"].as_str().unwrap());
    assert_eq!(&ls[code_len * 2..code_len * 2 + 2], "6a");
    let at = built_len_field_hex(&artifact());
    assert_eq!(&ls[at..at + 8], le32(code_len), "the pin must hold the deployed code-part length");
}

#[test]
fn n051_inscribed_code_part_matches_ts_reference_and_is_accepted() {
    let e = expected();
    let mut contract = RunarContract::new(artifact(), args());
    contract
        .with_inscription(Inscription {
            content_type: e["inscription"]["contentType"].as_str().unwrap().to_string(),
            data: e["inscription"]["data"].as_str().unwrap().to_string(),
        })
        .expect("a deploy-time pin is patched to the inscribed length, so the inscription is accepted");
    let ls = contract.get_locking_script();
    let len = e["inscribedCodePartLen"].as_u64().unwrap() as usize;
    assert_eq!(&ls[..len * 2], e["inscribedCodePartHex"].as_str().unwrap());
    assert_eq!(&ls[len * 2..len * 2 + 2], "6a");
    let at = built_len_field_hex(&artifact());
    assert_eq!(&ls[at..at + 8], le32(len));
}

#[test]
fn n051_exact_compile_time_pin_still_refuses_an_inscription() {
    let opts = runar_compiler_rust::CompileOptions {
        disable_constant_folding: true,
        ..Default::default()
    };
    let compiled = runar_compiler_rust::compile_from_source_str_with_options(
        FIXED_WIDTH_SRC, Some("FixedWidthVault.runar.ts"), &opts,
    )
    .expect("FixedWidthVault compiles");
    let a: RunarArtifact = serde_json::from_str(&serde_json::to_string(&compiled).unwrap()).unwrap();
    assert!(a.code_part_len_slots.as_ref().map_or(true, |s| s.is_empty()));
    let mut contract = RunarContract::new(
        a,
        vec![SdkValue::Bytes("00".into()), SdkValue::Bytes(format!("02{}", "11".repeat(32)))],
    );
    let err = contract
        .with_inscription(Inscription { content_type: "text/plain".into(), data: "6869".into() })
        .err()
        .expect("an exact compile-time pin cannot absorb an inscription");
    assert!(err.contains("pins SIZE(_codePart)"), "unexpected error: {err}");
    assert!(contract.inscription().is_none());
}

#[test]
fn n051_corrupted_slot_offset_is_refused() {
    let mut a = artifact();
    a.code_part_len_slots = Some(vec![CodePartLenSlot { byte_offset: 948 }]);

    let msg = panic_message(|| RunarContract::new(a.clone(), args()).get_locking_script());
    assert!(
        msg.as_deref().is_some_and(|m| m.contains("does not point at a verify_code_part_len length field")),
        "get_locking_script must refuse a mis-pointed slot: {msg:?}"
    );

    let mut contract = RunarContract::new(a, args());
    let mut provider = MockProvider::new("testnet");
    let err = contract
        .deploy(&mut provider, &MockSigner::new(), &DeployOptions { satoshis: 1000, ..Default::default() })
        .expect_err("deploy must refuse a mis-pointed slot");
    assert!(err.contains("does not point at a verify_code_part_len length field"), "unexpected error: {err}");
}

#[test]
fn n051_matches_artifact_checks_the_deployed_length_field() {
    let a = artifact();
    let ls = RunarContract::new(a.clone(), args()).get_locking_script();
    assert!(matches_artifact(&a, &ls).unwrap(), "the deployed script must match its artifact");

    let at = built_len_field_hex(&a);
    let code_len = expected()["codePartLen"].as_u64().unwrap() as usize;
    for wrong in [code_len - 1, code_len + 1, 1338 /* the template's compile-time value */] {
        let tampered = format!("{}{}{}", &ls[..at], le32(wrong), &ls[at + 8..]);
        assert!(!matches_artifact(&a, &tampered).unwrap(), "length field {wrong} must not match");
    }

    // A trailing segment of a different length must not match either.
    let op_return = code_len * 2;
    let extended = format!("{}51{}", &ls[..op_return], &ls[op_return..]);
    assert!(!matches_artifact(&a, &extended).unwrap());
}

#[test]
fn n051_rust_compiler_matches_ts_reference_artifact() {
    let opts = runar_compiler_rust::CompileOptions {
        disable_constant_folding: true,
        ..Default::default()
    };
    let compiled = runar_compiler_rust::compile_from_source_str_with_options(
        TAFFYTAIL_SRC, Some("TaffyTailVault.runar.ts"), &opts,
    )
    .expect("TaffyTailVault compiles");
    let reference: serde_json::Value = serde_json::from_str(ARTIFACT_JSON).unwrap();
    assert_eq!(compiled.script, reference["script"].as_str().unwrap(), "script differs from TS");
    let ours: serde_json::Value = serde_json::to_value(&compiled).unwrap();
    assert_eq!(ours["codePartLenSlots"], reference["codePartLenSlots"]);
}
