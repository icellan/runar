//! N-051 (TaffyTail) — the `SIZE(_codePart)` pin is always an equality.
//!
//! A stateful contract with a variable-length state section authenticates the
//! spender-supplied `_codePart` witness and pins its length with
//!
//! ```text
//! OP_DUP <04 LL LL LL LL> OP_BIN2NUM OP_NUMEQUAL OP_VERIFY
//! ```
//!
//! When a readonly constructor arg of variable width (ByteString, bigint) is
//! baked into the code, the compiler cannot know the deployed length. It used
//! to fall back to OP_GREATERTHANOREQUAL — a lower bound — and a stranger could
//! claim a truncated `_codePart` ending at a 0x6a byte inside the baked value,
//! planting attacker code in the continuation. The pin is now always
//! OP_NUMEQUAL; a length the compiler cannot know is recorded as a
//! `codePartLenSlots` entry that the SDK patches at deploy time.
//!
//! The on-chain proof (strict @bsv/sdk Spend) is
//! packages/runar-testing/src/__tests__/n051-codepart-length-exact-spend.test.ts.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

/// The reference contract: `tag` is a readonly ByteString baked into the code.
const TAFFYTAIL: &str = r#"import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
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

/// Control: same variable-length state, but every baked readonly arg is
/// fixed-width, so the deployed length is known at compile time.
const FIXED_WIDTH: &str = r#"import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
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

fn compile(src: &str, file: &str) -> (String, serde_json::Value, String) {
    let opts = CompileOptions { disable_constant_folding: true, ..CompileOptions::default() };
    let artifact = compile_from_source_str_with_options(src, Some(file), &opts)
        .unwrap_or_else(|e| panic!("{file} failed to compile: {e}"));
    let json = serde_json::to_string(&artifact).expect("serialize artifact");
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    (artifact.script.clone(), value, json)
}

/// Byte offsets (of the `04` push opcode) of every
/// `76 04 <4 bytes> 81 <cmp> 69` pin in the script, with its comparison opcode.
fn pins(script: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 18 <= script.len() {
        let s = &script[i..i + 18];
        if &s[0..4] == "7604" && &s[12..14] == "81" && &s[16..18] == "69" {
            out.push((i / 2 + 1, s[14..16].to_string()));
        }
        i += 2;
    }
    out
}

#[test]
fn n051_variable_width_pin_is_an_equality_with_a_deploy_time_slot() {
    let (script, value, _) = compile(TAFFYTAIL, "TaffyTailVault.runar.ts");
    let found = pins(&script);
    assert_eq!(found.len(), 1, "expected exactly one verify_code_part_len pin, got {found:?}");
    let (push_at, cmp) = &found[0];
    assert_eq!(cmp, "9c", "the pin must compare with OP_NUMEQUAL, never OP_GREATERTHANOREQUAL");
    assert!(
        pins(&script).iter().all(|(_, c)| c != "a2"),
        "no lower-bound (81 a2 69) pin may remain"
    );
    // The slot names the first of the 4 length bytes: the byte after `04`.
    assert_eq!(
        value["codePartLenSlots"],
        serde_json::json!([{ "byteOffset": push_at + 1 }]),
        "codePartLenSlots must record the pin's length field"
    );
    // Same layout as the TS reference artifact (fold OFF).
    assert_eq!(push_at + 1, 959);
}

#[test]
fn n051_code_part_len_slots_serialize_right_after_code_sep_index_slots() {
    let (_, _, json) = compile(TAFFYTAIL, "TaffyTailVault.runar.ts");
    let sep = json.find("\"codeSepIndexSlots\"").expect("codeSepIndexSlots present");
    // codeSepIndexSlots holds flat objects, so the first `]` closes it.
    let close = sep + json[sep..].find(']').expect("codeSepIndexSlots array closes");
    assert!(
        json[close + 1..].starts_with(",\"codePartLenSlots\":"),
        "codePartLenSlots must be serialized immediately after codeSepIndexSlots: {}",
        &json[sep..(close + 40).min(json.len())]
    );
    // Each entry carries exactly one key.
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    for e in v["codePartLenSlots"].as_array().unwrap() {
        assert_eq!(e.as_object().unwrap().len(), 1, "entry {e} must carry only byteOffset");
    }
}

#[test]
fn n051_fixed_width_contract_keeps_an_exact_pin_and_no_slot() {
    let (script, value, _) = compile(FIXED_WIDTH, "FixedWidthVault.runar.ts");
    let found = pins(&script);
    assert_eq!(found.len(), 1, "expected exactly one verify_code_part_len pin, got {found:?}");
    assert_eq!(found[0].1, "9c");
    assert!(
        value.get("codePartLenSlots").is_none(),
        "an exact pin needs no deploy-time slot; codePartLenSlots must be omitted"
    );
}
