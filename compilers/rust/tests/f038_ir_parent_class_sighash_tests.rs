//! F-038 / F-065 / F-066 / F-070 / F-088 — `parentClass` (program) and a
//! method's non-default `sigHashType` are ANF wire data.
//!
//! Before: both were `#[serde(skip)]` carriers, so `--emit-ir` dropped them and
//! an `--ir` recompile produced an artifact with no `parentClass` and no
//! `abi.methods[].sigHashType` — same script, but the SDK then skipped the
//! issue-#44 subscript trim for a zero-mutable-field StatefulSmartContract and
//! built an ALL|FORKID preimage for a covenant asserting another mode.
//!
//! Proves: the emitted IR carries both keys (default ALL|FORKID omitted), and
//! the IR-compiled artifact equals the source-compiled one on script,
//! parentClass and abi. The loader's refusal of malformed values is pinned by
//! the shared corpus in `n069_ir_required_fields_tests.rs`.
//! Does not prove: other tiers (conformance/ir-roundtrip does that).

use runar_compiler_rust::{compile_from_ir_str, compile_from_source_str, compile_source_str_to_ir};
use serde_json::Value;

const ZERO_MUTABLE: &str = r#"import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

class AllReadonly extends StatefulSmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public claim(sig: Sig): void {
    assert(checkSig(sig, this.owner));
  }
}
"#;

const SIGHASH_COUNTER: &str = r#"import { StatefulSmartContract, assert } from 'runar-lang';

class SighashCounter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  /** @sighash ALL|ANYONECANPAY|FORKID */
  public increment(): void {
    this.count = this.count + 1n;
    assert(true);
  }

  /** @sighash ALL|FORKID */
  public bump(): void {
    this.count = this.count + 2n;
    assert(true);
  }
}
"#;

fn emit_ir(src: &str, name: &str) -> (String, Value) {
    let program = compile_source_str_to_ir(src, Some(name)).expect("source -> IR");
    let json = serde_json::to_string_pretty(&program).unwrap();
    let v: Value = serde_json::from_str(&json).unwrap();
    (json, v)
}

fn method<'a>(ir: &'a Value, name: &str) -> &'a Value {
    ir["methods"].as_array().unwrap().iter().find(|m| m["name"] == name).unwrap()
}

#[test]
fn f038_emitted_ir_carries_parent_class() {
    let (_, ir) = emit_ir(ZERO_MUTABLE, "AllReadonly.runar.ts");
    assert_eq!(ir["parentClass"], "StatefulSmartContract");
}

#[test]
fn f065_emitted_ir_carries_non_default_sighash_only() {
    let (_, ir) = emit_ir(SIGHASH_COUNTER, "SighashCounter.runar.ts");
    assert_eq!(method(&ir, "increment")["sigHashType"], 0xc1);
    // Explicit ALL|FORKID is the default: omitted, like no directive at all.
    assert!(method(&ir, "bump").get("sigHashType").is_none());
    assert!(method(&ir, "constructor").get("sigHashType").is_none());
}

#[test]
fn f038_ir_artifact_matches_source_artifact() {
    for (src, name) in [(ZERO_MUTABLE, "AllReadonly.runar.ts"), (SIGHASH_COUNTER, "SighashCounter.runar.ts")] {
        let direct = compile_from_source_str(src, Some(name)).expect("source compile");
        let (json, _) = emit_ir(src, name);
        let via_ir = compile_from_ir_str(&json).expect("IR compile");
        assert_eq!(direct.parent_class, "StatefulSmartContract", "{}", name);
        assert_eq!(via_ir.parent_class, direct.parent_class, "{}", name);
        assert_eq!(via_ir.script, direct.script, "{}", name);
        assert_eq!(
            serde_json::to_value(&via_ir.abi).unwrap(),
            serde_json::to_value(&direct.abi).unwrap(),
            "{}",
            name
        );
    }
    let direct = compile_from_source_str(SIGHASH_COUNTER, Some("SighashCounter.runar.ts")).unwrap();
    let inc = direct.abi.methods.iter().find(|m| m.name == "increment").unwrap();
    assert_eq!(inc.sig_hash_type, Some(0xc1));
}
