//! D25 — the contract-level continuation binding (frontend/continuation_binding.rs):
//! classification, the SINGLE default, the hidden spent-outpoint field, the
//! diagnostics, and the `--ir` check. Port of the TS reference
//! packages/runar-compiler/src/__tests__/d25-continuation-binding.test.ts.
//! The executed twin-input refusal lives in the runar-rs SDK
//! (packages/runar-rs/tests/d25_twin_input_tests.rs).

use runar_compiler_rust::{compile_from_ir_str, compile_from_source_str_with_result, CompileOptions, CompileResult};
use serde_json::Value;
use std::collections::HashSet;

const FIELD: &str = "_spentOutpointHash";

const STATEFUL: &str = "import { StatefulSmartContract, assert, checkSig, extractAmount, extractOutputHash, hash256 } from 'runar-lang';
import type { PubKey, Sig, Sha256 } from 'runar-lang';
";

fn counter(inc: &str, dec: &str) -> String {
    format!(
        "{STATEFUL}
class Counter extends StatefulSmartContract {{
  count: bigint;
  constructor(count: bigint) {{ super(count); this.count = count; }}
  {inc}
  public increment() {{ this.count++; }}
  {dec}
  public decrement() {{ assert(this.count > 0n); this.count--; }}
}}"
    )
}

fn mixed() -> String {
    format!(
        "{STATEFUL}
class MixedPot extends StatefulSmartContract {{
  count: bigint;
  constructor(count: bigint) {{ super(count); this.count = count; }}
  public increment() {{ this.count++; }}
  public bump() {{ this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }}
}}"
    )
}

fn compile(src: &str, name: &str) -> CompileResult {
    compile_from_source_str_with_result(src, Some(&format!("{name}.runar.ts")), &CompileOptions::default())
}

fn ok(src: &str, name: &str) -> CompileResult {
    let r = compile(src, name);
    if !r.success {
        let msgs: Vec<String> = r.diagnostics.iter().map(|d| d.message.clone()).collect();
        panic!("compile failed: {}", msgs.join("; "));
    }
    r
}

fn abi_mode(r: &CompileResult, m: &str) -> Option<i64> {
    r.artifact.as_ref().unwrap().abi.methods.iter().find(|x| x.name == m).unwrap().sig_hash_type
}

fn state_fields(r: &CompileResult) -> Vec<String> {
    r.artifact.as_ref().unwrap().state_fields.iter().map(|f| f.name.clone()).collect()
}

fn warnings_with(r: &CompileResult, needle: &str) -> usize {
    r.diagnostics
        .iter()
        .filter(|d| matches!(d.severity, runar_compiler_rust::frontend::diagnostic::Severity::Warning))
        .filter(|d| d.message.contains(needle))
        .count()
}

fn anf_json(r: &CompileResult) -> Value {
    serde_json::to_value(r.anf.as_ref().unwrap()).unwrap()
}

/// Every binding object (pre-order) at any depth of `bindings`.
fn walk<'a>(bindings: &'a Value, out: &mut Vec<&'a Value>) {
    for b in bindings.as_array().unwrap() {
        out.push(b);
        for k in ["then", "else", "body"] {
            if let Some(n) = b["value"].get(k) {
                if n.is_array() {
                    walk(n, out);
                }
            }
        }
    }
}

fn walk_mut(bindings: &mut Value, f: &mut dyn FnMut(&mut Value)) {
    for b in bindings.as_array_mut().unwrap() {
        f(b);
        for k in ["then", "else", "body"] {
            if let Some(n) = b["value"].get_mut(k) {
                if n.is_array() {
                    walk_mut(n, f);
                }
            }
        }
    }
}

fn method<'a>(p: &'a Value, name: &str) -> &'a Value {
    p["methods"].as_array().unwrap().iter().find(|m| m["name"] == name).unwrap()
}

fn method_mut<'a>(p: &'a mut Value, name: &str) -> &'a mut Value {
    p["methods"].as_array_mut().unwrap().iter_mut().find(|m| m["name"] == name).unwrap()
}

fn compile_ir(p: &Value) -> Result<(), String> {
    compile_from_ir_str(&serde_json::to_string(p).unwrap()).map(|_| ())
}

// ---- class 1 -------------------------------------------------------------

#[test]
fn class1_defaults_every_continuation_method_to_single_forkid_and_drops_change_params() {
    let r = ok(&counter("", ""), "Counter");
    assert_eq!(abi_mode(&r, "increment"), Some(0x43));
    assert_eq!(abi_mode(&r, "decrement"), Some(0x43));
    assert_eq!(state_fields(&r), vec!["count"]);
    let inc = r.artifact.as_ref().unwrap().abi.methods.iter().find(|m| m.name == "increment").unwrap();
    let params: Vec<&str> = inc.params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(params, vec!["_newAmount", "txPreimage"]);
}

#[test]
fn class1_maps_all_acp_forkid_to_single_acp_forkid() {
    let d = "/** @sighash ALL|ANYONECANPAY|FORKID */";
    let r = ok(&counter(d, d), "Counter");
    assert_eq!(abi_mode(&r, "increment"), Some(0xc3));
}

#[test]
fn class1_keeps_an_explicit_single_acp_forkid() {
    let d = "/** @sighash SINGLE|ANYONECANPAY|FORKID */";
    assert_eq!(abi_mode(&ok(&counter(d, ""), "Counter"), "increment"), Some(0xc3));
}

#[test]
fn class1_refuses_an_explicit_all_forkid_sibling() {
    let r = compile(&counter("", "/** @sighash ALL|FORKID */"), "Counter");
    assert!(!r.success);
    assert!(r.diagnostics.iter().any(|d| {
        matches!(d.severity, runar_compiler_rust::frontend::diagnostic::Severity::Error)
            && d.message.contains("method 'decrement': @sighash ALL|FORKID")
    }));
}

#[test]
fn class1_terminal_method_keeps_all() {
    let src = format!(
        "{STATEFUL}
class Box extends StatefulSmartContract {{
  count: bigint;
  readonly owner: PubKey;
  constructor(count: bigint, owner: PubKey) {{ super(count, owner); this.count = count; this.owner = owner; }}
  public bump() {{ this.count++; }}
  public close(sig: Sig) {{ assert(checkSig(sig, this.owner)); }}
}}"
    );
    let r = ok(&src, "Box");
    assert_eq!(abi_mode(&r, "bump"), Some(0x43));
    assert_eq!(abi_mode(&r, "close"), None);
}

// ---- class 2 -------------------------------------------------------------

#[test]
fn class2_appends_zero_initialised_sha256_field_last_outside_constructor_abi() {
    let r = ok(&mixed(), "MixedPot");
    assert_eq!(state_fields(&r), vec!["count", FIELD]);
    let ctor: Vec<String> =
        r.artifact.as_ref().unwrap().abi.constructor.params.iter().map(|p| p.name.clone()).collect();
    assert_eq!(ctor, vec!["count"]);
    let prop = r.anf.as_ref().unwrap().properties.iter().find(|p| p.name == FIELD).unwrap();
    assert_eq!(prop.prop_type, "Sha256");
    assert_eq!(prop.initial_value, Some(Value::String("00".repeat(32))));
    assert_eq!(abi_mode(&r, "increment"), None);
    assert_eq!(abi_mode(&r, "bump"), None);
}

#[test]
fn class2_writes_outpoint_hash_in_auto_continuation_and_appends_it_to_add_output() {
    let r = ok(&mixed(), "MixedPot");
    let p = anf_json(&r);
    let mut inc = Vec::new();
    walk(&method(&p, "increment")["body"], &mut inc);
    assert!(inc.iter().any(|b| b["value"]["kind"] == "update_prop" && b["value"]["name"] == FIELD));
    let mut bump = Vec::new();
    walk(&method(&p, "bump")["body"], &mut bump);
    let outs: Vec<&&Value> = bump.iter().filter(|b| b["value"]["kind"] == "add_output").collect();
    assert_eq!(outs.len(), 1);
    assert_eq!(outs[0]["value"]["stateValues"].as_array().unwrap().len(), 2);
}

#[test]
fn class2_mutate_only_reading_extract_output_hash_is_bound() {
    let src = format!(
        "{STATEFUL}
class Peek extends StatefulSmartContract {{
  count: bigint;
  constructor(count: bigint) {{ super(count); this.count = count; }}
  public bump(h: Sha256) {{ assert(extractOutputHash(this.txPreimage) !== h); this.count++; }}
}}"
    );
    let r = ok(&src, "Peek");
    assert_eq!(abi_mode(&r, "bump"), None);
    assert_eq!(state_fields(&r), vec!["count", FIELD]);
}

#[test]
fn class2_field_name_is_reserved() {
    let src = format!(
        "{STATEFUL}
class X extends StatefulSmartContract {{
  _spentOutpointHash: bigint;
  constructor(_spentOutpointHash: bigint) {{ super(_spentOutpointHash); this._spentOutpointHash = _spentOutpointHash; }}
  public bump() {{ this._spentOutpointHash++; }}
}}"
    );
    let r = compile(&src, "X");
    assert!(!r.success);
    assert!(r.diagnostics.iter().any(|d| d.message.contains("'_spentOutpointHash' is reserved")));
}

// ---- class 3 -------------------------------------------------------------

fn pot(body: &str) -> String {
    format!(
        "{STATEFUL}
class Pot extends StatefulSmartContract {{
  count: bigint;
  readonly owner: PubKey;
  constructor(count: bigint, owner: PubKey) {{ super(count, owner); this.count = count; this.owner = owner; }}
  public bump(sig: Sig) {{ {body} }}
}}"
    )
}

#[test]
fn class3_warns_on_unsigned_add_output_extract_amount() {
    let r = ok(&pot("this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot");
    assert_eq!(warnings_with(&r, "twin-input aliasing"), 1);
    assert_eq!(state_fields(&r), vec!["count"]);
    assert_eq!(abi_mode(&r, "bump"), None);
}

#[test]
fn class3_follows_a_local_initialised_from_extract_amount() {
    let r = ok(
        &pot("const v: bigint = extractAmount(this.txPreimage); this.addOutput(v, this.count + 1n);"),
        "Pot",
    );
    assert_eq!(warnings_with(&r, "twin-input aliasing"), 1);
}

#[test]
fn class3_no_warning_when_the_method_checks_a_signature() {
    let r = ok(
        &pot("assert(checkSig(sig, this.owner)); this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"),
        "Pot",
    );
    assert_eq!(warnings_with(&r, "twin-input aliasing"), 0);
}

// ---- --ir check ----------------------------------------------------------

#[test]
fn ir_accepts_the_frontend_ir_of_every_class() {
    compile_ir(&anf_json(&ok(&counter("", ""), "Counter"))).unwrap();
    compile_ir(&anf_json(&ok(&mixed(), "MixedPot"))).unwrap();
}

#[test]
fn ir_refuses_a_mutate_only_program_whose_continuation_commits_under_all() {
    let mut p = anf_json(&ok(&counter("", ""), "Counter"));
    method_mut(&mut p, "decrement").as_object_mut().unwrap().remove("sigHashType");
    let err = compile_ir(&p).unwrap_err();
    assert!(err.contains("IR validation"), "{err}");
}

#[test]
fn ir_refuses_a_mixed_program_without_the_binding_field() {
    let mut p = anf_json(&ok(&mixed(), "MixedPot"));
    p["properties"].as_array_mut().unwrap().retain(|x| x["name"] != FIELD);
    for m in p["methods"].as_array_mut().unwrap() {
        let mut drop: Vec<String> = Vec::new();
        walk_mut(&mut m["body"], &mut |b| {
            if b["value"]["kind"] == "update_prop" && b["value"]["name"] == FIELD {
                drop.push(b["name"].as_str().unwrap().to_string());
            }
            if b["value"]["kind"] == "add_output" {
                let h = b["value"]["stateValues"].as_array_mut().unwrap().pop().unwrap();
                drop.push(h.as_str().unwrap().to_string());
            }
        });
        let mut all = Vec::new();
        walk(&m["body"], &mut all);
        let by_name = |n: &str| all.iter().find(|b| b["name"] == n).map(|b| b["value"].clone()).unwrap();
        let mut set: HashSet<String> = drop.iter().cloned().collect();
        for n in &drop {
            let v = by_name(n);
            let src = if v["kind"] == "update_prop" { v["value"].as_str().unwrap().to_string() } else { n.clone() };
            let sha = by_name(&src);
            let sha_arg = sha["args"][0].as_str().unwrap().to_string();
            let eo = by_name(&sha_arg);
            set.insert(src);
            set.insert(sha_arg);
            set.insert(eo["args"][0].as_str().unwrap().to_string());
        }
        m["body"].as_array_mut().unwrap().retain(|b| !set.contains(b["name"].as_str().unwrap()));
    }
    let err = compile_ir(&p).unwrap_err();
    assert!(err.contains("not bound to its input"), "{err}");
}

#[test]
fn ir_refuses_an_add_output_whose_last_state_value_is_not_the_outpoint_hash() {
    let mut p = anf_json(&ok(&mixed(), "MixedPot"));
    walk_mut(&mut method_mut(&mut p, "bump")["body"], &mut |b| {
        if b["value"]["kind"] == "add_output" {
            let first = b["value"]["stateValues"][0].clone();
            b["value"]["stateValues"][1] = first;
        }
    });
    let err = compile_ir(&p).unwrap_err();
    assert!(err.contains("every add_output must carry"), "{err}");
}

#[test]
fn ir_refuses_a_binding_field_that_is_not_last_or_not_zero() {
    let mut p = anf_json(&ok(&mixed(), "MixedPot"));
    let props = p["properties"].as_array_mut().unwrap();
    let last = props.len() - 1;
    props[last]["initialValue"] = Value::String("11".repeat(32));
    let err = compile_ir(&p).unwrap_err();
    assert!(err.contains("must be the last property"), "{err}");
}

#[test]
fn diagnostics_match_the_ts_reference_verbatim() {
    use runar_compiler_rust::frontend::continuation_binding::{explicit_all_sibling_message, unsigned_add_output_message};
    assert_eq!(
        explicit_all_sibling_message("M"),
        "method 'M': @sighash ALL|FORKID on a state-continuation method of a contract whose continuation methods are all mutate-only reopens twin-input theft: such a contract commits each continuation under SIGHASH_SINGLE (one output per input), and one ALL method lets its input reuse a sibling's output while its own value leaves as change. Remove the directive (the default is SINGLE|FORKID) or write @sighash SINGLE|FORKID"
    );
    assert_eq!(
        unsigned_add_output_message("M"),
        "method 'M' re-creates the contract with addOutput(extractAmount(...), ...) and checks no signature: two UTXOs of this contract spent in one transaction that reach the same state are both satisfied by ONE such output, and the other input's value leaves as anyone's change (twin-input aliasing). A method that sizes its own outputs is not bound to its input; require a signature, or let the compiler size the continuation (write state instead of calling addOutput)"
    );
}
