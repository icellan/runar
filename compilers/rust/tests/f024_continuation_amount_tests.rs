//! F-024 (CL-BUG-079, user decision R14) — Rust-tier port of
//! packages/runar-compiler/src/__tests__/f024-continuation-amount.test.ts.
//!
//! Proves (Rust tier, TS surface): every default single-output continuation
//! carries the injected `assert(_newAmount >= extractAmount(txPreimage))` ANF
//! (load_param txPreimage; call extractAmount; load_param _newAmount;
//! bin_op >=; assert) after the body; addOutput and terminal methods do not;
//! `continuationAmount()` lowers to load_param _newAmount where that witness
//! exists and is refused everywhere else; a write to it is refused.
//! Does NOT prove on-chain rejection of a drain (the TS Spend test does) or
//! cross-tier byte parity (conformance).

use runar_compiler_rust::compile_source_str_to_ir;
use runar_compiler_rust::ir::{ANFBinding, ANFMethod, ANFProgram, ANFValue};

const COUNTER: &str = r#"
class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count = this.count + 1n; }
  public addTo(amount: bigint) { this.addOutput(1000n, this.count + amount); }
  public close() { assert(this.count > 0n); }
  public log(payload: ByteString) { this.addDataOutput(0n, payload); }
}
"#;

const READ_ONLY: &str = "continuationAmount() is read-only and cannot be assigned";
const UNAVAILABLE: &str = "continuationAmount() is only available in a public StatefulSmartContract method whose state continues through the default single-output continuation";

fn pot(body: &str) -> String {
    format!(
        "class Pot extends StatefulSmartContract {{\n  count: bigint;\n  constructor(count: bigint) {{ super(count); this.count = count; }}\n  {}\n}}\n",
        body
    )
}

fn lower(src: &str) -> Result<ANFProgram, String> {
    compile_source_str_to_ir(src, Some("C.runar.ts"))
}

fn public_method<'a>(p: &'a ANFProgram, name: &str) -> &'a ANFMethod {
    p.methods
        .iter()
        .find(|m| m.name == name && m.is_public)
        .unwrap_or_else(|| panic!("no public method {}", name))
}

fn kinds(body: &[ANFBinding]) -> Vec<String> {
    body.iter()
        .map(|b| match &b.value {
            ANFValue::Call { func, .. } => format!("call:{}", func),
            v => serde_json::to_value(v).unwrap()["kind"].as_str().unwrap().to_string(),
        })
        .collect()
}

fn injected_check_at(body: &[ANFBinding]) -> Vec<usize> {
    let mut hits = Vec::new();
    for i in 0..body.len().saturating_sub(4) {
        let w = &body[i..i + 5];
        let ok = matches!(&w[0].value, ANFValue::LoadParam { name } if name == "txPreimage")
            && matches!(&w[1].value, ANFValue::Call { func, args } if func == "extractAmount" && args.len() == 1 && args[0] == w[0].name)
            && matches!(&w[2].value, ANFValue::LoadParam { name } if name == "_newAmount")
            && matches!(&w[3].value, ANFValue::BinOp { op, left, right, .. } if op == ">=" && *left == w[2].name && *right == w[1].name)
            && matches!(&w[4].value, ANFValue::Assert { value, .. } if *value == w[3].name);
        if ok {
            hits.push(i);
        }
    }
    hits
}

#[test]
fn default_continuation_carries_the_value_check() {
    let p = lower(COUNTER).expect("compile");
    let body = &public_method(&p, "increment").body;
    let hits = injected_check_at(body);
    assert_eq!(hits.len(), 1, "want exactly one injected check: {:?}", kinds(body));
    let k = kinds(body);
    assert!(k[..hits[0]].contains(&"update_prop".to_string()), "check must follow the body: {:?}", k);
    for want in ["if", "get_state_script", "call:computeStateOutput"] {
        assert!(k[hits[0] + 5..].contains(&want.to_string()), "{} must follow the check: {:?}", want, k);
    }
    match &body[hits[0] + 4].value {
        ANFValue::Assert { is_auto_injected_state_check, .. } => assert!(!is_auto_injected_state_check),
        _ => unreachable!(),
    }
    assert_eq!(injected_check_at(&public_method(&p, "log").body).len(), 1, "data-output-only method");
    for name in ["addTo", "close"] {
        let m = public_method(&p, name);
        assert!(!m.params.iter().any(|x| x.name == "_newAmount"), "{} has _newAmount", name);
        assert!(!kinds(&m.body).contains(&"call:extractAmount".to_string()), "{} has the check", name);
    }
}

#[test]
fn continuation_amount_read_lowers_to_new_amount() {
    let p = lower(&pot(
        "public join(bet: bigint) {\n    assert(continuationAmount() == extractAmount(this.txPreimage) + bet);\n    this.count = this.count + 1n;\n  }",
    ))
    .expect("compile");
    let body = &public_method(&p, "join").body;
    let hits = injected_check_at(body);
    assert_eq!(hits.len(), 1);
    let first = body
        .iter()
        .position(|b| matches!(&b.value, ANFValue::LoadParam { name } if name == "_newAmount"))
        .expect("a load_param _newAmount");
    assert!(first < hits[0], "the author's read is its own load before the check");
}

#[test]
fn continuation_amount_refusals() {
    let stateless = "class P extends SmartContract {\n  readonly x: bigint;\n  constructor(x: bigint) { super(x); this.x = x; }\n  public unlock() { assert(continuationAmount() > this.x); }\n}\n".to_string();
    let cases: Vec<(&str, String, Option<&str>)> = vec![
        // A parser may refuse a call as an assignment target on its own; the
        // typecheck guard covers the ones that accept it. Either way: refused.
        ("write", pot("public join() { continuationAmount() = 5n; this.count = this.count + 1n; }"), None),
        // This tier's .runar.ts parser refuses `f()++` itself (TS2406).
        ("increment", pot("public join() { continuationAmount()++; this.count = this.count + 1n; }"), None),
        ("stateless", stateless, Some("continuationAmount() is only available in StatefulSmartContract methods")),
        ("terminal", pot("public close() { assert(continuationAmount() > 0n); }"), Some(UNAVAILABLE)),
        ("addOutput", pot("public split() { this.addOutput(continuationAmount(), this.count); }"), Some(UNAVAILABLE)),
        (
            "private",
            pot("private amt(): bigint { return continuationAmount(); }\n  public bump() { this.count = this.count + this.amt(); }"),
            Some(UNAVAILABLE),
        ),
    ];
    for (name, src, want) in cases {
        let err = match lower(&src) {
            Ok(_) => panic!("{}: expected a refusal, it compiled", name),
            Err(e) => e,
        };
        if let Some(w) = want {
            assert!(err.contains(w), "{}: want {:?} in {:?}", name, w, err);
        }
    }
}
