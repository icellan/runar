//! D25: `lower_to_anf` is a public entry point. A caller that assembles its
//! own pipeline (parse -> validate -> typecheck -> lower_to_anf) and never runs
//! `inject_continuation_binding` would otherwise lower a mixed ("bind")
//! contract with no `_spentOutpointHash`: its continuations would not be bound
//! to the spent outpoint, which is the twin-input theft D25 closes.

use runar_compiler_rust::frontend::anf_lower::lower_to_anf;
use runar_compiler_rust::frontend::ast::ContractNode;
use runar_compiler_rust::frontend::continuation_binding::{inject_continuation_binding, TWIN_BINDING_FIELD};
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::typecheck::typecheck;
use runar_compiler_rust::frontend::validator::validate;

const MIXED: &str = r#"import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
class MixedPot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
}"#;

fn frontend() -> ContractNode {
    let pr = parse_source(MIXED, Some("MixedPot.runar.ts"));
    assert!(pr.errors.is_empty(), "parse: {:?}", pr.errors);
    let contract = pr.contract.expect("parse produced no contract");
    let v = validate(&contract);
    assert!(v.errors.is_empty(), "validate: {:?}", v.errors);
    let tc = typecheck(&contract);
    assert!(tc.errors.is_empty(), "typecheck: {:?}", tc.errors);
    contract
}

#[test]
fn lower_to_anf_injects_binding_without_caller_injection() {
    let program = lower_to_anf(&frontend());
    let last = program.properties.last().map(|p| p.name.as_str());
    assert_eq!(last, Some(TWIN_BINDING_FIELD), "binding not injected");
}

#[test]
fn lower_to_anf_does_not_inject_twice() {
    let program = lower_to_anf(&inject_continuation_binding(&frontend()));
    let n = program.properties.iter().filter(|p| p.name == TWIN_BINDING_FIELD).count();
    assert_eq!(n, 1, "{} appears {} times", TWIN_BINDING_FIELD, n);
}
