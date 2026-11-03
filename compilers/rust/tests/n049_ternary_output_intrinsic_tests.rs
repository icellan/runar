//! N-049 (EXT-2 "TernaryToll") — an output intrinsic inside a ternary arm.
//!
//! `lower_ternary_expr` lowers each arm into a sub-context whose
//! `add_output_refs` / `add_data_output_refs` are dropped, unlike the
//! if-statement lowering, which merges each arm's refs into the parent. The
//! continuation hash therefore omitted the arm's output: measured on every
//! tier, a spend that drops the payee output was accepted and the honest spend
//! rejected. Fail-closed like R-127: the validator refuses an output intrinsic
//! (direct, or through an inlined private helper) in either arm with the shared
//! N-049 diagnostic, and pass 4 refuses it again when reached unvalidated.
//!
//! What this proves: this tier refuses the ternary-arm shapes at pass 2 and
//! pass 4 with the shared diagnostic, and still accepts and lowers a ternary
//! that only selects VALUES.
//! What it does not prove: anything about emitted bytes (the cross-tier control
//! is conformance/negatives/ternary-output-control.test.ts).

use runar_compiler_rust::frontend::anf_lower::lower_to_anf;
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::validator::validate;

const HEAD: &str = "import { StatefulSmartContract, ByteString } from 'runar-lang';

class ConditionalPayout extends StatefulSmartContract {
  count: bigint;
  readonly payee: ByteString;
  readonly refund: ByteString;

  constructor(count: bigint, payee: ByteString, refund: ByteString) {
    super(count, payee, refund);
    this.count = count;
    this.payee = payee;
    this.refund = refund;
  }
";

const TERNARY_ARMS: &str = "  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.addRawOutput(50000n, this.payee)
                    : this.addRawOutput(50000n, this.refund);
  }";

const REFUSAL: &str =
    "Output intrinsic 'addRawOutput' cannot be called inside a conditional (ternary) expression arm.";

fn contract_of(methods: &str) -> runar_compiler_rust::frontend::ast::ContractNode {
    let src = format!("{HEAD}{methods}\n}}\n");
    let parsed = parse_source(&src, Some("ConditionalPayout.runar.ts"));
    assert!(parsed.errors.is_empty(), "parse: {:?}", parsed.errors);
    parsed.contract.expect("contract")
}

fn validation_errors(methods: &str) -> String {
    validate(&contract_of(methods))
        .errors
        .iter()
        .map(|d| d.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn lower_unvalidated(methods: &str) -> Option<String> {
    let contract = contract_of(methods);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(|| lower_to_anf(&contract));
    std::panic::set_hook(prev);
    match r {
        Ok(_) => None,
        Err(p) => Some(
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default(),
        ),
    }
}

#[test]
fn n049_validator_refuses_output_intrinsic_in_ternary_arm() {
    let errs = validation_errors(TERNARY_ARMS);
    assert!(errs.contains(REFUSAL), "not refused with the N-049 diagnostic: {errs}");
}

#[test]
fn n049_validator_refuses_helper_output_in_ternary_arm() {
    let errs = validation_errors(
        "  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.payTo(this.payee) : this.payTo(this.refund);
  }

  private payTo(script: ByteString): void {
    this.addRawOutput(50000n, script);
  }",
    );
    assert!(
        errs.contains(
            "Output intrinsic 'addRawOutput' (reached through private method 'payTo') cannot be called inside a conditional (ternary) expression arm."
        ),
        "{errs}"
    );
}

#[test]
fn n049_lowering_refuses_ternary_arm_output_without_validation() {
    let refusal = lower_unvalidated(TERNARY_ARMS)
        .expect("lower_to_anf accepted an output intrinsic inside a ternary arm");
    assert!(refusal.contains(REFUSAL), "not the N-049 diagnostic: {refusal}");
}

#[test]
fn n049_value_selecting_ternary_still_accepted() {
    let control = "  public release() {
    this.addOutput(1000n, this.count);
    this.addRawOutput(50000n, this.count > 0n ? this.payee : this.refund);
  }";
    assert_eq!(validation_errors(control), "");
    assert_eq!(lower_unvalidated(control), None);
}
