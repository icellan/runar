//! R-138 / CL-BUG-012 — a refusal from pass 4 or pass 5 reached the user with
//! no `file:line:column`.
//!
//! Passes 4 and 5 refuse a construct they must not emit by panicking, and
//! `catch_refusal` converts the payload into a bare `String`. Stack underflow,
//! unknown builtin, branch-output rejection and unresolvable-loop-shape
//! refusals therefore arrived with no location, unlike every `Diagnostic` from
//! passes 1-3 — so the one class of error that means "your contract is shaped
//! in a way this compiler cannot emit" was also the one class that would not
//! tell you where.
//!
//! There are 44 panic sites across `frontend/anf_lower.rs` (10) and
//! `codegen/stack.rs` (34). Rather than thread a location through all of them,
//! the location is published at the two choke points that already hold it —
//! `lower_binding`, which has the `ANFBinding` and therefore its `source_loc`,
//! and the ANF lowerer's statement dispatch — and `catch_refusal` reads it on
//! the error path. One field and two assignments cover every site, including
//! any added later.
//!
//! These tests assert the LOCATION only. The message text is pinned by the
//! cross-tier negatives corpus and must not move.

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

fn compile(source: &str) {
    let _ = source;
}

/// Every error-severity diagnostic carries a line greater than zero.
fn assert_all_located(source: &str, label: &str) {
    let result = compile_from_source_str_with_result(
        source,
        Some("Refusal.runar.ts"),
        &CompileOptions::default(),
    );
    let errors: Vec<_> = result
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert!(
        !errors.is_empty(),
        "{label}: expected at least one error, got none"
    );
    for d in &errors {
        let loc = d.loc.as_ref().unwrap_or_else(|| {
            panic!(
                "{label}: \"{}\" has no location — a refusal is the one error \
                 class that means the contract's SHAPE is wrong, so it is the \
                 one that most needs a line",
                d.message
            )
        });
        assert!(
            loc.line > 0,
            "{label}: \"{}\" reports line {}",
            d.message,
            loc.line
        );
    }
}

/// A branch that both declares an output and merges two locals: the
/// branch-output rejection in pass 4.
#[test]
fn anf_lowering_branch_output_refusal_is_located() {
    assert_all_located(
        r#"import { StatefulSmartContract, assert } from 'runar-lang';

export class Refusal extends StatefulSmartContract {
  a: bigint;
  b: bigint;

  constructor(a: bigint, b: bigint) {
    super(a, b);
    this.a = a;
    this.b = b;
  }

  public go(x: bigint, limit: bigint) {
    let na: bigint = 0n;
    let nb: bigint = 0n;
    if (x < limit) {
      na = na + x;
      nb = nb + na;
      this.addOutput(1000n, na, nb);
    }
    assert(x > 0n);
  }
}
"#,
        "branch-output refusal",
    );
}

/// A loop whose start is not a literal: the unresolvable-loop-shape refusal.
#[test]
fn anf_lowering_loop_shape_refusal_is_located() {
    assert_all_located(
        r#"import { StatefulSmartContract, assert } from 'runar-lang';

export class Refusal extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(start: bigint) {
    let acc: bigint = this.count;
    for (let i = start; i < 3n; i++) {
      acc = acc + i;
    }
    this.count = acc;
    assert(start >= 0n);
  }
}
"#,
        "loop-shape refusal",
    );
}

/// The control: an ordinary contract still compiles, so the assertions above
/// are reading a refusal and not a broken probe.
#[test]
fn an_ordinary_contract_still_compiles() {
    compile("");
    let result = compile_from_source_str_with_result(
        r#"import { SmartContract, assert } from 'runar-lang';

export class Refusal extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public go(x: bigint) {
    assert(x > this.limit);
  }
}
"#,
        Some("Refusal.runar.ts"),
        &CompileOptions::default(),
    );
    assert!(
        result.success,
        "control failed: {:?}",
        result.diagnostics.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
}
