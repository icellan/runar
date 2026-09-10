//! R-018: `this.arr[i]++` must be recognised as a state mutation.
//!
//! Two independent blind spots, both keyed on the operand of an
//! increment/decrement being a bare `PropertyAccess`:
//!
//!   1. **Lowering** — `lower_increment_expr` / `lower_decrement_expr` in
//!      `frontend/anf_lower.rs` compute the new value and then emit an
//!      `update_prop` ONLY when the operand is a `PropertyAccess`. After
//!      `expand-fixed-arrays` has run, `this.board[i]` (runtime index) is a
//!      ternary read chain over the expanded slots, so the new value is
//!      computed and DISCARDED — the mutation vanishes.
//!
//!   2. **Side-effect summary** — `collect_expr` in
//!      `frontend/side_effect_summary.rs` has the identical guard, so the
//!      method's `mutates_state` stays false. `ContinuationShape::for_effects`
//!      then returns `is_terminal = true` and NO continuation assertion is
//!      injected at all: a method that mutates state emits nothing binding
//!      that mutation.
//!
//! The control below (`this.count++`, a plain scalar property) is the shape
//! that already works, and must stay unchanged — it discriminates the two
//! paths.

use runar_compiler_rust::frontend::anf_lower::lower_to_anf;
use runar_compiler_rust::frontend::expand_fixed_arrays::expand_fixed_arrays;
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::side_effect_summary::{
    compute_side_effect_summary, ContinuationShape,
};
use runar_compiler_rust::ir::{ANFBinding, ANFValue};

/// Runtime index (`i` is a parameter), so `expand-fixed-arrays` cannot fold
/// `this.board[i]` to a single slot — it becomes a dispatch/ternary chain.
const INDEX_INCREMENT: &str = r#"
class BumpIncr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[i]++;
  }
}
"#;

const INDEX_DECREMENT: &str = r#"
class BumpDecr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[i]--;
  }
}
"#;

/// The hand-written form `this.board[i]++` must be equivalent to.
const INDEX_EXPLICIT_ADD: &str = r#"
class BumpIncr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[i] = this.board[i] + 1n;
  }
}
"#;

/// `this.board[i]++` used for its VALUE. Cannot be desugared to an
/// assignment, and must not silently drop the write.
const INDEX_INCREMENT_IN_EXPRESSION: &str = r#"
class BumpExpr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  seen: bigint = 0n;

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.seen = this.board[i]++;
  }
}
"#;

/// The most plausible real-world shape: a histogram bump inside a loop.
/// Exercises the prelude-splitting path in `rewrite_for_statement`.
const INDEX_INCREMENT_IN_LOOP: &str = r#"
class BumpLoop extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bumpAll() {
    for (let i: bigint = 0n; i < 3n; i++) {
      this.board[i]++;
    }
  }
}
"#;

/// Control: the already-working shape. A plain mutable scalar property.
const PLAIN_PROP_INCREMENT: &str = r#"
class BumpProp extends StatefulSmartContract {
  count: bigint = 0n;

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.count++;
  }
}
"#;

/// Parse + run pass 3b, exactly as `lib.rs` does before ANF lowering.
fn expanded(source: &str, file: &str) -> runar_compiler_rust::frontend::ast::ContractNode {
    let parsed = parse_source(source, Some(file));
    assert!(parsed.errors.is_empty(), "parse errors: {:?}", parsed.errors);
    let contract = parsed.contract.expect("parse returned no contract");
    let result = expand_fixed_arrays(&contract);
    assert!(
        result.errors.is_empty(),
        "expand-fixed-arrays errors: {:?}",
        result.errors
    );
    result.contract
}

/// Every `update_prop` name anywhere in the method body, including inside
/// `if` arms and loop bodies.
fn update_prop_names(bindings: &[ANFBinding], out: &mut Vec<String>) {
    for b in bindings {
        match &b.value {
            ANFValue::UpdateProp { name, .. } => out.push(name.clone()),
            ANFValue::If {
                then, else_branch, ..
            } => {
                update_prop_names(then, out);
                update_prop_names(else_branch, out);
            }
            ANFValue::Loop { body, .. } => update_prop_names(body, out),
            _ => {}
        }
    }
}

fn updated_props(source: &str, file: &str, method: &str) -> Vec<String> {
    let contract = expanded(source, file);
    let program = lower_to_anf(&contract);
    let m = program
        .methods
        .iter()
        .find(|m| m.name == method)
        .unwrap_or_else(|| panic!("method {} not found", method));
    let mut out = Vec::new();
    update_prop_names(&m.body, &mut out);
    out
}

fn param_names(source: &str, file: &str, method: &str) -> Vec<String> {
    let contract = expanded(source, file);
    let program = lower_to_anf(&contract);
    let m = program
        .methods
        .iter()
        .find(|m| m.name == method)
        .unwrap_or_else(|| panic!("method {} not found", method));
    m.params.iter().map(|p| p.name.clone()).collect()
}

fn shape(source: &str, file: &str, method: &str) -> (bool, ContinuationShape) {
    let contract = expanded(source, file);
    let summary = compute_side_effect_summary(&contract);
    let eff = summary
        .get(method)
        .unwrap_or_else(|| panic!("no side-effect entry for {}", method));
    (eff.mutates_state, ContinuationShape::for_effects(eff))
}

// ---------------------------------------------------------------------------
// Control — the shape that already works. Must pass before AND after the fix.
// ---------------------------------------------------------------------------

#[test]
fn control_plain_property_increment_updates_state() {
    let props = updated_props(PLAIN_PROP_INCREMENT, "BumpProp.runar.ts", "bump");
    assert!(
        props.iter().any(|p| p == "count"),
        "control regressed: `this.count++` produced no update_prop for `count`; got {:?}",
        props
    );

    let (mutates, shape) = shape(PLAIN_PROP_INCREMENT, "BumpProp.runar.ts", "bump");
    assert!(mutates, "control regressed: `this.count++` is not mutating");
    assert!(
        !shape.is_terminal,
        "control regressed: `this.count++` method treated as terminal"
    );
}

// ---------------------------------------------------------------------------
// Half 1 — lowering: the increment through an index must produce update_prop.
// ---------------------------------------------------------------------------

#[test]
fn index_increment_emits_update_prop() {
    let props = updated_props(INDEX_INCREMENT, "BumpIncr.runar.ts", "bump");
    assert!(
        !props.is_empty(),
        "`this.board[i]++` produced NO update_prop at all — the mutation was \
         computed and discarded"
    );
    assert!(
        props.iter().any(|p| p.starts_with("board")),
        "`this.board[i]++` produced no update_prop for a board slot; got {:?}",
        props
    );
}

#[test]
fn index_decrement_emits_update_prop() {
    let props = updated_props(INDEX_DECREMENT, "BumpDecr.runar.ts", "bump");
    assert!(
        props.iter().any(|p| p.starts_with("board")),
        "`this.board[i]--` produced no update_prop for a board slot; got {:?}",
        props
    );
}

// ---------------------------------------------------------------------------
// Half 2 — side-effect summary: the method is NOT terminal.
// ---------------------------------------------------------------------------

#[test]
fn index_increment_is_a_state_mutation() {
    let (mutates, shape) = shape(INDEX_INCREMENT, "BumpIncr.runar.ts", "bump");
    assert!(
        mutates,
        "`this.board[i]++` did not set mutates_state — no continuation is injected"
    );
    assert!(
        !shape.is_terminal,
        "`this.board[i]++` method classified terminal: no continuation assertion \
         binds the mutation"
    );
    assert!(shape.needs_change, "expected needs_change for a state mutation");
    assert!(
        shape.needs_new_amount,
        "expected needs_new_amount for a single-output state mutation"
    );
}

#[test]
fn index_decrement_is_a_state_mutation() {
    let (mutates, shape) = shape(INDEX_DECREMENT, "BumpDecr.runar.ts", "bump");
    assert!(mutates, "`this.board[i]--` did not set mutates_state");
    assert!(!shape.is_terminal, "`this.board[i]--` method classified terminal");
}

// ---------------------------------------------------------------------------
// The observable symptom the reviewer measured: the continuation params.
// ---------------------------------------------------------------------------

#[test]
fn index_increment_inside_a_loop_is_a_state_mutation() {
    let props = updated_props(INDEX_INCREMENT_IN_LOOP, "BumpLoop.runar.ts", "bumpAll");
    assert!(
        props.iter().any(|p| p.starts_with("board")),
        "`this.board[i]++` inside a for-loop produced no update_prop; got {:?}",
        props
    );

    let (mutates, shape) = shape(INDEX_INCREMENT_IN_LOOP, "BumpLoop.runar.ts", "bumpAll");
    assert!(mutates, "loop-bumped array element did not set mutates_state");
    assert!(!shape.is_terminal, "loop-bumping method classified terminal");
}

/// The desugar must be FAITHFUL, not merely present: `this.board[i]++`
/// lowers to exactly the ANF of `this.board[i] = this.board[i] + 1n`.
#[test]
fn index_increment_lowers_identically_to_the_explicit_add() {
    let sugar = lower_to_anf(&expanded(INDEX_INCREMENT, "BumpIncr.runar.ts"));
    let explicit = lower_to_anf(&expanded(INDEX_EXPLICIT_ADD, "BumpIncr.runar.ts"));
    assert_eq!(
        serde_json::to_value(&sugar).unwrap(),
        serde_json::to_value(&explicit).unwrap(),
        "`this.board[i]++` must lower identically to `this.board[i] = this.board[i] + 1n`"
    );
}

/// Expression-position `arr[i]++` cannot write back through the dispatch
/// chain. Rejecting is the only safe answer; silently dropping the write is
/// the defect this item is about.
#[test]
fn index_increment_in_expression_position_is_rejected() {
    let parsed = parse_source(INDEX_INCREMENT_IN_EXPRESSION, Some("BumpExpr.runar.ts"));
    assert!(parsed.errors.is_empty(), "parse errors: {:?}", parsed.errors);
    let contract = parsed.contract.expect("parse returned no contract");
    let result = expand_fixed_arrays(&contract);
    assert!(
        !result.errors.is_empty(),
        "`this.seen = this.board[i]++` was accepted; the array write is silently dropped"
    );
}

#[test]
fn index_increment_method_gets_continuation_params() {
    let params = param_names(INDEX_INCREMENT, "BumpIncr.runar.ts", "bump");
    let control = param_names(PLAIN_PROP_INCREMENT, "BumpProp.runar.ts", "bump");
    assert_eq!(
        params, control,
        "`this.board[i]++` must receive the same continuation params as the \
         equivalent `this.count++`; got {:?} vs control {:?}",
        params, control
    );
}
