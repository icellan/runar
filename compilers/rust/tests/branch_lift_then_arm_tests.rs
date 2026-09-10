//! Regression test: the branch-lift must not zero the matched arm.
//!
//! `lift_branch_update_props` flattens a dispatch chain
//!
//! ```text
//!   if (p == 0n) { this.c0 = v; } else if (p == 1n) { this.c1 = v; }
//!   else { assert(false); }
//! ```
//!
//! into one single-valued `if` per property plus a top-level `update_prop`. The
//! `if`'s then-arm must evaluate to the assigned value and its else-arm to the
//! property's old value.
//!
//! The defect: the then-arm was built from `branch.value_bindings` — everything
//! BEFORE the `update_prop` in the original arm. That ends on the assigned value
//! only when the value was computed INSIDE the arm. When the arm assigns
//! something bound outside it, `value_bindings` is empty, the arm was emitted
//! EMPTY, and stack lowering padded it with a zero push
//! (`OP_IF OP_0 OP_ELSE OP_DUP OP_ENDIF`): the MATCHED branch wrote 0.
//!
//! `examples/ts/tic-tac-toe` escapes it only because `this.cN = this.turn` puts
//! a `load_prop` inside the arm — that shape is the control below.

use std::collections::HashMap;

use runar_compiler_rust::frontend::anf_lower::lower_to_anf;
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::ir::{ANFBinding, ANFValue};

const LOCAL_VALUE_DISPATCH: &str = r#"
class LocalValueDispatch extends StatefulSmartContract {
  c0: bigint;
  c1: bigint;

  constructor(c0: bigint, c1: bigint) {
    super(c0, c1);
    this.c0 = c0;
    this.c1 = c1;
  }

  public poke(position: bigint, value: bigint) {
    const doubled: bigint = value + value;
    if (position == 0n) { this.c0 = doubled; }
    else if (position == 1n) { this.c1 = doubled; }
    else { assert(false); }
  }
}
"#;

const IN_ARM_VALUE_DISPATCH: &str = r#"
class InArmValueDispatch extends StatefulSmartContract {
  c0: bigint;
  c1: bigint;
  turn: bigint;

  constructor(c0: bigint, c1: bigint, turn: bigint) {
    super(c0, c1, turn);
    this.c0 = c0;
    this.c1 = c1;
    this.turn = turn;
  }

  public poke(position: bigint) {
    if (position == 0n) { this.c0 = this.turn; }
    else if (position == 1n) { this.c1 = this.turn; }
    else { assert(false); }
  }
}
"#;

struct Lifted {
    prop: String,
    then: Vec<ANFBinding>,
    else_branch: Vec<ANFBinding>,
}

/// Every top-level `update_prop` whose value is an `if` binding, paired with
/// that `if`'s two arms.
fn lifted_assignments(source: &str, file: &str) -> Vec<Lifted> {
    let parsed = parse_source(source, Some(file));
    assert!(parsed.errors.is_empty(), "parse errors: {:?}", parsed.errors);
    let contract = parsed.contract.expect("parse returned no contract");
    let program = lower_to_anf(&contract);

    let method = program
        .methods
        .iter()
        .find(|m| m.name == "poke")
        .expect("method poke not found in lowered program");

    let by_name: HashMap<&str, &ANFValue> = method
        .body
        .iter()
        .map(|b| (b.name.as_str(), &b.value))
        .collect();

    let mut out = Vec::new();
    for b in &method.body {
        let ANFValue::UpdateProp { name, value } = &b.value else {
            continue;
        };
        let Some(ANFValue::If {
            then, else_branch, ..
        }) = by_name.get(value.as_str()).copied()
        else {
            continue;
        };
        out.push(Lifted {
            prop: name.clone(),
            then: then.clone(),
            else_branch: else_branch.clone(),
        });
    }
    out
}

#[test]
fn then_arm_carries_value_bound_outside_the_arm() {
    let lifted = lifted_assignments(LOCAL_VALUE_DISPATCH, "LocalValueDispatch.runar.ts");

    // Both properties in the chain must be lifted. If this is 0 the pass has
    // stopped recognising the shape and the arm assertions below would pass
    // vacuously.
    assert_eq!(
        lifted.len(),
        2,
        "expected 2 lifted conditional assignments, got {}",
        lifted.len()
    );

    for l in &lifted {
        assert!(
            !l.then.is_empty(),
            "then-arm for this.{} is empty; stack lowering pads it with OP_0, \
             so the MATCHED branch writes zero instead of the assigned value",
            l.prop
        );
        let last = l.then.last().unwrap();
        match &last.value {
            ANFValue::LoadConst { value } => assert_eq!(
                value.as_str(),
                Some("@ref:doubled"),
                "then-arm for this.{} must end on the assigned local",
                l.prop
            ),
            other => panic!(
                "then-arm for this.{} must end on a load_const of the assigned local, got {other:?}",
                l.prop
            ),
        }
        assert!(
            !l.else_branch.is_empty(),
            "else-arm for this.{} is empty",
            l.prop
        );
    }
}

/// Control: the TicTacToe shape already computed its value inside the arm and
/// was always correct. The fix must add nothing here — a second binding would
/// move the checked-in goldens.
#[test]
fn in_arm_value_shape_is_unchanged() {
    let lifted = lifted_assignments(IN_ARM_VALUE_DISPATCH, "InArmValueDispatch.runar.ts");

    assert_eq!(lifted.len(), 2, "expected 2 lifted conditional assignments");
    for l in &lifted {
        assert_eq!(
            l.then.len(),
            1,
            "then-arm for this.{} should hold exactly the in-arm load_prop",
            l.prop
        );
        match &l.then[0].value {
            ANFValue::LoadProp { name } => assert_eq!(name, "turn"),
            other => panic!("then-arm for this.{} should be load_prop turn, got {other:?}", l.prop),
        }
    }
}
