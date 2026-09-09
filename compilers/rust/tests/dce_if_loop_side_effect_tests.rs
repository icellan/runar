//! R-005 — Rust DCE must not delete an `if` / `loop` whose *nested* bindings
//! carry observable side effects.
//!
//! ## The defect
//!
//! `frontend::dce::has_side_effect` was a `matches!` macro (no compiler-enforced
//! exhaustiveness) that enumerated only the *flat* effectful kinds. `ANFValue::If`
//! and `ANFValue::Loop` were absent, so both fell through to `false`.
//!
//! Nested bindings live INSIDE the parent `If`/`Loop` node rather than being
//! flattened into the method body, so binding retention is all-or-nothing: an
//! unreferenced `if` takes every `assert`, `check_preimage` and `add_output`
//! inside it with it. `anf_lower::lower_if_statement` produces exactly such an
//! unreferenced binding for the ordinary guard shape `if (flag) { assert(...) }`
//! — one arm, no rebound local, no output — so nothing in the surrounding method
//! ever references the `if` binding's name.
//!
//! DCE only runs when something upstream changed, and `anf_optimize::optimize_ec`
//! sweeps EVERY method as soon as ANY method anywhere contains a foldable EC
//! call. That is what makes this reachable from ordinary source rather than
//! theoretical: a single `ecMulGen(1n)` anywhere in the contract silently
//! deletes every guard clause in every method, and the result still compiles to
//! valid, non-erroring script.
//!
//! ## What these tests prove
//!
//! - `guard_clause_survives_ec_optimizer_dce` is the end-to-end regression: it
//!   drives the real `compile_source_str_to_ir` pipeline (parse → validate →
//!   typecheck → ANF → fold → optimize_ec/DCE) on the reproduction contract and
//!   asserts the `if` binding and its nested `pubKeyHash` assert survive. This
//!   exercises the actual deletion, not just the predicate.
//! - The predicate tests pin both polarities of the fix: nested effects keep the
//!   node, a genuinely pure `if`/`loop` is still eligible for elimination.
//!
//! ## What these tests do NOT prove
//!
//! They say nothing about the emitted *hex* being correct for a retained guard —
//! only that the binding is no longer dropped. They do not cover the other six
//! tiers (the TypeScript tier carries the identical gap and is tracked
//! separately), and they do not prove `has_side_effect` is now exhaustive over
//! future ANF kinds beyond the compile-time guarantee the exhaustive `match`
//! gives.

use runar_compiler_rust::compile_source_str_to_ir;
use runar_compiler_rust::frontend::dce::{eliminate_dead_bindings_method, has_side_effect};
use runar_compiler_rust::ir::{ANFBinding, ANFMethod, ANFValue};

// ---------------------------------------------------------------------------
// End-to-end: the real deletion
// ---------------------------------------------------------------------------

/// Guard clause + a foldable `ecMulGen(1n)` to arm `optimize_ec`'s DCE sweep.
const GUARD_WITH_EC_TRIGGER: &str = r#"import { SmartContract, assert, ByteString, Sig, PubKey, hash160, checkSig, ecMulGen } from 'runar-lang';

class Guard extends SmartContract {
  readonly pubKeyHash: ByteString;

  constructor(pubKeyHash: ByteString) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey, flag: boolean): void {
    assert(checkSig(sig, pubKey));
    if (flag) {
      assert(hash160(pubKey) === this.pubKeyHash);
    }
    const g: ByteString = ecMulGen(1n);
    assert(g !== this.pubKeyHash);
  }
}"#;

#[test]
fn guard_clause_survives_ec_optimizer_dce() {
    let program = compile_source_str_to_ir(GUARD_WITH_EC_TRIGGER, Some("Guard.runar.ts"))
        .expect("contract should compile to ANF IR");

    let unlock = program
        .methods
        .iter()
        .find(|m| m.name == "unlock")
        .expect("unlock method present");

    let if_binding = unlock
        .body
        .iter()
        .find(|b| matches!(b.value, ANFValue::If { .. }))
        .unwrap_or_else(|| {
            panic!(
                "the `if (flag) {{ assert(...) }}` guard was eliminated by DCE; \
                 surviving bindings: {:?}",
                unlock
                    .body
                    .iter()
                    .map(|b| b.name.as_str())
                    .collect::<Vec<_>>()
            )
        });

    // ...and the guard's assert must still be inside it.
    let ANFValue::If { then, .. } = &if_binding.value else {
        unreachable!("matched above")
    };
    assert!(
        then.iter().any(|b| matches!(b.value, ANFValue::Assert { .. })),
        "retained `if` lost its nested assert: {:?}",
        then.iter().map(|b| b.name.as_str()).collect::<Vec<_>>()
    );
    assert!(
        then.iter()
            .any(|b| matches!(&b.value, ANFValue::LoadProp { name } if name == "pubKeyHash")),
        "retained `if` lost the `this.pubKeyHash` load it guards on"
    );
}

// ---------------------------------------------------------------------------
// Predicate + pass-level behaviour, both polarities
// ---------------------------------------------------------------------------

fn binding(name: &str, value: ANFValue) -> ANFBinding {
    ANFBinding { name: name.to_string(), value, source_loc: None }
}

fn method_with(body: Vec<ANFBinding>) -> ANFMethod {
    ANFMethod {
        name: "m".to_string(),
        params: vec![],
        body,
        is_public: true,
        sighash_type: None,
    }
}

fn load_true(name: &str) -> ANFBinding {
    binding(name, ANFValue::LoadConst { value: serde_json::Value::Bool(true) })
}

fn assert_on(name: &str, target: &str) -> ANFBinding {
    binding(
        name,
        ANFValue::Assert {
            value: target.to_string(),
            is_auto_injected_state_check: false,
        },
    )
}

#[test]
fn if_with_nested_assert_has_side_effect() {
    let node = ANFValue::If {
        cond: "c".to_string(),
        then: vec![load_true("n0"), assert_on("n1", "n0")],
        else_branch: vec![],
        results: vec![],
    };
    assert!(has_side_effect(&node), "an `if` whose arm asserts is effectful");
}

#[test]
fn loop_with_nested_assert_has_side_effect() {
    let node = ANFValue::Loop {
        count: 1,
        body: vec![load_true("n0"), assert_on("n1", "n0")],
        iter_var: "i".to_string(),
        start: serde_json::Value::from(0),
        step: 1,
    };
    assert!(has_side_effect(&node), "a `loop` whose body asserts is effectful");
}

#[test]
fn pure_if_is_still_eliminable() {
    let node = ANFValue::If {
        cond: "c".to_string(),
        then: vec![load_true("n0")],
        else_branch: vec![load_true("n1")],
        results: vec![],
    };
    assert!(
        !has_side_effect(&node),
        "an `if` with no nested effects must remain DCE-eligible"
    );
}

#[test]
fn dce_keeps_unreferenced_if_that_asserts() {
    let method = method_with(vec![
        load_true("c"),
        binding(
            "t_if",
            ANFValue::If {
                cond: "c".to_string(),
                then: vec![load_true("n0"), assert_on("n1", "n0")],
                else_branch: vec![],
                results: vec![],
            },
        ),
    ]);

    let out = eliminate_dead_bindings_method(&method);
    assert!(
        out.body.iter().any(|b| b.name == "t_if"),
        "DCE deleted an unreferenced `if` that contains an assert"
    );
}

#[test]
fn dce_still_drops_unreferenced_pure_if() {
    let method = method_with(vec![
        load_true("c"),
        binding(
            "t_if",
            ANFValue::If {
                cond: "c".to_string(),
                then: vec![load_true("n0")],
                else_branch: vec![],
                results: vec![],
            },
        ),
        // A real effect so the method is not entirely elided.
        load_true("k"),
        assert_on("k_assert", "k"),
    ]);

    let out = eliminate_dead_bindings_method(&method);
    assert!(
        !out.body.iter().any(|b| b.name == "t_if"),
        "a pure unreferenced `if` should still be eliminated"
    );
}
