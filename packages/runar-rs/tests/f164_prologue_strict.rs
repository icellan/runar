//! F-164 (round 2): `execute_strict` must mock the WHOLE auto-injected
//! stateful prologue (checkPreimage's assert AND the sighash-type assert),
//! not just developer asserts.
//!
//! See `packages/runar-sdk/src/anf-interpreter.ts` for the TS reference
//! this ports (`detectAutoInjectedPrologueAsserts` there,
//! `detect_auto_injected_prologue_asserts` in
//! `packages/runar-rs/src/sdk/anf_interpreter.rs`).
//!
//! Round 1 of F-164 fixed the `check_preimage` ANF-node kind to
//! mock-return `true` in strict mode. That alone is NOT enough: the
//! compiler's prologue also emits a SECOND, un-marked assert right after —
//! the sighash-type check (`assert(extractSigHashType(txPreimage) ===
//! <mode>)`) — and `extractSigHashType` has no real/mock value off-chain.
//! Before round 2, a strict-mode call against a REAL compiled stateful
//! method would get past checkPreimage only to throw at the sighash-type
//! assert instead — never reaching the method's actual body.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use runar_lang::sdk::anf_interpreter::{
    execute_strict, AssertionFailureError, ANFBinding, ANFMethod, ANFParam, ANFProgram,
    ANFProperty,
};
use runar_lang::sdk::SdkValue;

fn conformance_ir(fixture: &str) -> ANFProgram {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir
            .join("conformance/tests")
            .join(fixture)
            .join("expected-ir.json");
        if candidate.is_file() {
            let data = fs::read_to_string(&candidate)
                .unwrap_or_else(|e| panic!("read {}: {}", candidate.display(), e));
            return serde_json::from_str(&data)
                .unwrap_or_else(|e| panic!("parse {}: {}", candidate.display(), e));
        }
        if !dir.pop() {
            panic!(
                "could not locate conformance/tests/{}/expected-ir.json walking up from {}",
                fixture,
                env!("CARGO_MANIFEST_DIR")
            );
        }
    }
}

/// `execute_strict` against the REAL compiled `stateful-counter` fixture's
/// `increment` method (the same ANF + inputs the conformance strict-golden
/// `stateful-counter-increment` exercises) must now reach the method's real
/// body result instead of aborting at the auto-injected prologue.
#[test]
fn execute_strict_mocks_whole_auto_injected_prologue_on_real_fixture() {
    let anf = conformance_ir("stateful-counter");
    let mut current_state = HashMap::new();
    current_state.insert("count".to_string(), SdkValue::Int(0));
    let args = HashMap::new();

    let result = execute_strict(&anf, "increment", &current_state, &args, &[]);
    let (state, _data_outputs, _raw_outputs) =
        result.unwrap_or_else(|e| panic!("execute_strict returned error, want success: {}", e));
    assert_eq!(state.get("count"), Some(&SdkValue::Int(1)));
}

// ---------------------------------------------------------------------------
// Hand-built prologue + a user-written assert placed AFTER it, proving the
// structural detector is anchored to the FIXED prologue position
// (indices 0-7), not to IR shape alone.
// ---------------------------------------------------------------------------

fn load_tx_preimage(name: &str) -> ANFBinding {
    ANFBinding {
        name: name.to_string(),
        value: serde_json::json!({"kind": "load_param", "name": "txPreimage"}),
    }
}

fn check_preimage(name: &str, preimage_ref: &str) -> ANFBinding {
    ANFBinding {
        name: name.to_string(),
        value: serde_json::json!({"kind": "check_preimage", "preimage": preimage_ref}),
    }
}

fn assert_binding(name: &str, pred_ref: &str) -> ANFBinding {
    ANFBinding {
        name: name.to_string(),
        value: serde_json::json!({"kind": "assert", "value": pred_ref}),
    }
}

fn extract_sighash_call(name: &str, preimage_ref: &str) -> ANFBinding {
    ANFBinding {
        name: name.to_string(),
        value: serde_json::json!({"kind": "call", "func": "extractSigHashType", "args": [preimage_ref]}),
    }
}

fn bin_op_eq(name: &str, left: &str, right: &str) -> ANFBinding {
    ANFBinding {
        name: name.to_string(),
        value: serde_json::json!({"kind": "bin_op", "op": "===", "left": left, "right": right}),
    }
}

fn load_const(name: &str, value: i64) -> ANFBinding {
    ANFBinding {
        name: name.to_string(),
        value: serde_json::json!({"kind": "load_const", "value": value}),
    }
}

fn full_prologue_program(user_body: Vec<ANFBinding>) -> ANFProgram {
    let mut body = vec![
        load_tx_preimage("t0"),
        check_preimage("t1", "t0"),
        assert_binding("t2", "t1"),
        load_tx_preimage("t3"),
        extract_sighash_call("t4", "t3"),
        load_const("t5", 65),
        bin_op_eq("t6", "t4", "t5"),
        assert_binding("t7", "t6"),
    ];
    body.extend(user_body);
    ANFProgram {
        contract_name: "Counter".to_string(),
        properties: vec![ANFProperty {
            name: "count".to_string(),
            prop_type: "bigint".to_string(),
            readonly: false,
            initial_value: None,
        }],
        methods: vec![ANFMethod {
            name: "increment".to_string(),
            params: vec![ANFParam {
                name: "txPreimage".to_string(),
                param_type: "SigHashPreimage".to_string(),
            }],
            body,
            is_public: true,
        }],
    }
}

#[test]
fn user_written_assert_after_prologue_still_enforced() {
    let anf = full_prologue_program(vec![
        load_tx_preimage("u0"),
        extract_sighash_call("u1", "u0"),
        load_const("u2", 1), // wrong expected mode (real mode is 65)
        bin_op_eq("u3", "u1", "u2"),
        assert_binding("userAssert", "u3"),
        ANFBinding {
            name: "t8".to_string(),
            value: serde_json::json!({"kind": "load_prop", "name": "count"}),
        },
        load_const("t9", 1),
        ANFBinding {
            name: "t10".to_string(),
            value: serde_json::json!({"kind": "bin_op", "op": "+", "left": "t8", "right": "t9"}),
        },
        ANFBinding {
            name: "t11".to_string(),
            value: serde_json::json!({"kind": "update_prop", "name": "count", "value": "t10"}),
        },
    ]);

    let mut current_state = HashMap::new();
    current_state.insert("count".to_string(), SdkValue::Int(0));
    let args = HashMap::new();

    let err: AssertionFailureError = execute_strict(&anf, "increment", &current_state, &args, &[])
        .expect_err("expected AssertionFailureError");
    assert_eq!(
        err.binding_name, "userAssert",
        "mocking must not reach past the prologue"
    );
}
