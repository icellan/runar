//! H1 (#119 tail): `lower_load_prop` must NOT silently coerce an unknown
//! property onto constructor slot 0.
//!
//! A `load_prop` binding whose name is not a declared constructor-param
//! property used to fall through to `.unwrap_or(0)`, emitting the placeholder
//! for constructor slot 0 — an UNRELATED argument's deploy-time bytes — with no
//! diagnostic. That is a silent-wrong-code path: the produced locking script
//! splices the wrong value at that position.
//!
//! The hardened behaviour is a HARD ERROR (a `panic!` inside the lowering,
//! surfaced by the public `lower_to_stack` — which wraps the pass in
//! `catch_unwind` — as an `Err`). Note the divergence from the TS reference:
//! TS `lowerToStack` *throws*, whereas Rust's `lower_to_stack` converts the
//! panic into `Err(String)`; the message content is identical.

use runar_compiler_rust::codegen::stack::lower_to_stack;
use runar_compiler_rust::ir::{
    ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFValue, SourceLocation,
};

/// A real readonly constructor-param property `pk` (constructor slot 0).
fn pk_property() -> ANFProperty {
    ANFProperty {
        name: "pk".to_string(),
        prop_type: "PubKey".to_string(),
        readonly: true,
        initial_value: None,
        synthetic_array_chain: None,
    }
}

/// Program with the real ctor-param property `pk` plus a public method that
/// loads a property `ghost` that is NOT declared on the contract. `ghost`
/// therefore reaches the placeholder fallback with no matching constructor slot.
fn program_with_unknown_load_prop() -> ANFProgram {
    ANFProgram {
        contract_name: "Ghost".to_string(),
        parent_class: String::new(),
        properties: vec![pk_property()],
        methods: vec![ANFMethod {
            name: "spend".to_string(),
            params: vec![],
            body: vec![
                ANFBinding {
                    name: "t0".to_string(),
                    value: ANFValue::LoadProp { name: "ghost".to_string(), preserve: false },
                    source_loc: Some(SourceLocation {
                        file: "Ghost.runar.ts".to_string(),
                        line: 7,
                        column: 4,
                    }),
                },
                ANFBinding {
                    name: "t1".to_string(),
                    value: ANFValue::Assert {
                        value: "t0".to_string(),
                        is_auto_injected_state_check: false,
                    },
                    source_loc: None,
                },
            ],
            is_public: true,
            sighash_type: None,
        }],
    }
}

#[test]
fn load_prop_with_no_ctor_slot_is_a_hard_error() {
    let result = lower_to_stack(&program_with_unknown_load_prop());
    let err = result.expect_err("expected a hard error, not a silent slot-0 placeholder");
    assert!(
        err.contains("ghost"),
        "error should name the offending property, got: {err}"
    );
}

#[test]
fn load_prop_hard_error_names_property_and_source_location() {
    let result = lower_to_stack(&program_with_unknown_load_prop());
    let err = result.expect_err("expected a hard error");
    // Names the ghost property, says it is not a constructor parameter, and
    // lists the known ctor-param property names — plus the source location.
    assert!(err.contains("ghost"), "should name the property, got: {err}");
    assert!(
        err.contains("constructor parameter"),
        "should say it is not a constructor parameter, got: {err}"
    );
    assert!(
        err.contains("pk"),
        "should list known ctor-param property names, got: {err}"
    );
    assert!(
        err.contains("Ghost.runar.ts"),
        "should include the source file, got: {err}"
    );
    assert!(err.contains('7'), "should include the source line, got: {err}");
}

#[test]
fn real_ctor_param_prop_lowers_without_error() {
    let program = ANFProgram {
        contract_name: "Ok".to_string(),
        parent_class: String::new(),
        properties: vec![pk_property()],
        methods: vec![ANFMethod {
            name: "spend".to_string(),
            params: vec![ANFParam {
                name: "given".to_string(),
                param_type: "PubKey".to_string(),
            }],
            body: vec![
                ANFBinding {
                    name: "t0".to_string(),
                    value: ANFValue::LoadProp { name: "pk".to_string(), preserve: false },
                    source_loc: None,
                },
                ANFBinding {
                    name: "t1".to_string(),
                    value: ANFValue::LoadParam { name: "given".to_string() },
                    source_loc: None,
                },
                ANFBinding {
                    name: "t2".to_string(),
                    value: ANFValue::BinOp {
                        op: "===".to_string(),
                        left: "t0".to_string(),
                        right: "t1".to_string(),
                        result_type: Some("bytes".to_string()),
                    },
                    source_loc: None,
                },
                ANFBinding {
                    name: "t3".to_string(),
                    value: ANFValue::Assert {
                        value: "t2".to_string(),
                        is_auto_injected_state_check: false,
                    },
                    source_loc: None,
                },
            ],
            is_public: true,
            sighash_type: None,
        }],
    };
    assert!(
        lower_to_stack(&program).is_ok(),
        "a real constructor-param property must lower without error"
    );
}
