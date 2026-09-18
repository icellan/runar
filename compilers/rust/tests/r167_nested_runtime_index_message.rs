//! R-167 / CL-BUG-148 — a runtime index on the SECOND level of a nested
//! FixedArray was refused by the wrong pass, naming a symbol the user never
//! wrote.
//!
//! `self.g[i][0]` — runtime index on the FIRST level — is refused explicitly by
//! the expander:
//!
//!     NestedIdx2.runar.rs:16:9: Runtime index access on a nested FixedArray
//!     is not supported
//!
//! `self.g[0][i]` — runtime index on the SECOND — was not. `try_resolve_array_base`
//! only recognises a `PropertyAccess` object, and here the object is itself an
//! `IndexAccess`, so the call fell through to the generic "rewrite both sides"
//! path. The rewritten form `g__0[i]` then survived into ANF and died in STACK
//! LOWERING:
//!
//!     stack lowering: property 'g__0' at NestedIdx.runar.rs:16:9 is neither on
//!     the stack, initialized, nor a constructor parameter ...
//!
//! `g__0` is a synthetic intermediate `expand_fixed_arrays` invents; it appears
//! nowhere in the source. The author is told a property they never declared has
//! no deploy-time slot, by a pass two stages downstream of the one that knows
//! what is actually wrong.
//!
//! Both spellings are the same unsupported feature and now give the same
//! sentence.

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

fn contract(access: &str) -> String {
    format!(
        r#"use runar::prelude::*;

#[runar::contract]
struct NestedIdx {{
    #[readonly]
    limit: Int,
    g: [[Int; 2]; 2],
}}

impl NestedIdx {{
    pub fn init(&mut self) {{
        self.g = [[0, 0], [0, 0]];
    }}

    pub fn go(&self, i: Int) {{
        assert!({access} > self.limit);
    }}
}}
"#
    )
}

fn errors(src: &str) -> Vec<String> {
    compile_from_source_str_with_result(src, Some("NestedIdx.runar.rs"), &CompileOptions::default())
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.message.clone())
        .collect()
}

const EXPECTED: &str = "Runtime index access on a nested FixedArray is not supported";

#[test]
fn runtime_index_on_the_first_level_is_explicit() {
    let msgs = errors(&contract("self.g[i][0]"));
    assert!(
        msgs.iter().any(|m| m.contains(EXPECTED)),
        "expected the expander's message, got: {msgs:?}"
    );
}

#[test]
fn runtime_index_on_the_second_level_gets_the_same_message() {
    let msgs = errors(&contract("self.g[0][i]"));
    assert!(
        msgs.iter().any(|m| m.contains(EXPECTED)),
        "expected the expander's message, got: {msgs:?}"
    );
}

#[test]
fn the_second_level_refusal_never_names_a_synthetic_slot() {
    let msgs = errors(&contract("self.g[0][i]"));
    for m in &msgs {
        assert!(
            !m.contains("g__0"),
            "the diagnostic names 'g__0', a synthetic this pass invents and the \
             author never wrote: {m}"
        );
    }
}

/// The control: literal indices on both levels still compile.
#[test]
fn fully_literal_nested_indexing_still_compiles() {
    let result = compile_from_source_str_with_result(
        &contract("self.g[0][1]"),
        Some("NestedIdx.runar.rs"),
        &CompileOptions::default(),
    );
    assert!(
        result.success,
        "control failed: {:?}",
        result.diagnostics.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
}
