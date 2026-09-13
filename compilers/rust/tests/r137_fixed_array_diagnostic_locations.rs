//! R-137 / CL-BUG-011 — the fixed-array expander's refusals carried no
//! `file:line:column`.
//!
//! `rewrite_index_access` and the increment-as-value refusal built their
//! `Diagnostic::error(...)` with `None` for the location, while the sibling
//! checks in the same file — initializer length, nested initializer length,
//! constructor-parameter arrays — all pass `Some(loc)`. Three sites, measured
//! by grepping the `Diagnostic::error` calls in
//! `frontend/expand_fixed_arrays.rs`:
//!
//!   :812   `++` on a FixedArray element used for its value
//!   :999   a literal index out of range (the WRITE path)
//!   :1018  a runtime index on a nested FixedArray
//!
//! A fourth turned up while fixing them, and it is the one an ordinary READ
//! actually hits: `resolve_literal_index_chain` raises the same out-of-range
//! message from a third place, also with `None`. The first fix left the test
//! red for exactly that reason — the message matched a site I had already
//! patched, and the diagnostic still had no location. A scan of every
//! `Diagnostic::error` call in the file whose last argument is `None` now
//! reports zero, and that scan is how the fourth was found rather than by
//! reading.
//!
//! Every other error in this tier arrives with a location, so an author gets a
//! sentence with no line for exactly the three fixed-array mistakes that are
//! easiest to make by accident.
//!
//! These tests assert the LOCATION, not the wording: the message text is
//! already pinned by the cross-tier negatives corpus.

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

fn contract(body: &str) -> String {
    format!(
        r#"use runar::prelude::*;

#[runar::contract]
struct ArrProbe {{
    #[readonly]
    limit: Int,
    cells: [Int; 3],
}}

impl ArrProbe {{
    pub fn init(&mut self) {{
        self.cells = [0, 0, 0];
    }}

    pub fn go(&self, i: Int) {{
{body}
    }}
}}
"#
    )
}

/// Every error-severity diagnostic must carry a line greater than zero.
fn assert_all_located(source: &str, label: &str) {
    let result = compile_from_source_str_with_result(
        source,
        Some("ArrProbe.runar.rs"),
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
                "{label}: \"{}\" has no location — the author cannot find the line",
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

#[test]
fn literal_index_out_of_range_is_located() {
    assert_all_located(
        &contract("        assert!(self.cells[7] > 0);"),
        "index out of range",
    );
}

#[test]
fn negative_literal_index_is_located() {
    assert_all_located(
        &contract("        assert!(self.cells[-1] > 0);"),
        "negative index",
    );
}

// NOT tested here: `let v = self.cells[0]++`. On the `.runar.rs` surface that
// never reaches the expander — the parser refuses it first, with
// "unsupported token 'Plus' at 16:36 — not valid in Rúnar contract", whose
// position lives in the MESSAGE TEXT while `loc` is still `None`. That is the
// same class of defect in a different pass and belongs to R-138 (refusal
// diagnostics from passes 4/5 and the parser carry no SourceLocation), so
// asserting it here would credit this change with a fix it did not make. The
// expander's third `None` site (the increment-as-value refusal) is fixed
// alongside the two below; it is simply not reachable from this surface.

/// The control: a well-formed fixed-array contract still compiles, so the
/// tests above are measuring the diagnostic and not a broken probe. It earns
/// its place — the first version of this file declared `cells` without an
/// `init()`, which made it a constructor parameter and failed for an unrelated
/// reason, and the three "located" assertions would have been reading that
/// error instead.
#[test]
fn a_valid_fixed_array_contract_still_compiles() {
    let result = compile_from_source_str_with_result(
        &contract("        assert!(self.cells[0] + self.cells[1] + self.cells[2] > i);"),
        Some("ArrProbe.runar.rs"),
        &CompileOptions::default(),
    );
    assert!(
        result.success,
        "control contract failed: {:?}",
        result.diagnostics.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
}
