//! R-065 — the Go-format `for` header with no update clause.
//!
//! `parser_gocontract.rs::parse_for_statement` has two arms. The three-part
//! arm parses init / condition / post. The other arm — reached whenever there
//! is no `;` before the `{` — SYNTHESISES a header the source never wrote:
//!
//!     let dummy_init   = VariableDecl { name: "_i", init: 0 };
//!     let dummy_update = ExpressionStatement { Identifier { "_i" } };
//!
//! A bare identifier is on R-029's accepted-update list on purpose (it is the
//! no-op sentinel the zig / move while-shaped parsers synthesize when the
//! surface has no continue expression), so R-065 waved the loop through and
//! the count got derived from the condition alone.
//!
//! That derivation is not sound. The update, if there is one, is in the BODY,
//! where nothing proves it runs unconditionally, runs once per iteration, or
//! advances by one. Measured before the fix:
//!
//!     for i < 5 { sum = sum + start + i; i++ }        184 hexchars, count=5
//!     for i < 5 { if start > 3 { i++ }; sum = sum+i } 234 hexchars, count=5
//!
//! The second is a Go program that spins forever when `start <= 3`. Rust
//! compiled it clean to a fixed five-iteration script — a locking script
//! computing something the source does not say, which is strictly worse than
//! no script at all.
//!
//! spec/grammar.md:420 is already explicit: "The loop variable MUST use simple
//! increment (`++`) or decrement (`--`)." A header with no update clause has
//! no such variable. Six of the seven tiers refuse this program (five at the
//! parser, one at R-065); Rust and Zig were the two that did not, and they
//! disagreed with each other about what it meant.
//!
//! The fix is in the parser, not the validator: refusing to synthesize a
//! header nobody wrote keeps the no-op sentinel available to the while-shaped
//! parsers that genuinely need it.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

fn compile(source: &str, file_name: &str) -> Result<String, String> {
    compile_from_source_str_with_options(source, Some(file_name), &CompileOptions::default())
        .map(|artifact| artifact.script)
}

fn go_contract(loop_src: &str) -> String {
    format!(
        r#"package contract

import "runar"

type T struct {{
    runar.SmartContract
    ExpectedSum runar.Int `runar:"readonly"`
}}

func (c *T) Verify(start runar.Int) {{
    sum := runar.Int(0)
    i := runar.Int(0)
{loop_src}
    runar.Assert(sum == c.ExpectedSum)
}}
"#
    )
}

/// The control. Its whole job is to prove the probes below do not pass because
/// the Go parser stopped accepting bounded loops altogether.
#[test]
fn control_a_three_part_go_for_header_still_compiles() {
    let src = go_contract("    for j := runar.Int(0); j < 5; j++ {\n        sum = sum + start + j\n    }");
    let hex = compile(&src, "T.runar.go").expect(
        "an ordinary three-part Go for header must still compile; if this fails the \
         rejections below prove nothing",
    );
    assert!(!hex.is_empty(), "control compiled to an empty script");
}

/// The reported shape.
#[test]
fn a_condition_only_go_for_header_is_rejected() {
    let src = go_contract("    for i < 5 {\n        sum = sum + start + i\n        i++\n    }");
    let err = compile(&src, "T.runar.go").expect_err(
        "a Go `for cond { }` header carries no update clause, so no iteration count is \
         derivable; deriving one from the condition is a guess. Six peer tiers refuse it.",
    );
    assert!(
        !err.trim().is_empty(),
        "rejection must carry a diagnostic, got an empty message"
    );
}

/// The shape that shows the derivation is unsound rather than merely divergent.
/// In Go this either never terminates or advances irregularly; there is no
/// iteration count to derive at all.
#[test]
fn a_condition_only_header_with_a_conditional_body_update_is_rejected() {
    let src = go_contract(
        "    for i < 5 {\n        if start > 3 {\n            i++\n        }\n        sum = sum + i\n    }",
    );
    compile(&src, "T.runar.go").expect_err(
        "the body's increment is conditional, so the loop is unbounded for start <= 3; \
         unrolling it five times emits a script for a program that was never written",
    );
}
