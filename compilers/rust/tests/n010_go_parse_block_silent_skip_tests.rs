//! N-010 (CL-BUG-167) — `.runar.go` parser's `parse_block` recovery silently
//! skips a token it cannot parse as a statement, with NO diagnostic.
//!
//! `parse_block`'s `else { self.advance() }` arm (parser_gocontract.rs) runs
//! whenever `parse_statement()` returns `None` — i.e. the current token could
//! not start ANY statement shape, including the expression-statement
//! fallback. F-019 closed the one path into this arm that went through a
//! compound-assignment operator; this item is every OTHER way to reach it. A
//! stray `%` is a binary-only operator and cannot start a statement or an
//! expression in the Go DSL, so it reaches this arm directly. Before the fix
//! the Rust tier silently drops it and keeps parsing, compiling the contract
//! clean (exit 0) with the statement that held the `%` simply missing from
//! the output. Every other tier (TS reference, Go, Python, Zig, Ruby, Java)
//! refuses this input with a parse error.
//!
//! Frontend parity: the TS reference Go-surface parser (01-parse-go.ts,
//! `parsePrimary`'s final fallback) pushes a diagnostic for exactly this
//! case ("Unexpected token in expression: '%'") instead of inventing a
//! placeholder. The Rust tier must do the same: fail closed, not silently.
//!
//! What this test proves: a Go-DSL method body containing a statement that
//! cannot be parsed (`%` alone) is a compile ERROR in the Rust tier, naming
//! the unexpected token — matching the TS reference and the Go tier's
//! behaviour on the same source. It also proves the statement is not simply
//! vanishing: the pre-fix hex for the whole-method-dropped contract differs
//! from (there is no such hex any more, because compilation now fails).
//!
//! What this test does NOT prove: that the chosen diagnostic wording matches
//! any other tier's wording (the cross-tier rejection-parity gate deliberately
//! does not compare wording, only accept/reject), or that every other
//! unparseable-token shape reachable through this same recovery arm is
//! covered — only the minimal reproduction (a stray binary operator at
//! statement start) is exercised here.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

fn compile(source: &str) -> Result<String, String> {
    compile_from_source_str_with_options(source, Some("Drop.runar.go"), &CompileOptions::default())
        .map(|artifact| artifact.script)
}

const GOOD: &str = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Drop struct {
	runar.SmartContract
	Secret runar.Int `runar:"readonly"`
}

func (c *Drop) Verify(claim runar.Int) {
	runar.Assert(claim == c.Secret)
}
"#;

const WITH_STRAY_PERCENT: &str = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Drop struct {
	runar.SmartContract
	Secret runar.Int `runar:"readonly"`
}

func (c *Drop) Verify(claim runar.Int) {
	%
	runar.Assert(claim == c.Secret)
}
"#;

#[test]
fn control_without_the_stray_token_compiles() {
    compile(GOOD).expect("control contract without the stray '%' must compile");
}

#[test]
fn stray_token_that_cannot_start_a_statement_is_a_parse_error_not_a_silent_drop() {
    let result = compile(WITH_STRAY_PERCENT);
    let err = match result {
        Ok(hex) => panic!(
            "a bare '%' cannot start a statement in the Go DSL (it is a binary-only \
             operator) and must be refused like the TS reference and Go tier refuse it; \
             instead parse_block's recovery silently dropped the token and compiled to {hex}"
        ),
        Err(e) => e,
    };
    assert!(
        err.contains("Unexpected token") && err.contains("Percent"),
        "the parse error must name the unexpected token (rendered as the \
         tokenizer's own `Percent` variant, matching this file's existing \
         `expect_tok` catch-all diagnostics), got: {err}"
    );
}
