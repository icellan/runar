//! F-019 (CL-BUG-167, Rust half) — compound assignment in the `.runar.go` surface.
//!
//! The Rust tier's Go-DSL tokenizer knew only `+=` and `-=`. `x *= 2` lexed as
//! `Star Eq`, the expression parser gave up on the `=`, and `parse_block`'s
//! error-recovery skipped the statement token by token with NO diagnostic. The
//! contract compiled clean to a script that never multiplies:
//!
//!     x := a; x *= 2; runar.Assert(x == 8)   ->   script checks `a == 8`
//!
//! The same silent drop hit `/= %= &= |= ^= <<= >>= &^=`.
//!
//! Frontend parity: the TS reference Go-surface parser (01-parse-go.ts) accepts
//! exactly `+= -= *= /= %=` as compound assignments. So does the Go tier after
//! F-003. The Rust tier must desugar exactly those five to `x = x op rhs` and
//! refuse every other Go compound operator with a parse error.
//!
//! What these tests prove: for each of the five accepted operators, the Rust
//! tier emits a script byte-identical to the one it emits for the explicit
//! `x = x op 2` spelling (so the operation is present, with the right operator,
//! and in the right operand order); the dropped-statement script is a different
//! byte string, so the equality cannot hold by accident; and each of the six
//! unsupported operators — in a statement and in a `for` post clause — is a
//! compile error naming the operator.
//!
//! What they do not prove: that the explicit-spelling script is itself correct
//! Bitcoin Script (that is the job of the conformance suite and the script
//! execution oracle), or anything about the other six tiers' Go parsers.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

fn compile(source: &str) -> Result<String, String> {
    compile_from_source_str_with_options(source, Some("T.runar.go"), &CompileOptions::default())
        .map(|artifact| artifact.script)
}

fn go_contract(body: &str) -> String {
    format!(
        r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type T struct {{
    runar.SmartContract
}}

func (c *T) Verify(a runar.Int) {{
    x := a
{body}
    runar.Assert(x == 8)
}}
"#
    )
}

#[test]
fn supported_compound_assignments_desugar_to_x_eq_x_op_rhs() {
    let dropped = compile(&go_contract("")).expect("control without the statement compiles");

    for (compound, op) in [("+=", "+"), ("-=", "-"), ("*=", "*"), ("/=", "/"), ("%=", "%")] {
        let got = compile(&go_contract(&format!("    x {compound} 2")))
            .unwrap_or_else(|e| panic!("`x {compound} 2` must compile, got: {e}"));
        let want = compile(&go_contract(&format!("    x = x {op} 2")))
            .unwrap_or_else(|e| panic!("`x = x {op} 2` must compile, got: {e}"));
        assert_eq!(
            got, want,
            "`x {compound} 2` must emit the same script as `x = x {op} 2`"
        );
        assert_ne!(
            got, dropped,
            "`x {compound} 2` emitted the script of a contract WITHOUT the statement — \
             the compound assignment was silently dropped"
        );
    }
}

#[test]
fn unsupported_compound_assignments_are_parse_errors() {
    for compound in ["&=", "|=", "^=", "<<=", ">>=", "&^="] {
        let result = compile(&go_contract(&format!("    x {compound} 2")));
        let err = match result {
            Ok(hex) => panic!(
                "`x {compound} 2` must be refused (the TS reference Go parser accepts only \
                 += -= *= /= %=), but it compiled to {hex}"
            ),
            Err(e) => e,
        };
        assert!(
            err.contains("compound assignment") && err.contains(compound),
            "`x {compound} 2`: error must name the unsupported compound operator, got: {err}"
        );
    }
}

#[test]
fn unsupported_compound_assignment_in_for_post_is_a_parse_error() {
    for compound in ["&=", "|=", "^=", "<<=", ">>=", "&^="] {
        let body = format!(
            "    for i := runar.Int(0); i < 3; i {compound} 1 {{\n        x = x + i\n    }}"
        );
        let result = compile(&go_contract(&body));
        let err = match result {
            Ok(hex) => panic!("for-post `i {compound} 1` must be refused, but it compiled to {hex}"),
            Err(e) => e,
        };
        assert!(
            err.contains("compound assignment") && err.contains(compound),
            "for-post `i {compound} 1`: error must name the unsupported compound operator, got: {err}"
        );
    }
}
