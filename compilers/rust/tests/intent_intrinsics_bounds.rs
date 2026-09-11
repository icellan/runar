//! R-2 / R-4 typecheck bounds for the BSVM Phase 13 intent sub-covenant
//! intrinsics `requireOutputP2PKH` and `extractPrevOutputScript`.
//!
//! Mirrors `compilers/go/frontend/intent_intrinsics_test.go` R-2/R-4
//! tests (see `TestRequireOutputP2PKH_OutputIndexBound_Rejects`, etc.).

use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::typecheck::typecheck;

fn typecheck_errors(source: &str) -> Vec<String> {
    let parse = parse_source(source, Some("Test.runar.go"));
    if !parse.errors.is_empty() {
        return parse.error_strings();
    }
    let contract = match parse.contract {
        Some(c) => c,
        None => return vec!["no contract".to_string()],
    };
    let tc = typecheck(&contract);
    tc.error_strings()
}

fn assert_error_contains(errors: &[String], substr: &str) {
    if errors.iter().any(|e| e.contains(substr)) {
        return;
    }
    panic!("expected error containing {:?}, got: {:?}", substr, errors);
}

// R-2 — requireOutputP2PKH index bound (0 <= idx <= 1000) ------------------

#[test]
fn test_require_output_p2pkh_output_index_bound_rejects() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    PKH runar.ByteString `runar:"readonly"`
    A   runar.Bigint     `runar:"readonly"`
}

func (c *Cov) Pay() {
    // 2000 > 1000 bound — should be rejected at typecheck.
    runar.RequireOutputP2PKH(2000, c.PKH, c.A)
}
"#;
    let errors = typecheck_errors(source);
    assert_error_contains(&errors, "bound to <= 1000");
}

#[test]
fn test_require_output_p2pkh_negative_index_rejects() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    PKH runar.ByteString `runar:"readonly"`
    A   runar.Bigint     `runar:"readonly"`
}

func (c *Cov) Pay() {
    runar.RequireOutputP2PKH(-1, c.PKH, c.A)
}
"#;
    let errors = typecheck_errors(source);
    assert_error_contains(&errors, "must be >= 0");
}

// R-4 — extractPrevOutputScript prefixLen bound (32 <= n <= 4 MiB) ---------

#[test]
fn test_extract_prev_output_script_prefix_len_too_small_rejects() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    H runar.ByteString `runar:"readonly"`
}

func (c *Cov) Bind() {
    // prefixLen=16 < 32 (hash size) — should be rejected.
    _ = runar.ExtractPrevOutputScript(0, c.H, 16)
}
"#;
    let errors = typecheck_errors(source);
    assert_error_contains(&errors, "must be >= 32");
}

#[test]
fn test_extract_prev_output_script_prefix_len_too_large_rejects() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    H runar.ByteString `runar:"readonly"`
}

func (c *Cov) Bind() {
    // prefixLen=10485760 > 4 MiB — should be rejected.
    _ = runar.ExtractPrevOutputScript(0, c.H, 10485760)
}
"#;
    let errors = typecheck_errors(source);
    assert_error_contains(&errors, "MAX_SCRIPT_BYTES");
}

// R-068 — `-0` index evades the literal gate and silently DELETES the covenant
//
// The typecheck index gate above accepts `UnaryExpr{Neg, BigIntLiteral}` only
// so that a negative index reports "must be >= 0" instead of the misleading
// "must be an integer literal". `-0` negates to `0`, so it passes that bound
// check — but ANF lowering matches on a bare `BigIntLiteral` and, finding a
// `UnaryExpr`, falls through to `load_const ""`: no witness param, no hash
// assertion, NO COVENANT, and no diagnostic. A contract whose whole purpose
// is the covenant compiles to a script that does not carry it.

/// Compile all the way to ANF IR. Returns Err(diagnostics) on rejection.
fn lower_to_ir_result(
    source: &str,
    file: &str,
) -> Result<runar_compiler_rust::ir::ANFProgram, String> {
    runar_compiler_rust::compile_source_str_to_ir(source, Some(file))
}

const EPS_NEG_ZERO_SRC: &str = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    H     runar.ByteString
    Count runar.Bigint
}

func (c *Cov) Bind() {
    s := runar.ExtractPrevOutputScript(-0, c.H)
    runar.Assert(runar.Len(s) > 0)
    c.Count = c.Count + 1
}
"#;

const ROP_NEG_ZERO_SRC: &str = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    PKH   runar.ByteString
    Amt   runar.Bigint
    Count runar.Bigint
}

func (c *Cov) Pay() {
    runar.RequireOutputP2PKH(-0, c.PKH, c.Amt)
    c.Count = c.Count + 1
}
"#;

#[test]
fn test_extract_prev_output_script_negative_zero_index_rejects() {
    let errors = typecheck_errors(EPS_NEG_ZERO_SRC);
    assert_error_contains(&errors, "must be an integer literal");
}

#[test]
fn test_require_output_p2pkh_negative_zero_index_rejects() {
    let errors = typecheck_errors(ROP_NEG_ZERO_SRC);
    assert_error_contains(&errors, "must be an integer literal");
}

/// The funds-safety half of the pair: a `-0` index must never reach codegen,
/// because when it does the intrinsic lowers to a bare empty-string constant
/// and the covenant it was supposed to install is simply absent.
#[test]
fn test_negative_zero_index_never_silently_drops_the_covenant() {
    for (label, src) in [
        ("extractPrevOutputScript", EPS_NEG_ZERO_SRC),
        ("requireOutputP2PKH", ROP_NEG_ZERO_SRC),
    ] {
        match lower_to_ir_result(src, "Test.runar.go") {
            Err(_) => {}
            Ok(program) => {
                let json = serde_json::to_string(&program).expect("serialize ANF");
                panic!(
                    "{}(-0, ...) compiled with NO diagnostic; covenant markers \
                     present: _prevOutScript_={} _serialisedOutputs={}",
                    label,
                    json.contains("_prevOutScript_"),
                    json.contains("_serialisedOutputs"),
                );
            }
        }
    }
}

// Controls — the valid forms must keep lowering exactly as before.

#[test]
fn test_literal_zero_index_still_installs_the_covenant() {
    let eps = EPS_NEG_ZERO_SRC.replace("ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(0,");
    let program = lower_to_ir_result(&eps, "Test.runar.go").expect("valid eps contract must lower");
    let json = serde_json::to_string(&program).expect("serialize ANF");
    assert!(
        json.contains("_prevOutScript_0"),
        "extractPrevOutputScript(0, ...) must still auto-inject its witness param"
    );

    let rop = ROP_NEG_ZERO_SRC.replace("RequireOutputP2PKH(-0,", "RequireOutputP2PKH(1,");
    let program = lower_to_ir_result(&rop, "Test.runar.go").expect("valid rop contract must lower");
    let json = serde_json::to_string(&program).expect("serialize ANF");
    assert!(
        json.contains("_serialisedOutputs"),
        "requireOutputP2PKH(1, ...) must still auto-inject _serialisedOutputs"
    );
}

#[test]
fn test_plain_negative_index_still_reports_the_bound_message() {
    let src = EPS_NEG_ZERO_SRC.replace("ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(-3,");
    let errors = typecheck_errors(&src);
    assert_error_contains(&errors, "must be >= 0");
}
