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
