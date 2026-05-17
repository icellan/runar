//! Frontend tests for the BSVM Phase 13 intent sub-covenant intrinsics:
//! `extractPrevOutputScript`, `requireOutputP2PKH`, `currentBlockHeight`.
//!
//! These three are pure frontend sugar — they desugar to existing ANF
//! primitives. No new ANF kind or stack codegen change. Mirrors
//! `compilers/go/frontend/intent_intrinsics_test.go`.

use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::typecheck::typecheck;
use runar_compiler_rust::ir::{ANFMethod, ANFProgram, ANFValue};
use runar_compiler_rust::compile_source_str_to_ir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lower_go(source: &str) -> ANFProgram {
    compile_source_str_to_ir(source, Some("Test.runar.go"))
        .unwrap_or_else(|e| panic!("expected lowering to succeed; got: {}", e))
}

/// Run parse + typecheck only (bypassing the validator's "must end with
/// assert()" gate, which would otherwise mask typecheck-level errors like
/// non-literal intrinsic indices or stateless misuse). Returns formatted
/// typecheck error strings.
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

fn find_method<'a>(p: &'a ANFProgram, name: &str) -> &'a ANFMethod {
    p.methods
        .iter()
        .find(|m| m.name == name)
        .unwrap_or_else(|| {
            let names: Vec<&str> = p.methods.iter().map(|m| m.name.as_str()).collect();
            panic!("method {:?} not found; got: {:?}", name, names)
        })
}

fn param_names(m: &ANFMethod) -> Vec<&str> {
    m.params.iter().map(|p| p.name.as_str()).collect()
}

fn assert_error_contains(errors: &[String], substr: &str) {
    if errors.iter().any(|e| e.contains(substr)) {
        return;
    }
    panic!("expected error containing {:?}, got: {:?}", substr, errors);
}

// ---------------------------------------------------------------------------
// extractPrevOutputScript
// ---------------------------------------------------------------------------

#[test]
fn test_extract_prev_output_script_auto_injects_witness_param() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
    runar.StatefulSmartContract
    StateCovScriptHash runar.ByteString `runar:"readonly"`
}

func (c *IntentCov) CoSpend() {
    stateCovScript := runar.ExtractPrevOutputScript(0, c.StateCovScriptHash)
    runar.Assert(runar.Len(stateCovScript) > 0)
}
"#;
    let p = lower_go(source);
    let m = find_method(&p, "coSpend");
    let names = param_names(m);
    assert!(
        names.contains(&"_prevOutScript_0"),
        "expected '_prevOutScript_0' in params, got {:?}",
        names
    );
    assert!(
        names.contains(&"txPreimage"),
        "expected 'txPreimage' in params, got {:?}",
        names
    );
}

#[test]
fn test_extract_prev_output_script_two_indices_produce_two_params() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
    runar.StatefulSmartContract
    H0 runar.ByteString `runar:"readonly"`
    H1 runar.ByteString `runar:"readonly"`
}

func (c *IntentCov) CoSpend() {
    a := runar.ExtractPrevOutputScript(0, c.H0)
    b := runar.ExtractPrevOutputScript(1, c.H1)
    runar.Assert(runar.Len(a) > 0)
    runar.Assert(runar.Len(b) > 0)
}
"#;
    let p = lower_go(source);
    let m = find_method(&p, "coSpend");
    let names = param_names(m);
    for want in &["_prevOutScript_0", "_prevOutScript_1"] {
        assert!(
            names.contains(want),
            "expected {:?} in params, got {:?}",
            want,
            names
        );
    }
}

#[test]
fn test_extract_prev_output_script_same_index_is_idempotent() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
    runar.StatefulSmartContract
    H0 runar.ByteString `runar:"readonly"`
}

func (c *IntentCov) CoSpend() {
    a := runar.ExtractPrevOutputScript(0, c.H0)
    b := runar.ExtractPrevOutputScript(0, c.H0)
    runar.Assert(runar.Len(a) > 0)
    runar.Assert(runar.Len(b) > 0)
}
"#;
    let p = lower_go(source);
    let m = find_method(&p, "coSpend");
    let count = m
        .params
        .iter()
        .filter(|p| p.name == "_prevOutScript_0")
        .count();
    assert_eq!(
        count, 1,
        "expected exactly one _prevOutScript_0 param, got {}",
        count
    );
}

#[test]
fn test_extract_prev_output_script_non_literal_index_errors() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
    runar.StatefulSmartContract
    H0 runar.ByteString `runar:"readonly"`
}

func (c *IntentCov) CoSpend(idx runar.Bigint) {
    s := runar.ExtractPrevOutputScript(idx, c.H0)
    runar.Assert(runar.Len(s) > 0)
}
"#;
    let errors = typecheck_errors(source);
    assert_error_contains(&errors, "must be an integer literal");
}

// ---------------------------------------------------------------------------
// requireOutputP2PKH
// ---------------------------------------------------------------------------

#[test]
fn test_require_output_p2pkh_auto_injects_serialised_outputs() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayBond() {
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
"#;
    let p = lower_go(source);
    let m = find_method(&p, "payBond");
    let names = param_names(m);
    assert!(
        names.contains(&"_serialisedOutputs"),
        "expected '_serialisedOutputs' in params, got {:?}",
        names
    );
}

#[test]
fn test_require_output_p2pkh_multiple_calls_one_serialised_outputs_param() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayMulti() {
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
    runar.RequireOutputP2PKH(1, c.BondPKH, c.Bond)
}
"#;
    let p = lower_go(source);
    let m = find_method(&p, "payMulti");
    let count = m
        .params
        .iter()
        .filter(|p| p.name == "_serialisedOutputs")
        .count();
    assert_eq!(
        count, 1,
        "expected exactly one _serialisedOutputs param across multiple intrinsic calls, got {}",
        count
    );
}

#[test]
fn test_require_output_p2pkh_non_literal_index_errors() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayBond(idx runar.Bigint) {
    runar.RequireOutputP2PKH(idx, c.BondPKH, c.Bond)
}
"#;
    let errors = typecheck_errors(source);
    assert_error_contains(&errors, "must be an integer literal");
}

// ---------------------------------------------------------------------------
// currentBlockHeight
// ---------------------------------------------------------------------------

#[test]
fn test_current_block_height_desugars_to_extract_locktime() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    Deadline runar.Bigint `runar:"readonly"`
}

func (c *Cov) Spend() {
    h := runar.CurrentBlockHeight()
    runar.Assert(h <= c.Deadline)
}
"#;
    let p = lower_go(source);
    let m = find_method(&p, "spend");
    let saw_extract_locktime = m.body.iter().any(|b| match &b.value {
        ANFValue::Call { func, .. } => func == "extractLocktime",
        _ => false,
    });
    assert!(
        saw_extract_locktime,
        "expected currentBlockHeight() to desugar to extractLocktime call in spend.body"
    );
}

#[test]
fn test_current_block_height_stateless_contract_errors() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Sl struct {
    runar.SmartContract
    Deadline runar.Bigint `runar:"readonly"`
}

func (c *Sl) Spend() {
    h := runar.CurrentBlockHeight()
    runar.Assert(h <= c.Deadline)
}
"#;
    let errors = typecheck_errors(source);
    assert_error_contains(&errors, "StatefulSmartContract");
}

// ---------------------------------------------------------------------------
// Crit-2 — extractPrevOutputScript 3-arg prefix-hash form
// ---------------------------------------------------------------------------

#[test]
fn test_extract_prev_output_script_prefix_form_lowers_with_substr() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentTemplate struct {
    runar.StatefulSmartContract
    ExpectedPolicyPrefixHash runar.ByteString `runar:"readonly"`
}

func (c *IntentTemplate) Bind() {
    s := runar.ExtractPrevOutputScript(0, c.ExpectedPolicyPrefixHash, 600)
    runar.Assert(runar.Len(s) > 0)
}
"#;
    let p = lower_go(source);
    let m = find_method(&p, "bind");
    // Expect a substr call inside the method body whose first arg is the
    // load_param for _prevOutScript_0 — that's the prefix extraction that
    // precedes the hash256.
    let mut saw_prefix_substr = false;
    for (i, b) in m.body.iter().enumerate() {
        if let ANFValue::Call { func, args } = &b.value {
            if func == "substr" && args.len() == 3 {
                let first_arg = &args[0];
                for j in 0..i {
                    let prior = &m.body[j];
                    if &prior.name == first_arg {
                        if let ANFValue::LoadParam { name } = &prior.value {
                            if name == "_prevOutScript_0" {
                                saw_prefix_substr = true;
                                break;
                            }
                        }
                    }
                }
                if saw_prefix_substr {
                    break;
                }
            }
        }
    }
    assert!(
        saw_prefix_substr,
        "expected substr(load_param(_prevOutScript_0), …) for 3-arg prefix form; body={:?}",
        m.body
    );
}

#[test]
fn test_extract_prev_output_script_prefix_form_non_literal_prefix_len_errors() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    H runar.ByteString `runar:"readonly"`
}

func (c *Cov) Bind(n runar.Bigint) {
    _ = runar.ExtractPrevOutputScript(0, c.H, n)
}
"#;
    let errors = typecheck_errors(source);
    assert_error_contains(&errors, "prefixLen) must be an integer literal");
}

#[test]
fn test_extract_prev_output_script_too_many_args_errors() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    H runar.ByteString `runar:"readonly"`
}

func (c *Cov) Bind() {
    _ = runar.ExtractPrevOutputScript(0, c.H, 600, 999)
}
"#;
    let errors = typecheck_errors(source);
    assert_error_contains(&errors, "expects 2 or 3 arguments");
}

// ---------------------------------------------------------------------------
// Crit-3 — requireOutputP2PKH + addDataOutput mix rejection
// ---------------------------------------------------------------------------

#[test]
fn test_require_output_p2pkh_mixed_with_add_data_output_errors() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
    Tag     runar.ByteString `runar:"readonly"`
}

func (c *Cov) PayBondAndAnnounce() {
    c.AddDataOutput(0, c.Tag)
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
"#;
    let errors = typecheck_errors(source);
    assert_error_contains(&errors, "mixes requireOutputP2PKH() with addDataOutput()");
}

#[test]
fn test_require_output_p2pkh_without_add_data_output_ok() {
    let source = r#"
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayBond() {
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
"#;
    // Must lower without errors (no mix).
    let _ = lower_go(source);
}
