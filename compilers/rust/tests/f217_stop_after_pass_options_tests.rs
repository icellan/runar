//! F-217 — `parse_only` / `validate_only` / `typecheck_only` on `CompileOptions`
//! were honored only by `compile_from_source_str_with_result`. Every other
//! `_with_options` entry point (`compile_from_source_str_with_options`,
//! `compile_source_str_to_ir_with_options`, `compile_from_program_with_options`,
//! `compile_from_ir_str_with_options`) read the fields nowhere and silently ran
//! every later pass, so behavior depended on which return type the caller
//! happened to pick rather than on the option itself.
//!
//! Fix: those entry points cannot express "stopped successfully with no
//! output" — their return type is `Result<RunarArtifact, String>` or
//! `Result<ANFProgram, String>`, and there is no value to put in `Ok` after
//! stopping at an earlier pass. They now reject the option explicitly, before
//! running any pass, and point the caller at
//! `compile_from_source_str_with_result`, which already honors it.
//!
//! Proves: setting any of the three options on one of the plain APIs is
//! refused immediately — in particular, the refusal happens BEFORE later
//! passes run, so a `parse_only` caller never sees a validation error leak
//! through (the exact failure mode in the bug report). Also proves
//! `compile_from_source_str_with_result` (the already-correct, dedicated
//! partial-compilation API) is untouched by this change.
//!
//! Does not prove anything about Go/Python/Zig/Ruby/Java/TS, which are out of
//! scope for this item (Rust-only `Tier`), nor does it prove `main.rs`'s CLI
//! wiring is affected — no CLI flag sets these options on the plain APIs
//! today (audited: only `--parse-only`, which bypasses `CompileOptions`
//! entirely via `frontend_validate`).

use runar_compiler_rust::{
    compile_from_ir_str_with_options, compile_from_program_with_options,
    compile_from_source_str_with_options, compile_from_source_str_with_result,
    compile_source_str_to_ir, compile_source_str_to_ir_with_options, CompileOptions,
};

/// A valid, simple contract — used to build an `ANFProgram` for the
/// direct-program entry point test below.
const VALID_SOURCE: &str = r#"
import { SmartContract, assert } from 'runar-lang';

class Valid extends SmartContract {
  readonly owner: bigint;

  constructor(owner: bigint) {
    super(owner);
    this.owner = owner;
  }

  public spend() {
    assert(this.owner > 0n);
  }
}
"#;

/// Parses fine (valid Rúnar syntax) but fails validation: a `SmartContract`
/// property must be `readonly`; `owner` here is not.
const PARSEABLE_BUT_VALIDATION_INVALID: &str = r#"
import { SmartContract, assert } from 'runar-lang';

class Invalid extends SmartContract {
  owner: bigint;

  constructor(owner: bigint) {
    super(owner);
    this.owner = owner;
  }

  public spend() {
    assert(this.owner > 0n);
  }
}
"#;

/// Control: confirms the fixture really is parseable-but-validation-invalid
/// under default options. If this fails, the "red" assertions below are
/// vacuous (the fixture change, not the option, is what fails).
#[test]
fn control_fixture_is_validation_invalid_not_parse_invalid() {
    let err = compile_from_source_str_with_options(
        PARSEABLE_BUT_VALIDATION_INVALID,
        Some("Invalid.runar.ts"),
        &CompileOptions::default(),
    )
    .expect_err("fixture must fail compilation under default options");
    assert!(
        err.contains("Validation errors") && err.contains("must be readonly"),
        "expected a validation error, got: {}",
        err
    );
}

/// F-217 red/green: `parse_only` on `compile_from_source_str_with_options`.
/// Before the fix this ran validate/typecheck anyway and returned the
/// validation error. After the fix it must reject the unsupported option
/// instead — and must do so without ever reaching validation.
#[test]
fn parse_only_is_rejected_before_validation_runs() {
    let opts = CompileOptions { parse_only: true, ..Default::default() };
    let err = compile_from_source_str_with_options(
        PARSEABLE_BUT_VALIDATION_INVALID,
        Some("Invalid.runar.ts"),
        &opts,
    )
    .expect_err("parse_only must be rejected, not silently ignored");
    assert!(
        !err.contains("Validation errors"),
        "parse_only leaked a validation-pass error instead of being rejected up front: {}",
        err
    );
    assert!(
        err.contains("parse_only"),
        "rejection message should name the unsupported option: {}",
        err
    );
}

/// Same option, same fixture, on the sibling IR-producing entry point.
#[test]
fn validate_only_is_rejected_on_source_to_ir_api() {
    let opts = CompileOptions { validate_only: true, ..Default::default() };
    let err = compile_source_str_to_ir_with_options(
        PARSEABLE_BUT_VALIDATION_INVALID,
        Some("Invalid.runar.ts"),
        &opts,
    )
    .expect_err("validate_only must be rejected, not silently ignored");
    assert!(
        err.contains("validate_only"),
        "rejection message should name the unsupported option: {}",
        err
    );
}

/// `typecheck_only` on `compile_from_program_with_options` (direct-program
/// entry point). Before the fix this compiled a perfectly valid program all
/// the way through and returned `Ok`, silently ignoring the option.
#[test]
fn typecheck_only_is_rejected_on_direct_program_api() {
    let program = compile_source_str_to_ir(VALID_SOURCE, Some("Valid.runar.ts"))
        .expect("VALID_SOURCE must lower to ANF");
    let opts = CompileOptions { typecheck_only: true, ..Default::default() };
    let result = compile_from_program_with_options(&program, &opts);
    assert!(
        result.is_err(),
        "typecheck_only must be rejected on compile_from_program_with_options, not silently ignored"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("typecheck_only"),
        "rejection message should name the unsupported option: {}",
        err
    );
}

/// Same option, same shape of input, via the string-IR entry point
/// (`compile_from_ir_str_with_options`), which loads through the IR loader
/// rather than raw serde — covers the delegation path separately from the
/// direct-program test above.
#[test]
fn parse_only_is_rejected_on_ir_str_api() {
    let ir_json = r#"{
        "contractName": "P2PKH",
        "properties": [
            {"name": "pubKeyHash", "type": "Addr", "readonly": true}
        ],
        "methods": [{
            "name": "unlock",
            "params": [
                {"name": "sig", "type": "Sig"},
                {"name": "pubKey", "type": "PubKey"}
            ],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "sig"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "pubKey"}},
                {"name": "t2", "value": {"kind": "load_prop", "name": "pubKeyHash"}},
                {"name": "t3", "value": {"kind": "call", "func": "hash160", "args": ["t1"]}},
                {"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t3", "right": "t2"}},
                {"name": "t5", "value": {"kind": "assert", "value": "t4"}},
                {"name": "t6", "value": {"kind": "call", "func": "checkSig", "args": ["t0", "t1"]}},
                {"name": "t7", "value": {"kind": "assert", "value": "t6"}}
            ],
            "isPublic": true
        }]
    }"#;
    let opts = CompileOptions { parse_only: true, ..Default::default() };
    let err = compile_from_ir_str_with_options(ir_json, &opts)
        .expect_err("parse_only must be rejected on compile_from_ir_str_with_options");
    assert!(
        err.contains("parse_only"),
        "rejection message should name the unsupported option: {}",
        err
    );
}

/// Regression guard: the dedicated partial-compilation API
/// (`compile_from_source_str_with_result`) is unaffected — it already
/// honors `parse_only` by returning a successful partial `CompileResult`
/// with no error diagnostics and the parsed contract present.
#[test]
fn with_result_api_still_honors_parse_only() {
    let result = compile_from_source_str_with_result(
        PARSEABLE_BUT_VALIDATION_INVALID,
        Some("Invalid.runar.ts"),
        &CompileOptions { parse_only: true, ..Default::default() },
    );
    assert!(
        result.success,
        "compile_from_source_str_with_result must still stop successfully after parse"
    );
    assert!(result.contract.is_some());
}
