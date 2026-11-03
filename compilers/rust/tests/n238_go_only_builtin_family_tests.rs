//! N-238: F-387 added `go_only_builtin_family()` in
//! `compilers/rust/src/frontend/typecheck.rs` so that calling
//! `merkleRootPoseidon2KB` from the Rust tier names the builtin and the
//! Go-only policy instead of saying "unknown function". That table only
//! covered the one builtin F-387 was about and explicitly left the other
//! seven Go-only builtins "a separate item" (see the comment above
//! `go_only_builtin_family`): `bn254Pairing`, `assertGroth16WitnessAssisted`,
//! `assertGroth16WitnessAssistedWithMSM`, `groth16PublicInput`,
//! `bn254MultiPairing3`, `bn254MultiPairing4`, and `verifySP1FRI`. This is
//! that item.
//!
//! The expected family labels are the ones Python already uses in its
//! `GO_ONLY_BUILTINS` table (R-258/R-259,
//! `compilers/python/runar_compiler/frontend/typecheck.py`):
//!   - "assertGroth16WitnessAssisted"        -> "BN254 + Groth16"
//!   - "assertGroth16WitnessAssistedWithMSM" -> "BN254 + Groth16"
//!   - "groth16PublicInput"                  -> "BN254 + Groth16"
//!   - "bn254Pairing"                        -> "BN254 pairing"
//!   - "bn254MultiPairing3"                  -> "BN254 pairing"
//!   - "bn254MultiPairing4"                  -> "BN254 pairing"
//!   - "verifySP1FRI"                        -> "SP1 FRI"
//!
//! RED at base (d207ee8e + F-387 only): `go_only_builtin_family()` returns
//! `None` for all seven of these names, so each falls through to the
//! generic "unknown function '<name>' -- only Rúnar built-in functions and
//! contract methods are allowed" message, exactly as `merkleRootPoseidon2KB`
//! did before F-387.
//!
//! This test only checks the DIAGNOSTIC, same scope as F-387's test: it does
//! not touch `codegen/stack.rs` / `ir/loader.rs` dispatch for these
//! builtins.

use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

/// One probe per builtin: a minimal `.runar.ts` contract that calls it by
/// name with two dummy `bigint` arguments. Arity/argument types do not
/// matter here -- `check_call_expr` never reaches `check_call_args` for a
/// name that isn't in `builtin_functions()`, so every call falls straight
/// through to the (name-only) `go_only_builtin_family` lookup.
fn diagnostics_for_call(builtin_name: &str) -> String {
    let source = format!(
        r#"
import {{ SmartContract, assert, {name} }} from 'runar-lang';

class Probe extends SmartContract {{
  readonly limit: bigint;

  constructor(limit: bigint) {{
    super(limit);
    this.limit = limit;
  }}

  public unlock(a: bigint, b: bigint) {{
    assert({name}(a, b) === this.limit);
  }}
}}
"#,
        name = builtin_name
    );

    let result = compile_from_source_str_with_result(&source, Some("Probe.runar.ts"), &CompileOptions::default());
    assert!(
        !result.success,
        "{} is Go-tier-only by policy; it must not typecheck in the Rust tier",
        builtin_name
    );
    result
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Asserts the shared shape of the fixed diagnostic for one builtin/family
/// pair: not reported as "unknown function", names the builtin, and names
/// the Go-tier policy.
fn assert_go_only_diagnostic(builtin_name: &str, expected_family: &str) {
    let msg = diagnostics_for_call(builtin_name);
    assert!(
        !msg.contains("unknown function"),
        "{} is a real Rúnar builtin, scoped to the Go tier by policy. Calling \
         it 'unknown' sends the author looking for a typo: {msg}",
        builtin_name
    );
    assert!(
        msg.contains(builtin_name),
        "diagnostic must name the builtin '{}'; got: {msg}",
        builtin_name
    );
    assert!(
        msg.contains(expected_family),
        "diagnostic must name the '{}' family (matching Python's GO_ONLY_BUILTINS \
         label); got: {msg}",
        expected_family
    );
    assert!(
        msg.to_lowercase().contains("go tier") || msg.to_lowercase().contains("go-only"),
        "diagnostic must say this builtin is scoped to the Go tier; got: {msg}"
    );
}

#[test]
fn bn254_pairing_names_bn254_pairing_family() {
    assert_go_only_diagnostic("bn254Pairing", "BN254 pairing");
}

#[test]
fn bn254_multi_pairing3_names_bn254_pairing_family() {
    assert_go_only_diagnostic("bn254MultiPairing3", "BN254 pairing");
}

#[test]
fn bn254_multi_pairing4_names_bn254_pairing_family() {
    assert_go_only_diagnostic("bn254MultiPairing4", "BN254 pairing");
}

#[test]
fn assert_groth16_witness_assisted_names_bn254_groth16_family() {
    assert_go_only_diagnostic("assertGroth16WitnessAssisted", "BN254 + Groth16");
}

#[test]
fn assert_groth16_witness_assisted_with_msm_names_bn254_groth16_family() {
    assert_go_only_diagnostic("assertGroth16WitnessAssistedWithMSM", "BN254 + Groth16");
}

#[test]
fn groth16_public_input_names_bn254_groth16_family() {
    assert_go_only_diagnostic("groth16PublicInput", "BN254 + Groth16");
}

#[test]
fn verify_sp1_fri_names_sp1_fri_family() {
    assert_go_only_diagnostic("verifySP1FRI", "SP1 FRI");
}
