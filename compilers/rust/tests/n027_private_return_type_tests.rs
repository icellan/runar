//! N-027 — a private method call typed `<unknown>` must not become a
//! type error.
//!
//! `packages/runar-compiler/src/passes/03-typecheck.ts:257-259` makes
//! `<unknown>` (and `<inferred>`) assignable in BOTH directions inside
//! `isSubtype`; the Rust port of `is_subtype` dropped that clause. Both
//! tiers infer a private method's return type with the same
//! environment-free walk (`inferMethodReturnType` / `infer_method_return_type`
//! over `inferExprTypeStatic` / `infer_expr_type_static`), so both yield
//! `<unknown>` whenever the returned expression is an identifier, a
//! property access, an index access, or a call to another private method.
//! TS/Go/Python then let the binding through; Rust alone reported
//! "Type '<unknown>' is not assignable to type 'bigint'".
//!
//! The boundary is the SHAPE OF THE RETURNED EXPRESSION, not the statement
//! count: `return x;` (one statement) fails, `assert(x > 0n); return x + x;`
//! (two statements) passes. The tests below pin that real rule.

use runar_compiler_rust::compile_from_source_str;
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::typecheck::typecheck;

fn typecheck_errors(source: &str) -> Vec<String> {
    let parse = parse_source(source, Some("Probe.runar.ts"));
    assert!(parse.errors.is_empty(), "unexpected parse errors: {:?}", parse.errors);
    let contract = parse.contract.expect("expected a contract node");
    typecheck(&contract).error_strings()
}

fn compile_hex(source: &str) -> String {
    compile_from_source_str(source, Some("Probe.runar.ts"))
        .unwrap_or_else(|e| panic!("expected a clean compile, got: {e}"))
        .script
}

// --- RED: the reported repro -------------------------------------------

/// A private helper whose body binds a local and returns it. TS, Go and
/// Python all emit `767c9300a0` for this contract.
const MULTI_STATEMENT_HELPER: &str = r#"
class Probe extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }

  private helper(x: bigint): bigint {
    const y: bigint = x + x;
    return y;
  }

  public settle(amount: bigint) {
    const paid: bigint = this.helper(amount);
    assert(paid > 0n);
  }
}
"#;

#[test]
fn multi_statement_private_helper_typechecks() {
    let errors = typecheck_errors(MULTI_STATEMENT_HELPER);
    assert!(errors.is_empty(), "expected no type errors, got: {:?}", errors);
}

#[test]
fn multi_statement_private_helper_compiles_to_the_cross_tier_hex() {
    assert_eq!(compile_hex(MULTI_STATEMENT_HELPER), "767c9300a0");
}

// --- The real boundary: returned-expression shape, not statement count ---

/// One statement, but the returned expression is a bare identifier, so
/// `infer_expr_type_static` yields `<unknown>` exactly like the repro.
/// If the trigger were "more than one statement" this would already pass.
#[test]
fn single_statement_identifier_return_typechecks() {
    let errors = typecheck_errors(
        r#"
class Probe extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }

  private ident(x: bigint): bigint { return x; }

  public settle(amount: bigint) {
    const paid: bigint = this.ident(amount);
    assert(paid > 0n);
  }
}
"#,
    );
    assert!(errors.is_empty(), "expected no type errors, got: {:?}", errors);
}

/// A property-access return is `<unknown>` too.
#[test]
fn property_access_return_typechecks() {
    let errors = typecheck_errors(
        r#"
class Probe extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }

  private getLimit(): bigint { return this.limit; }

  public settle(amount: bigint) {
    const cap: bigint = this.getLimit();
    assert(amount <= cap);
  }
}
"#,
    );
    assert!(errors.is_empty(), "expected no type errors, got: {:?}", errors);
}

/// A private helper that returns another private helper's call is
/// `<unknown>` (only builtins are in the static call table).
#[test]
fn nested_private_call_return_typechecks() {
    let errors = typecheck_errors(
        r#"
class Probe extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }

  private inner(x: bigint): bigint { return x * 2n; }
  private outer(x: bigint): bigint { return this.inner(x); }

  public settle(amount: bigint) {
    const paid: bigint = this.outer(amount);
    assert(paid > 0n);
  }
}
"#,
    );
    assert!(errors.is_empty(), "expected no type errors, got: {:?}", errors);
}

// --- Controls: shapes that already worked, so a regression is caught ----

/// The single-statement arithmetic form from the report. Already GREEN
/// before the fix; must stay GREEN.
#[test]
fn control_single_statement_arithmetic_helper_still_compiles() {
    let source = r#"
class Probe extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }

  private double(x: bigint): bigint { return x + x; }

  public settle(amount: bigint) {
    const paid: bigint = this.double(amount);
    assert(paid > 0n);
  }
}
"#;
    assert!(typecheck_errors(source).is_empty());
    assert_eq!(compile_hex(source), "767c9300a0");
}

/// Two statements, arithmetic return. Already GREEN before the fix —
/// this is the pair that disproves "the trigger is statement count".
#[test]
fn control_two_statement_arithmetic_helper_still_compiles() {
    let source = r#"
class Probe extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }

  private helper(x: bigint): bigint {
    assert(x > 0n);
    return x + x;
  }

  public settle(amount: bigint) {
    const paid: bigint = this.helper(amount);
    assert(paid > 0n);
  }
}
"#;
    assert!(typecheck_errors(source).is_empty());
    assert_eq!(compile_hex(source), "7600a069767c9300a0");
}

// --- Negatives: real type errors must still be REJECTED -----------------
//
// The lazy "fix" is to stop typechecking private method calls (or to make
// every private call `<unknown>`). Each test below stays RED under that
// shortcut, because each one depends on a private method's INFERRED return
// type still being compared against a declared type.

/// A private helper whose body genuinely returns a bigint, bound to a
/// `ByteString`. Inference gives `bigint`; the mismatch must be reported.
#[test]
fn negative_private_helper_returning_wrong_type_is_rejected() {
    let errors = typecheck_errors(
        r#"
class Probe extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }

  private helper(x: bigint): ByteString { return x + x; }

  public settle(amount: bigint) {
    const blob: ByteString = this.helper(amount);
    assert(len(blob) > 0n);
  }
}
"#,
    );
    assert!(
        errors.iter().any(|e| e.contains("is not assignable to type 'ByteString'")),
        "expected a bigint-vs-ByteString assignability error, got: {:?}",
        errors
    );
}

/// Same, the other way round: a helper returning a ByteString bound to a
/// `bigint`.
#[test]
fn negative_bytestring_helper_bound_to_bigint_is_rejected() {
    let errors = typecheck_errors(
        r#"
class Probe extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }

  private digest(x: ByteString): ByteString { return sha256(x); }

  public settle(blob: ByteString) {
    const n: bigint = this.digest(blob);
    assert(n > 0n);
  }
}
"#,
    );
    assert!(
        errors.iter().any(|e| e.contains("is not assignable to type 'bigint'")),
        "expected a ByteString-vs-bigint assignability error, got: {:?}",
        errors
    );
}

/// A boolean-returning helper bound to a `bigint`. Guards the third
/// inference family.
#[test]
fn negative_boolean_helper_bound_to_bigint_is_rejected() {
    let errors = typecheck_errors(
        r#"
class Probe extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }

  private isBig(x: bigint): boolean { return x > 100n; }

  public settle(amount: bigint) {
    const n: bigint = this.isBig(amount);
    assert(n > 0n);
  }
}
"#,
    );
    assert!(
        errors.iter().any(|e| e.contains("is not assignable to type 'bigint'")),
        "expected a boolean-vs-bigint assignability error, got: {:?}",
        errors
    );
}

/// A plain (non-call) assignability violation must still be caught — the
/// `<unknown>` wildcard must not turn `is_subtype` into a rubber stamp.
#[test]
fn negative_direct_literal_mismatch_is_rejected() {
    let errors = typecheck_errors(
        r#"
class Probe extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }

  public settle(amount: bigint) {
    const blob: ByteString = amount + 1n;
    assert(len(blob) > 0n);
  }
}
"#,
    );
    assert!(
        errors.iter().any(|e| e.contains("is not assignable to type 'ByteString'")),
        "expected a bigint-vs-ByteString assignability error, got: {:?}",
        errors
    );
}
