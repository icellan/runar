//! NEW-012 — `return` in a PUBLIC method.
//!
//! `spec/grammar.md:161` makes public methods void, `:162` makes their trailing
//! assert the spending condition, and `spec/semantics.md` gives `return` no
//! early-exit meaning at all (§4.6 defines only "the value of this method is
//! v"; §4.7 sequences statements unconditionally).
//!
//! Lowering it as if it were the tail of an inlined helper produced two broken
//! scripts: `return;` left the enclosing arm with no result, so it yielded OP_0
//! and the whole script evaluated FALSE — an unspendable UTXO from source that
//! compiled clean; `return expr;` made the returned value the branch result and
//! hence the script's final truthiness, so any truthy expr spent the contract
//! WITHOUT reaching the guarding assert (fail-OPEN).

use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::validator::validate;

const DIAG: &str = "must not use `return`";

fn validate_ts(source: &str) -> Vec<String> {
    let parsed = parse_source(source, Some("Guard.runar.ts"));
    assert!(parsed.errors.is_empty(), "unexpected parse errors: {:?}", parsed.errors);
    let contract = parsed.contract.expect("expected a contract node");
    validate(&contract).errors.iter().map(|d| d.message.clone()).collect()
}

fn count(errors: &[String], substr: &str) -> usize {
    errors.iter().filter(|m| m.contains(substr)).count()
}

#[test]
fn rejects_bare_return_in_public_method() {
    let errors = validate_ts(
        r#"
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) { return; }
    assert(x === this.secret);
  }
}
"#,
    );
    assert_eq!(count(&errors, DIAG), 1, "{:?}", errors);
}

#[test]
fn rejects_valued_return_in_public_method() {
    let errors = validate_ts(
        r#"
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) { return x; }
    assert(x === this.secret);
  }
}
"#,
    );
    assert_eq!(count(&errors, DIAG), 1, "{:?}", errors);
}

#[test]
fn rejects_return_nested_in_loop_in_public_method() {
    let errors = validate_ts(
        r#"
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    for (let i: bigint = 0n; i < 4n; i++) {
      if (x > i) { return; }
    }
    assert(x === this.secret);
  }
}
"#,
    );
    assert_eq!(count(&errors, DIAG), 1, "{:?}", errors);
}

/// `spec/grammar.md:168` — "Private methods may return a value." The rejection
/// must not spill onto the inlined-helper form, which is how ~340 in-repo
/// contracts legitimately use `return`.
#[test]
fn allows_return_in_private_helper() {
    let errors = validate_ts(
        r#"
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  private doubled(v: bigint): bigint { return v + v; }

  public unlock(x: bigint) {
    assert(this.doubled(x) === this.secret);
  }
}
"#,
    );
    assert!(errors.is_empty(), "{:?}", errors);
}
