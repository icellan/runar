//! R-189 — a private method may shadow a builtin, and nothing upstream of ANF
//! lowering notices when the two disagree about arity.
//!
//! `typecheck` resolves a BARE-IDENTIFIER call against the builtin table
//! BEFORE it looks at the contract's own methods; `anf_lower` resolves the
//! same call against private methods FIRST. So `min(x, y)` against
//! `private min(a, b, c)` type-checks as the two-argument BUILTIN `min` and
//! then lowers as the three-parameter METHOD `min`. No validator forbids the
//! shadowing.
//!
//! The zip that bound params to args stopped at the shorter list. When the
//! surplus parameter was never read, the contract compiled CLEAN — an arity
//! mismatch silently accepted. When it was read, the defect surfaced two
//! passes later as "method parameter 'c' is not on the stack", a stack
//! lowering message about a pass the author never wrote in.

use runar_compiler_rust::compile_source_str_to_ir;

/// The silent case: the surplus parameter `c` is never read, so nothing
/// downstream ever noticed the missing binding.
const SURPLUS_PARAM_UNREAD: &str = r#"
class R189Unread extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    min(x, y);
  }
}
"#;

/// Too many arguments: `y` was evaluated and then dropped on the floor.
const TOO_MANY_ARGS: &str = r#"
class R189Extra extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint): bigint {
    this.count = a;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    min(x, y);
  }
}
"#;

/// Control 1: the SAME builtin-shadowing private, called at its real arity
/// through `this.` — the bare form cannot reach pass 4 at arity 3, because
/// pass 3 checks it against the two-argument BUILTIN `min` and refuses.
const CONTROL_SHADOWING_AT_REAL_ARITY: &str = r#"
class R189ControlShadow extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b + c;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint, z: bigint) {
    this.min(x, y, z);
  }
}
"#;

/// Control 2: an ordinary private helper, bare-identifier call at matching
/// arity — the Move / Go-DSL lowering path this refusal sits directly on.
/// Without the controls, a refusal that simply rejected every private call
/// would pass the two tests above.
const CONTROL_PLAIN_PRIVATE: &str = r#"
class R189ControlPlain extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private tally(a: bigint, b: bigint): bigint {
    this.count = a + b;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    tally(x, y);
  }
}
"#;

#[test]
fn surplus_parameter_is_refused_not_silently_dropped() {
    let err = compile_source_str_to_ir(SURPLUS_PARAM_UNREAD, Some("R189Unread.runar.ts"))
        .expect_err("arity mismatch was accepted: ANF lowering produced a program");
    assert!(
        err.contains("private method 'min' expects 3 argument(s), got 2."),
        "refusal does not name the mismatch: {err}"
    );
}

#[test]
fn surplus_argument_is_refused_not_silently_dropped() {
    let err = compile_source_str_to_ir(TOO_MANY_ARGS, Some("R189Extra.runar.ts"))
        .expect_err("arity mismatch was accepted: ANF lowering produced a program");
    assert!(
        err.contains("private method 'min' expects 1 argument(s), got 2."),
        "refusal does not name the mismatch: {err}"
    );
}

#[test]
fn matching_arity_still_lowers() {
    for (name, source) in [
        ("builtin-shadowing private at its real arity", CONTROL_SHADOWING_AT_REAL_ARITY),
        ("plain private helper, bare-identifier call", CONTROL_PLAIN_PRIVATE),
    ] {
        compile_source_str_to_ir(source, Some("R189Control.runar.ts"))
            .unwrap_or_else(|e| panic!("control '{name}' must still lower, got refusal: {e}"));
    }
}
