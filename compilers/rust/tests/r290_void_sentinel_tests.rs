//! R-290 — `inline_private_method_call` used to emit a
//! `load_const "@void"` sentinel when the inlined body produced no bindings.
//!
//! No tier's stack lowering recognises `"@void"` (unlike `"@this"`, which IS
//! special-cased), so the sentinel survived pass 4 and died in the hex
//! decoder: this tier said `invalid hex string length: 5`, Go said
//! `invalid byte: U+0040 '@'`. Neither names the method or the problem, and
//! both fire only because the string happens to be odd-length and non-hex —
//! an even-length sentinel would decode to zeros in
//! `codegen::stack`'s `from_str_radix(..).unwrap_or(0)` and reach the script.
//!
//! It is reachable. The side-effect summary resolves a called name through a
//! LAST-WINS map and caches the result under that name, while
//! `get_private_method` returns the FIRST match. Declare the public caller
//! BEFORE two same-named privates and the two disagree: the summary describes
//! the output-emitting `helper` (so `should_inline_private` is true) while the
//! lowerer inlines the empty one. Measured pre-fix on this tier's CLI:
//! `--emit-ir` exited 0 with `@void` in the IR.

use runar_compiler_rust::compile_source_str_to_ir;

const EMPTY_INLINED_BODY: &str = r#"
class R290Void extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(x: bigint) {
    this.count = x;
    this.helper();
  }

  private helper(): void {
  }

  private helper(): void {
    this.addOutput(1000n, this.count);
  }
}
"#;

/// Control: the ordinary shape — one private helper that really does emit an
/// output. The inlining path must still work; a refusal that simply rejected
/// every inlined private would pass the test above.
const CONTROL_EMITTING_HELPER: &str = r#"
class R290Control extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(x: bigint) {
    this.count = x;
    this.helper();
  }

  private helper(): void {
    this.addOutput(1000n, this.count);
  }
}
"#;

#[test]
fn empty_inlined_body_is_refused_not_sentinelled() {
    let err = compile_source_str_to_ir(EMPTY_INLINED_BODY, Some("R290Void.runar.ts"))
        .expect_err("the empty inlined body was accepted: ANF lowering produced a program");
    assert!(
        err.contains("private method 'helper' was inlined but produced no bindings"),
        "refusal does not name the method: {err}"
    );
}

#[test]
fn no_void_sentinel_remains() {
    // A refusal that still emitted the sentinel first would satisfy the test
    // above on some other path. Nothing may carry "@void" any more.
    let program = compile_source_str_to_ir(CONTROL_EMITTING_HELPER, Some("R290Control.runar.ts"))
        .expect("control must lower");
    let json = serde_json::to_string(&program).expect("ANF must serialise");
    assert!(!json.contains("@void"), "the @void sentinel is still emitted somewhere");
}

#[test]
fn emitting_helper_still_inlines() {
    compile_source_str_to_ir(CONTROL_EMITTING_HELPER, Some("R290Control.runar.ts"))
        .expect("control must still lower");
}
