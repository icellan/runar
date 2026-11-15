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

//
// GK-BUG-015: the validator now refuses a repeated method name, so a SOURCE
// with two `helper` bodies never reaches pass 4 through the pipeline.
// `lower_to_anf` is a public entry point, so the backstop is still pinned on a
// hand-built duplicate: the source declares `helper` and `helper2` and the
// test renames the second on the parsed AST.

use runar_compiler_rust::compile_source_str_to_ir;
use runar_compiler_rust::frontend::anf_lower::lower_to_anf;
use runar_compiler_rust::frontend::ast::ContractNode;
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::validator::validate;

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

fn hand_built_duplicate() -> ContractNode {
    let parsed = parse_source(EMPTY_INLINED_BODY, Some("R290Void.runar.ts"));
    assert!(parsed.errors.is_empty(), "parse errors: {:?}", parsed.errors);
    let mut contract = parsed.contract.expect("contract");
    for m in contract.methods.iter_mut() {
        if m.name == "helper2" {
            m.name = "helper".to_string();
        }
    }
    contract
}

#[test]
fn hand_built_duplicate_is_a_validate_error() {
    let errs = validate(&hand_built_duplicate()).error_strings().join("\n");
    assert!(
        errs.contains("method 'helper' is already declared in this contract and cannot be re-declared"),
        "validate did not refuse the duplicate: {errs}"
    );
}

#[test]
fn empty_inlined_body_is_refused_not_sentinelled() {
    let contract = hand_built_duplicate();
    let err = std::panic::catch_unwind(|| lower_to_anf(&contract))
        .expect_err("the empty inlined body was accepted: ANF lowering produced a program");
    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert!(
        msg.contains("private method 'helper' was inlined but produced no bindings"),
        "refusal does not name the method: {msg}"
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
