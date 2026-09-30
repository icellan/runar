//! N-048 (external "PrematurePeek"): pass 3b hoists a computed FixedArray
//! index to `const __idx_K` in front of its whole statement. In
//!
//!     assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);
//!
//! that bound the index BEFORE the increment, so the gate read the
//! pre-increment slot (an outsider spend at cursor 0 was accepted under the
//! real @bsv/sdk Spend). The AST has no let-expression, so every hoist that
//! would reorder evaluation is refused with the diagnostic shared by all seven
//! tiers.
//!
//! Proves: the same refused / accepted shapes as the TS reference
//! (packages/runar-compiler/src/__tests__/03b-expand-fixed-arrays.test.ts).
//! Does not prove on-chain behaviour; the TS VM test and
//! conformance/negatives/N120-N122 cover that across tiers.

use runar_compiler_rust::frontend::ast::Statement;
use runar_compiler_rust::frontend::expand_fixed_arrays::{expand_fixed_arrays, ExpandResult};
use runar_compiler_rust::frontend::parser::parse_source;

const DIAG: &str = "FixedArray index would be evaluated out of source order";

fn expand(body: &str) -> ExpandResult {
    let src = format!(
        r#"
class Peek extends StatefulSmartContract {{
  readonly enabled: FixedArray<bigint, 2> = [1n, 0n];
  slots: FixedArray<bigint, 2> = [0n, 0n];
  cursor: bigint;
  constructor(cursor: bigint) {{ super(cursor); this.cursor = cursor; }}
  public release(k: bigint, c: boolean) {{
    {}
  }}
}}
"#,
        body
    );
    let pr = parse_source(&src, Some("Peek.runar.ts"));
    assert!(pr.errors.is_empty(), "parse errors: {:?}", pr.errors);
    expand_fixed_arrays(pr.contract.as_ref().expect("contract"))
}

fn joined(r: &ExpandResult) -> String {
    r.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>().join("\n")
}

#[test]
fn n048_refuses_reordering_hoist() {
    let cases = [
        ("the reported shape", "assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);"),
        ("index after an earlier ++", "assert(++this.cursor + this.enabled[this.cursor % 2n] > 0n);"),
        ("index after an output intrinsic", r#"assert(this.addRawOutput(1n, toByteString("00")) === this.enabled[this.cursor % 2n]);"#),
        ("right operand of &&", "assert(k > 0n && this.enabled[k - 1n] === 1n);"),
        ("right operand of ||", "assert(k === 0n || this.enabled[k - 1n] === 1n);"),
        ("ternary arm", "assert((c ? this.enabled[k + 1n] : 0n) === 0n);"),
        ("own ++ ahead of an earlier read", "assert(this.cursor + this.enabled[++this.cursor % 2n] > 0n);"),
        ("value read after target-index effect", "this.slots[++this.cursor % 2n] = this.enabled[this.cursor % 2n]; assert(true);"),
    ];
    for (what, body) in cases {
        let r = expand(body);
        assert!(joined(&r).contains(DIAG), "{}: expected refusal, got {:?}", what, joined(&r));
    }
}

#[test]
fn n048_accepts_order_preserving_hoist() {
    let cases = [
        ("increment in its own statement", "++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);"),
        ("left operand of &&", "assert(this.enabled[k - 1n] === 1n && k > 0n);"),
        ("ternary condition", "assert((this.enabled[k + 1n] === 1n ? 1n : 0n) === 1n);"),
        ("effect after the read", "assert(this.enabled[this.cursor % 2n] + ++this.cursor > 0n);"),
        ("statement-form read", "const v = this.enabled[k + 1n]; assert(v === 1n);"),
        ("computed write index, effectful value", "this.slots[this.cursor % 2n] = ++this.cursor; assert(true);"),
    ];
    for (what, body) in cases {
        let r = expand(body);
        assert!(!joined(&r).contains(DIAG), "{}: unexpected refusal {:?}", what, joined(&r));
    }
}

#[test]
fn n048_split_form_hoists_after_increment() {
    let r = expand("++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);");
    assert!(r.errors.is_empty(), "{:?}", joined(&r));
    let m = r.contract.methods.iter().find(|m| m.name == "release").unwrap();
    assert!(matches!(m.body[0], Statement::ExpressionStatement { .. }), "{:?}", m.body[0]);
    match &m.body[1] {
        Statement::VariableDecl { name, .. } => assert!(name.starts_with("__idx_"), "{}", name),
        other => panic!("body[1] = {:?}, want the __idx_* binding", other),
    }
}
