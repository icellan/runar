//! R-026: `expand-fixed-arrays` must not drop `CallExpr::asm_return_type`.
//!
//! `rewrite_expression` rebuilt every `CallExpr` field-by-field and hard-coded
//! `asm_return_type: None`. The captured return type of an expression-form
//! `asm<T>({...})` is what tells ANF lowering the value is byte-typed, which
//! is what makes `+` lower to OP_CAT instead of OP_ADD. Losing it does not
//! merely mis-tag a node — it emits a different opcode, so the script computes
//! a numeric sum where the author wrote a concatenation.
//!
//! Asserted at the AST level rather than on emitted opcodes: the Rust tier
//! separately never annotates a byte-typed `+` at all (`lower_binary_expr` in
//! `frontend/anf_lower.rs` handles `===`/`!==`/`&`/`|`/`^` but has no `+`
//! branch, despite the comment above it saying it does), so `ByteString`
//! concatenation emits OP_ADD in this tier whether or not a FixedArray is
//! present. That is a separate defect; an opcode assertion here would fail
//! for that reason instead of this one and could not discriminate.

const ARRAY_PROP: &str = "  readonly board: FixedArray<bigint, 3> = [1n, 2n, 3n];\n";

fn source(array_prop: &str, tail: &str) -> String {
    format!(
        r#"
class Boardy extends UnsafeSmartContract {{
{array_prop}  readonly n: bigint;
  constructor(n: bigint) {{ super(n); this.n = n; }}
  public go(): void {{
    const a: ByteString = asm<ByteString>({{ body: '00', in_arity: 0, out_arity: 1 }});
    const c: ByteString = a + a;
    assert(len(c) === 2n);
{tail}  }}
}}"#
    )
}

fn with_array() -> String {
    source(ARRAY_PROP, "    assert(this.board[0] === this.n);\n")
}

#[test]
fn asm_return_type_survives_fixed_array_expansion() {
    use runar_compiler_rust::frontend::ast::{Expression, Statement};
    use runar_compiler_rust::frontend::expand_fixed_arrays::expand_fixed_arrays;
    use runar_compiler_rust::frontend::parser::parse_source;

    let src = with_array();
    let parsed = parse_source(&src, Some("Boardy.runar.ts"));
    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    let contract = parsed.contract.expect("contract");

    let result = expand_fixed_arrays(&contract);
    assert!(result.errors.is_empty(), "{:?}", result.errors);

    let go = result
        .contract
        .methods
        .iter()
        .find(|m| m.name == "go")
        .expect("method go");
    match &go.body[0] {
        Statement::VariableDecl { name, init, .. } => {
            assert_eq!(name, "a");
            match init {
                Expression::CallExpr {
                    asm_return_type, ..
                } => assert_eq!(
                    asm_return_type.as_deref(),
                    Some("ByteString"),
                    "expand_fixed_arrays dropped CallExpr::asm_return_type"
                ),
                other => panic!("expected a CallExpr init, got {other:?}"),
            }
        }
        other => panic!("expected a variable declaration, got {other:?}"),
    }
}
