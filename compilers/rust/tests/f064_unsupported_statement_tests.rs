//! F-064: every `.runar.ts` statement kind outside spec/grammar.md §9 must be
//! refused with the TS reference's diagnostic,
//! "Unsupported statement kind: <ts.SyntaxKind name>".
//!
//! The Go tier dropped all of these silently. This tier already refused them,
//! but (a) the message was a `{:?}` dump of the swc node, not the shared
//! diagnostic, and (b) an EMPTY bare block `{ }` returned `None` with no error
//! at all — a silent drop the reference refuses ("Unsupported statement kind:
//! Block").
//!
//! Proves: the Rust `.runar.ts` parser refuses each kind (top level and nested
//! in if/for) with the shared diagnostic. Does not prove: the other Rust-tier
//! surfaces (.runar.rs/.sol/.move/...), which have their own dispatchers.

use runar_compiler_rust::frontend::parser::parse_source;

fn wrap(stmt: &str) -> String {
    format!(
        r#"import {{ SmartContract, assert }} from 'runar-lang';

class Probe extends SmartContract {{
  readonly a: bigint;

  constructor(a: bigint) {{
    super(a);
    this.a = a;
  }}

  public unlock(x: bigint) {{
    {stmt}
    assert(x > this.a);
  }}
}}
"#
    )
}

const CASES: &[(&str, &str)] = &[
    ("while (x > 0n) { assert(false); }", "WhileStatement"),
    ("do { assert(false); } while (x > 0n);", "DoStatement"),
    ("switch (x) { case 1n: assert(false); break; default: assert(false); }", "SwitchStatement"),
    ("outer: for (let i = 0n; i < 2n; i++) { assert(false); }", "LabeledStatement"),
    ("try { assert(false); } catch (e) { assert(false); }", "TryStatement"),
    ("throw x;", "ThrowStatement"),
    ("for (const k in this) { assert(false); }", "ForInStatement"),
    ("for (const k of [x]) { assert(false); }", "ForOfStatement"),
    ("{ assert(false); }", "Block"),
    ("{ }", "Block"),
    (";", "EmptyStatement"),
    ("assert(x > 1n);;", "EmptyStatement"),
    ("const y = x;;", "EmptyStatement"),
    ("class Inner { }", "ClassDeclaration"),
    ("function inner(): void { assert(false); }", "FunctionDeclaration"),
    ("debugger;", "DebuggerStatement"),
];

#[test]
fn every_unsupported_statement_kind_is_refused_with_the_shared_diagnostic() {
    let mut failures = Vec::new();
    for (stmt, kind) in CASES {
        for body in [
            stmt.to_string(),
            format!("if (x > 0n) {{ {stmt} }}"),
            format!("for (let j = 0n; j < 2n; j++) {{ {stmt} }}"),
        ] {
            let res = parse_source(&wrap(&body), Some("Probe.runar.ts"));
            let want = format!("Unsupported statement kind: {kind}");
            if !res.errors.iter().any(|e| e.message == want) {
                failures.push(format!(
                    "`{body}`: expected {want:?}, got {:?}",
                    res.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
