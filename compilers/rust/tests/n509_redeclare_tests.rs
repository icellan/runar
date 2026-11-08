//! N-509: a local cannot be re-declared in the same scope (spec/grammar.md).
//! One scope = one statement list; a method's parameters belong to its body's
//! top-level list. Shadowing in a NESTED list is not a re-declaration.
//! Mirrors packages/runar-compiler/src/__tests__/02-validate.test.ts (N-509).

use runar_compiler_rust::frontend::diagnostic::Diagnostic;
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::validator::validate;

fn source(body: &str, ctor: Option<&str>) -> String {
    let ctor = ctor.unwrap_or("super(k);\n    this.k = k;");
    format!(
        "\nclass R extends SmartContract {{\n  readonly k: bigint;\n  constructor(k: bigint) {{\n    {}\n  }}\n  public unlock(p: bigint, c: boolean) {{\n    {}\n  }}\n}}\n",
        ctor, body
    )
}

fn msg(name: &str) -> String {
    format!("'{}' is already declared in this scope and cannot be re-declared", name)
}

fn errors(src: &str) -> Vec<Diagnostic> {
    let r = parse_source(src, Some("R.runar.ts"));
    assert!(r.errors.is_empty(), "parse errors: {:?}", r.errors);
    validate(&r.contract.expect("contract")).errors
}

#[test]
fn refuses_same_scope_redeclaration() {
    let cases: &[(&str, &str, Option<&str>)] = &[
        ("const a = 1n; const a = 2n; assert(a == p);", "a", None),
        ("let x = 1n; let x = 2n; assert(x == p);", "x", None),
        ("const a = 1n; let a = 2n; a = 3n; assert(a == p);", "a", None),
        ("if (c) { let y = 1n; let y = 2n; assert(y == p); } assert(c);", "y", None),
        ("if (c) { assert(c); } else { let y = 1n; let y = 2n; assert(y == p); }", "y", None),
        ("let s = 0n; for (let i = 0n; i < 2n; i++) { let t = i; let t = i; s = s + t; } assert(s == p);", "t", None),
        ("let p = 5n; assert(p == this.k && c);", "p", None),
        ("assert(p == this.k && c);", "k", Some("super(k);\n    this.k = k;\n    const k = 2n;\n    assert(k > 0n);")),
    ];
    for (body, id, ctor) in cases {
        let n = errors(&source(body, *ctor)).iter().filter(|d| d.message == msg(id)).count();
        assert_eq!(n, 1, "want exactly one {:?} for {:?}", msg(id), body);
    }
}

#[test]
fn reports_the_second_declaration() {
    let errs = errors(&source("const a = 1n;\n    const a = 2n;\n    assert(a == p);", None));
    let d = errs.iter().find(|d| d.message == msg("a")).expect("no re-declaration error");
    assert_eq!(d.loc.as_ref().map(|l| l.line), Some(10));
}

#[test]
fn accepts_shadowing_and_siblings() {
    let cases = [
        "let x = 1n; if (c) { let x = 2n; assert(x == 2n); } assert(x == p);",
        "if (c) { let p = 5n; assert(p == 5n); } assert(p == this.k);",
        "const k = 5n; assert(k == p + this.k && c);",
        "let s = 0n; for (let i = 0n; i < 2n; i++) { let i = 7n; s = s + i; } assert(s == p && c);",
        "if (c) { let y = 1n; assert(y == p); } else { let y = 2n; assert(y == p); }",
        "if (c) { let y = 1n; assert(y == p); } let y = 2n; assert(y == p);",
        "let s = 0n; for (let i = 0n; i < 2n; i++) { s = s + i; } for (let i = 0n; i < 3n; i++) { s = s + i; } assert(s == p && c);",
    ];
    for body in cases {
        let hits: Vec<_> = errors(&source(body, None))
            .into_iter()
            .filter(|d| d.message.contains("already declared"))
            .collect();
        assert!(hits.is_empty(), "unexpected for {:?}: {:?}", body, hits);
    }
}
