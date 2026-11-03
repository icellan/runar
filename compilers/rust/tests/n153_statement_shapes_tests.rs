//! N-153: statement shapes on the .runar.move / .runar.go surfaces, aligned to
//! the TS reference.
//!
//! Pre-fix this tier alone refused a .runar.move empty statement `;` (TS skips
//! it as a no-op, so `self.check(x);;` compiles to 76009d5177), and, with the
//! Python and Java tiers, accepted a .runar.go EMPTY statement `;` that the TS
//! reference and the Go tier (go/parser EmptyStmt) refuse with
//! "Unexpected token in expression: ';'".
//!
//! Proves: the Rust tier compiles the .move shapes to the TS bytes and refuses
//! each .go empty statement with the TS diagnostic, while a `;` that ends a
//! statement on the same line still separates statements as before.
//! Does not prove: the other six tiers (see
//! conformance/negatives/n153-statement-shape-parity.test.ts) or whether the
//! .go same-line separator itself should be accepted (TS refuses it; left
//! open, see the N-153 report).

use runar_compiler_rust::compile_from_source_str;
use runar_compiler_rust::frontend::parser::parse_source;

fn move_src(stmt: &str) -> String {
    format!(
        r#"module Disc {{
    use runar::SmartContract;
    use runar::types::{{Int}};

    struct Disc {{
        t: Int,
    }}

    public fun unlock(contract: &Disc, x: Int) {{
        {stmt}
        assert!(true, 0);
    }}

    fun check(x: Int): Int {{
        assert!(x == self.t, 0);
        return x;
    }}
}}
"#
    )
}

fn go_src(stmt: &str) -> String {
    format!(
        r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Disc struct {{
	runar.SmartContract
	T runar.Bigint `runar:"readonly"`
}}

func (c *Disc) Unlock(x runar.Bigint) {{
	{stmt}
	runar.Assert(true)
}}

func (c *Disc) check(x runar.Bigint) runar.Bigint {{
	runar.Assert(x == c.T)
	return x
}}
"#
    )
}

#[test]
fn move_empty_statement_is_a_no_op_like_ts() {
    for (stmt, want) in [
        (";", "5177"),
        (";;", "5177"),
        ("self.check(x);;", "76009d5177"),
        ("if (x == self.t) { ; };", "009c636851"),
    ] {
        let art = compile_from_source_str(&move_src(stmt), Some("Disc.runar.move"))
            .unwrap_or_else(|e| panic!("move `{stmt}` refused: {e}"));
        assert_eq!(art.script, want, "move `{stmt}`");
    }
}

#[test]
fn go_empty_statement_is_refused_with_the_ts_diagnostic() {
    let want = "Unexpected token in expression: ';'";
    let mut failures = Vec::new();
    for stmt in [
        ";",
        "runar.Assert(x == c.T)\n\t;",
        "runar.Assert(x == c.T); ;",
        "runar.Assert(x == c.T);;",
        "if x == c.T { ; }",
    ] {
        let res = parse_source(&go_src(stmt), Some("Disc.runar.go"));
        if !res.errors.iter().any(|e| e.message.contains(want)) {
            failures.push(format!(
                "go `{stmt}`: expected {want:?}, got {:?}",
                res.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// N-153 (escalation decision): a `{` at statement start is refused. It used to
/// parse as a brace composite literal, so `{ x, c.check(x) }` (not Go)
/// compiled. A composite literal in expression position still parses.
#[test]
fn go_statement_starting_with_a_brace_is_refused_with_the_ts_diagnostic() {
    let want = "Unexpected token in expression: '{'";
    let mut failures = Vec::new();
    for stmt in [
        "{ runar.Assert(x == c.T) }",
        "{ x, c.check(x) }",
        "{ }",
        "{\n\t\ty := x\n\t\trunar.Assert(y == c.T)\n\t}",
        "if x == c.T {\n\t\t{ runar.Assert(true) }\n\t}",
    ] {
        let res = parse_source(&go_src(stmt), Some("Disc.runar.go"));
        if !res.errors.iter().any(|e| e.message.contains(want)) {
            failures.push(format!(
                "go `{stmt}`: expected {want:?}, got {:?}",
                res.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    let res = parse_source(&go_src("y := [2]runar.Bigint{x, c.T}\n\t_ = y"), Some("Disc.runar.go"));
    assert!(res.errors.is_empty(), "expression-position literal: {:?}", res.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>());
}

#[test]
fn go_statement_separator_on_the_same_line_is_unchanged() {
    for stmt in ["runar.Assert(x == c.T);", "y := c.check(x); _ = y", "if x == c.T { runar.Assert(true) };"] {
        let res = parse_source(&go_src(stmt), Some("Disc.runar.go"));
        assert!(
            res.errors.is_empty(),
            "go `{stmt}`: {:?}",
            res.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
        );
    }
}
