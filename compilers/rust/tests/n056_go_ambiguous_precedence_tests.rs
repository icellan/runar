//! N-056 (CL-BUG-192) — `.runar.go` operator precedence differed across tiers.
//!
//! The Go tier parses `.runar.go` with go/parser (Go precedence); this tier,
//! the TS reference and the other four use the C ladder, so `a & b + 1` was
//! `(a & b) + 1` in one tier and `a & (b + 1)` in the rest. R51: every tier
//! refuses an unparenthesised mix whose grouping differs between the two
//! schemes, with the shared diagnostic from 01-parse-go.ts.
//!
//! The oracle recomputes the 72 ambiguous ordered operator pairs from the two
//! precedence tables rather than reusing the parser's constant.
//!
//! What these tests prove: the Rust tier refuses every ambiguous pair with the
//! shared text, accepts the 252 agreeing pairs and both parenthesisations, and
//! treats `&^` as `&` and call results as operands.
//! What they do not prove: emitted bytes or the other tiers (conformance
//! negatives N175-N179 and the agreeing-pairs control cover cross-tier
//! agreement).

use runar_compiler_rust::frontend::parser_gocontract::parse_go_contract;

const GO_PREC: &[(&str, i32)] = &[
    ("*", 5), ("/", 5), ("%", 5), ("<<", 5), (">>", 5), ("&", 5),
    ("+", 4), ("-", 4), ("|", 4), ("^", 4),
    ("==", 3), ("!=", 3), ("<", 3), ("<=", 3), (">", 3), (">=", 3),
    ("&&", 2), ("||", 1),
];

fn c_prec(op: &str) -> i32 {
    match op {
        "*" | "/" | "%" => 10,
        "+" | "-" => 9,
        "<<" | ">>" => 8,
        "<" | "<=" | ">" | ">=" => 7,
        "==" | "!=" => 6,
        "&" => 5,
        "^" => 4,
        "|" => 3,
        "&&" => 2,
        "||" => 1,
        _ => unreachable!("{op}"),
    }
}

fn message(x: &str, y: &str) -> String {
    format!(
        "ambiguous operator precedence in .runar.go: `a {x} b {y} c` groups differently \
         under Go precedence than in Rúnar's other surfaces; add parentheses"
    )
}

fn errors_of(expr: &str) -> Vec<String> {
    let src = format!(
        r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Probe struct {{
	runar.SmartContract
	T runar.Int `runar:"readonly"`
}}

func (c *Probe) Unlock(a runar.Int, b runar.Int, d runar.Int) {{
	x := {expr}
	runar.Assert(x == c.T)
}}
"#
    );
    parse_go_contract(&src, Some("Probe.runar.go"))
        .errors
        .into_iter()
        .map(|d| d.message)
        .collect()
}

fn refused(expr: &str, x: &str, y: &str) -> Option<String> {
    let got = errors_of(expr);
    let want = message(x, y);
    if got.iter().any(|m| *m == want) {
        None
    } else {
        Some(format!("{expr}: errors {got:?}, want {want:?}"))
    }
}

fn accepted(expr: &str) -> Option<String> {
    let got = errors_of(expr);
    if got.is_empty() { None } else { Some(format!("{expr}: unexpected errors {got:?}")) }
}

#[test]
fn n056_every_ambiguous_pair_refused_and_agreeing_pair_accepted() {
    let (mut conflicts, mut agree) = (0, 0);
    let mut failures = Vec::new();
    for &(x, gx) in GO_PREC {
        for &(y, gy) in GO_PREC {
            let expr = format!("a {x} b {y} d");
            if (gx >= gy) != (c_prec(x) >= c_prec(y)) {
                conflicts += 1;
                failures.extend(refused(&expr, x, y));
                failures.extend(accepted(&format!("(a {x} b) {y} d")));
                failures.extend(accepted(&format!("a {x} (b {y} d)")));
            } else {
                agree += 1;
                failures.extend(accepted(&expr));
            }
        }
    }
    assert_eq!((conflicts, agree), (72, 252));
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn n056_probes() {
    let mut failures = Vec::new();
    failures.extend(refused("a & b + 1", "&", "+"));
    failures.extend(refused("a + b << 2", "+", "<<"));
    failures.extend(refused("a | b + d", "|", "+"));
    failures.extend(refused("a & 255 == 15", "&", "=="));
    failures.extend(accepted("a ^ b * d"));
    failures.extend(refused("(a & b + 1) * d", "&", "+"));
    failures.extend(refused("runar.Abs(a + b << 2)", "+", "<<"));
    failures.extend(refused("a * (d + (a | b + d))", "|", "+"));
    failures.extend(accepted("a + b * d - a"));
    failures.extend(refused("a * b + d << 1", "+", "<<"));
    failures.extend(accepted("a &^ b"));
    failures.extend(refused("a &^ b + d", "&", "+"));
    failures.extend(accepted("(a &^ b) + d"));
    failures.extend(accepted("runar.BigintBigAdd(a, b) << 2"));
    failures.extend(accepted("runar.Abs(a + b) << 2"));
    failures.extend(refused("-a + b << 2", "+", "<<"));
    failures.extend(accepted("-(a + b) << 2"));
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}
