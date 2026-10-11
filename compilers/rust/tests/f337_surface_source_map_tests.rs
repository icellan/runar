//! F-337 — the Rust compiler's source map points at the real statement
//! positions on EVERY input surface, not only on `.runar.rs`.
//!
//! Before the fix the TypeScript (swc), Solidity-like, Move, Python, Zig and
//! Ruby parsers stamped every statement with line 1, column 0, so a source map
//! emitted for those surfaces collapsed to the single position (1,0). The
//! Go, Rust and Java parsers already tracked positions. The conformance
//! source-map runner only grades the Rust tier on `.runar.rs`, so it never saw
//! the collapse.
//!
//! Convention: lines are 1-based, columns are 0-based character offsets from
//! the start of the line (a tab counts as one character), as documented in
//! conformance/source-map/run.ts and used by every tier's committed goldens.
//!
//! What this proves: compiling examples/*/arithmetic through each of the
//! nine surfaces, the distinct (line, column) set of the emitted source map is
//! exactly the six statements of `verify`, each at the first non-blank
//! character of its line — positions derived by reading the source file
//! itself, not from any compiler output.
//! What it does NOT prove: per-opcode attribution (which statement each
//! opcode maps to), positions of statements nested inside if/for bodies on
//! these surfaces, non-ASCII column handling, or anything about other tiers.

use runar_compiler_rust::{compile_from_source_with_options, CompileOptions};
use std::collections::BTreeSet;
use std::path::PathBuf;

const SURFACES: &[&str] = &[
    "ts/arithmetic/Arithmetic.runar.ts",
    "sol/arithmetic/Arithmetic.runar.sol",
    "move/arithmetic/Arithmetic.runar.move",
    "go/arithmetic/Arithmetic.runar.go",
    "rust/arithmetic/Arithmetic.runar.rs",
    "python/arithmetic/Arithmetic.runar.py",
    "zig/arithmetic/Arithmetic.runar.zig",
    "ruby/arithmetic/Arithmetic.runar.rb",
    "java/src/main/java/runar/examples/arithmetic/Arithmetic.runar.java",
];

/// The six statements of `verify` are on consecutive lines; the fifth one
/// (`result = sum + diff + prod + quot`) is the anchor.
fn expected_positions(src: &str) -> BTreeSet<(usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let result_idx = lines
        .iter()
        .position(|l| l.contains("result") && l.contains("quot") && l.contains("prod"))
        .expect("result statement not found");
    (result_idx - 4..=result_idx + 1)
        .map(|i| {
            let l = lines[i];
            let indent = l.chars().take_while(|c| c.is_whitespace()).count();
            assert!(indent < l.chars().count(), "line {} is blank", i + 1);
            (i + 1, indent)
        })
        .collect()
}

#[test]
fn every_surface_maps_ops_to_real_statement_positions() {
    let examples = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let opts = CompileOptions { disable_constant_folding: true, ..CompileOptions::default() };
    let mut failures = Vec::new();
    for rel in SURFACES {
        let path = examples.join(rel);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let want = expected_positions(&src);
        let art = compile_from_source_with_options(&path, &opts)
            .unwrap_or_else(|e| panic!("compile {rel}: {e}"));
        let got: BTreeSet<(usize, usize)> = art
            .source_map
            .expect("source map")
            .mappings
            .iter()
            .map(|m| (m.line, m.column))
            .collect();
        if got != want {
            failures.push(format!("{rel}: got {got:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "degenerate or wrong source maps:\n{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// `else if` / `elif` / `elsif`
// ---------------------------------------------------------------------------
//
// What this proves: on every surface with an else-if form, the nested
// IfStatement the parser builds for it is located at its own keyword (`if`
// after `else`, `elif`, `elsif`) — the Sol / Move / Zig / Python / Ruby
// parsers build that statement outside parse_statement, so it needs its own
// location. Positions are derived from the source text. The AST column is
// 1-based (codegen/emit.rs converts to the source map's 0-based column).
// What it does NOT prove: that any opcode is attributed to that statement —
// the Rust tier's branch lowering maps a branch's ops to the outer `if`.

use runar_compiler_rust::frontend::ast::Statement;
use runar_compiler_rust::frontend::parser::parse_source;

const SOL_ELSE_IF: &str = "pragma runar ^0.1.0;

contract Selector is StatefulSmartContract {
    bigint a;
    bigint b;

    constructor(bigint _a, bigint _b) {
        a = _a;
        b = _b;
    }

    function set(bigint i, bigint v) public {
        if (i == 0) {
            this.a = v;
        } else if (i == 1) {
            this.b = v;
        } else {
            require(false);
        }
    }
}
";

const MOVE_ELSE_IF: &str = "module Selector {
    resource struct Selector {
        a: &mut bigint,
        b: &mut bigint,
    }

    public fun set(contract: &mut Selector, i: bigint, v: bigint) {
        if (i == 0) {
            contract.a = v;
        } else if (i == 1) {
            contract.b = v;
        } else {
            assert!(false, 0);
        };
    }
}
";

fn stmt_pos(s: &Statement) -> (usize, usize) {
    match s {
        Statement::VariableDecl { source_location: l, .. }
        | Statement::Assignment { source_location: l, .. }
        | Statement::IfStatement { source_location: l, .. }
        | Statement::ForStatement { source_location: l, .. }
        | Statement::ReturnStatement { source_location: l, .. }
        | Statement::ExpressionStatement { source_location: l, .. } => (l.line, l.column),
    }
}

/// 1-based (line, column) of the first `keyword` on the first line that
/// contains `marker`.
fn keyword_pos(src: &str, marker: &str, keyword: &str) -> (usize, usize) {
    for (i, l) in src.lines().enumerate() {
        if let Some(m) = l.find(marker) {
            let k = m + l[m..].find(keyword).unwrap();
            return (i + 1, l[..k].chars().count() + 1);
        }
    }
    panic!("{marker:?} not in source");
}

#[test]
fn else_if_statements_are_located_at_their_keyword() {
    let examples = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let read = |rel: &str| std::fs::read_to_string(examples.join(rel)).unwrap();
    // (file name, source, outer-if marker, else-if marker, else-if keyword)
    let cases: Vec<(&str, String, &str, &str, &str)> = vec![
        ("Selector.runar.ts", read("ts/selector/Selector.runar.ts"), "if (i == 0n)", "else if", "if ("),
        ("Selector.runar.sol", SOL_ELSE_IF.to_string(), "if (i == 0)", "else if", "if ("),
        ("Selector.runar.move", MOVE_ELSE_IF.to_string(), "if (i == 0)", "else if", "if ("),
        ("Selector.runar.go", read("go/selector/Selector.runar.go"), "if i == 0", "else if", "if "),
        ("Selector.runar.py", read("python/selector/Selector.runar.py"), "if i == 0", "elif", "elif"),
        ("Selector.runar.zig", read("zig/selector/Selector.runar.zig"), "if (i == 0)", "else if", "if ("),
        ("Selector.runar.rb", read("ruby/selector/Selector.runar.rb"), "if i == 0", "elsif", "elsif"),
    ];
    let mut failures = Vec::new();
    for (name, src, outer_marker, inner_marker, inner_kw) in &cases {
        let res = parse_source(src, Some(name));
        let errs = res.error_strings();
        let contract = res.contract.unwrap_or_else(|| panic!("{name}: parse failed: {errs:?}"));
        let set = contract.methods.iter().find(|m| m.name == "set").expect("set method");
        let outer = &set.body[0];
        let inner = match outer {
            Statement::IfStatement { else_branch: Some(e), .. } => &e[0],
            other => panic!("{name}: first statement is not if/else: {other:?}"),
        };
        let want_outer = keyword_pos(src, outer_marker, "if");
        let want_inner = keyword_pos(src, inner_marker, inner_kw.trim_end_matches([' ', '(']));
        if stmt_pos(outer) != want_outer || stmt_pos(inner) != want_inner {
            failures.push(format!(
                "{name}: outer {:?} (want {want_outer:?}), else-if {:?} (want {want_inner:?})",
                stmt_pos(outer),
                stmt_pos(inner)
            ));
        }
    }
    assert!(failures.is_empty(), "wrong else-if locations:\n{}", failures.join("\n"));
}
