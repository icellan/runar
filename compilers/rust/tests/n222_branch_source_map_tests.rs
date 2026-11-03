//! N-222 — the Rust tier attributed every opcode inside an `if`/`else` body to
//! the line of the enclosing `if`.
//!
//! An if-op's arms are lowered in their own contexts, each with a `source_locs`
//! vector parallel to its ops, but only the PARENT's vector survived: the arm
//! vectors were dropped when the arms became a `StackOp::If`, and emit then
//! stamped the if-op's location on every opcode beneath it (`OP_ELSE`,
//! `OP_ENDIF` and the arms' reconcile ops included). For if-else that was 19
//! mappings onto 3 distinct anchors where the TypeScript reference has 13 onto
//! 5 (each body statement its own anchor, `OP_ELSE`/`OP_ENDIF` unmapped).
//!
//! The reference is the TypeScript tier: opcode N is the same opcode in every
//! tier (byte-identical hex), and statements appear in the same order in each
//! tier's surface syntax, so a mapping's STATEMENT is identified by the rank of
//! its `(line, column)` among the method's distinct anchors.
//!
//! What this proves: for if-else (against the committed TS golden) and
//! if-without-else (against the TS map pinned below), the Rust map maps exactly
//! the opcodes TS maps — no extra ones, none missing — and each to the same
//! statement, so the then/else body ops, the `if` condition and the post-if
//! ops are each attributed to their own statement.
//! What it does NOT prove: anything about the other tiers, nor that TS itself
//! picks the "right" statement for an opcode (it is the reference by project
//! policy), nor columns (the anchor oracle in conformance/source-map checks
//! those against the real source text).

use runar_compiler_rust::{compile_from_source_with_options, CompileOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn repo(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
}

/// opcodeIndex -> statement ordinal (rank of the mapping's `(line, column)`).
fn statements(mappings: &[(usize, usize, usize)]) -> BTreeMap<usize, usize> {
    let anchors: BTreeSet<(usize, usize)> = mappings.iter().map(|&(_, l, c)| (l, c)).collect();
    let rank: BTreeMap<(usize, usize), usize> = anchors.into_iter().enumerate().map(|(i, a)| (a, i)).collect();
    mappings.iter().map(|&(i, l, c)| (i, rank[&(l, c)])).collect()
}

fn rust_map(rel: &str) -> Vec<(usize, usize, usize)> {
    let opts = CompileOptions { disable_constant_folding: true, ..CompileOptions::default() };
    let art = compile_from_source_with_options(&repo(rel), &opts).unwrap_or_else(|e| panic!("compile {}: {}", rel, e));
    art.source_map
        .expect("source map")
        .mappings
        .iter()
        .map(|m| (m.opcode_index, m.line, m.column))
        .collect()
}

fn assert_matches_reference(fixture: &str, ts: &[(usize, usize, usize)], rs: &[(usize, usize, usize)]) {
    let (ts, rs) = (statements(ts), statements(rs));
    for i in ts.keys().chain(rs.keys()).collect::<BTreeSet<_>>() {
        assert_eq!(
            rs.get(i),
            ts.get(i),
            "{}: opcode #{} — TS maps it to statement {:?}, Rust to {:?} (full TS {:?} / Rust {:?})",
            fixture,
            i,
            ts.get(i),
            rs.get(i),
            ts,
            rs
        );
    }
}

#[test]
fn if_else_body_opcodes_map_to_their_own_statements() {
    let golden: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo("conformance/source-map/if-else/ts/expected-source-map.json"))
            .expect("read TS golden"),
    )
    .unwrap();
    let ts: Vec<(usize, usize, usize)> = golden["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let n = |k: &str| m[k].as_u64().unwrap() as usize;
            (n("opcodeIndex"), n("line"), n("column"))
        })
        .collect();
    assert_matches_reference("if-else", &ts, &rust_map("examples/rust/if-else/IfElse.runar.rs"));
}

/// The TS reference map of `examples/ts/if-without-else/IfWithoutElse.runar.ts`
/// (constant folding off), as `(opcodeIndex, line, column)`. Regenerate with
/// `runar compile <file> --disable-constant-folding --emit-source-map <out>`.
/// TS puts each `if` and its body on one line, so the body statement is the
/// second anchor on that line (column 30).
const IF_WITHOUT_ELSE_TS: &[(usize, usize, usize)] = &[
    (0, 12, 4),
    (1, 13, 4),
    (2, 13, 4),
    (3, 13, 4),
    (4, 13, 4),
    (5, 13, 30),
    (6, 13, 30),
    (7, 13, 30),
    (8, 13, 30),
    (12, 13, 4),
    (13, 14, 4),
    (14, 14, 4),
    (15, 14, 4),
    (16, 14, 4),
    (17, 14, 30),
    (18, 14, 30),
    (19, 14, 30),
    (20, 14, 30),
    (24, 14, 4),
    (25, 15, 4),
    (26, 15, 4),
];

#[test]
fn if_without_else_body_opcodes_map_to_their_own_statements() {
    assert_matches_reference(
        "if-without-else",
        IF_WITHOUT_ELSE_TS,
        &rust_map("examples/rust/if-without-else/IfWithoutElse.runar.rs"),
    );
}
