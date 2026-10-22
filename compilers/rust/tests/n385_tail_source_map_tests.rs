//! N-385 — the Rust tier attributed a method's tail cleanup ops, and the ops
//! after an inlined private-method body, to the LAST statement of that body.
//!
//! `BindingsTask` left `current_source_loc` set to the final binding's
//! location after its last binding, so the ops emitted afterwards (the final
//! `OP_NIP` before the dispatch `OP_ELSE`/`OP_ENDIF`, the rename/cleanup tail
//! of an inlined call) were stamped with it. The TypeScript reference clears
//! the location after every binding (05-stack-lower.ts), leaving those ops
//! unmapped. Seen in MathDemo at opcodes 6571 and 7092.
//!
//! The reference is the TypeScript tier, pinned in
//! `n385_ts_reference_maps.json` as runs `[firstOpcode, lastOpcode, statement]`
//! (statement = rank of the mapping's `(line, column)` among the method's
//! distinct anchors; opcode N is the same opcode in every tier, since the hex
//! is byte-identical). Regenerate with
//! `runar compile <examples/ts/...> --disable-constant-folding --emit-source-map <out>`.
//!
//! What this proves: for math-demo, auction (stateful) and function-patterns (public
//! methods that call private helpers, which are inlined), the Rust map maps exactly the
//! opcodes TS maps — none extra, none missing — each to the same statement.
//! What it does NOT prove: anything about the other tiers, columns (the anchor
//! oracle in conformance/source-map checks those), or that TS itself picks the
//! right statement (it is the reference by project policy).

use runar_compiler_rust::{compile_from_source_with_options, CompileOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn repo(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
}

fn rust_statements(rel: &str) -> BTreeMap<usize, usize> {
    let opts = CompileOptions { disable_constant_folding: true, ..CompileOptions::default() };
    let art = compile_from_source_with_options(&repo(rel), &opts).unwrap_or_else(|e| panic!("compile {}: {}", rel, e));
    let mappings = art.source_map.expect("source map").mappings;
    let anchors: BTreeSet<(usize, usize)> = mappings.iter().map(|m| (m.line, m.column)).collect();
    let rank: BTreeMap<(usize, usize), usize> = anchors.into_iter().enumerate().map(|(i, a)| (a, i)).collect();
    mappings.iter().map(|m| (m.opcode_index, rank[&(m.line, m.column)])).collect()
}

fn ts_statements(key: &str) -> BTreeMap<usize, usize> {
    let all: serde_json::Value =
        serde_json::from_str(include_str!("n385_ts_reference_maps.json")).expect("parse TS reference maps");
    let mut out = BTreeMap::new();
    for run in all[key].as_array().unwrap_or_else(|| panic!("no TS reference for {}", key)) {
        let n = |i: usize| run[i].as_u64().unwrap() as usize;
        for op in n(0)..=n(1) {
            out.insert(op, n(2));
        }
    }
    out
}

fn assert_matches_reference(key: &str, rel: &str) {
    let (ts, rs) = (ts_statements(key), rust_statements(rel));
    let diffs: Vec<String> = ts
        .keys()
        .chain(rs.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|i| ts.get(i) != rs.get(i))
        .map(|i| format!("#{}: TS {:?} / Rust {:?}", i, ts.get(i), rs.get(i)))
        .collect();
    assert!(diffs.is_empty(), "{}: {} opcodes differ from the TS map: {:?}", key, diffs.len(), diffs);
}

#[test]
fn math_demo_tail_ops_are_unmapped_like_ts() {
    assert_matches_reference("math-demo", "examples/rust/math-demo/MathDemo.runar.rs");
}

// A stateful contract: the state-continuation epilogue after the last
// statement of `bid` / `close` is method-tail cleanup (opcodes 351, 352).
#[test]
fn stateful_method_tail_ops_are_unmapped_like_ts() {
    assert_matches_reference("auction", "examples/rust/auction/Auction.runar.rs");
}

// Guard, not a red-first case: `InlineTask`'s tail emits no opcodes of its own
// (it only renames stack-model entries), so inlining is already TS-equal here
// at base; the fix to `BindingsTask` is what keeps the ops after an inlined
// body unmapped, and this pins that they stay so.
#[test]
fn inlined_private_method_tail_ops_are_unmapped_like_ts() {
    assert_matches_reference("function-patterns", "examples/rust/function-patterns/FunctionPatterns.runar.rs");
}
