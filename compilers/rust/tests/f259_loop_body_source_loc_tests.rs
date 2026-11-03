//! F-259 — an unrolled loop body's opcodes map to the body statement's line,
//! not to the `for` line.
//!
//! Before the fix `lower_loop` lowered every body binding without updating
//! `current_source_loc`, so every opcode of every unrolled iteration inherited
//! the enclosing loop binding's location (the `for` line).
//!
//! Convention (same in all 7 tiers): each body binding's own location is used
//! while it lowers; a body binding without one keeps the loop's location. The
//! per-iteration iteration-variable push stays on the `for` line. The restore
//! after each body binding matters in this tier in particular: `lower_bindings`
//! never clears `current_source_loc`, so without it iteration 2's push would
//! inherit the body location.
//!
//! What this proves: end to end on the Rust surface of
//! examples/rust/bounded-loop, every body op of all five unrolled iterations
//! maps to the body line and column, and only the five iteration-variable
//! pushes (OP_0..OP_4) map to the `for` line.
//! What it does NOT prove: anything about the other tiers, nested loops, or
//! body bindings the ANF lowerer leaves without a location. It equates ASM
//! token index with opcodeIndex, which holds for this contract (no raw spans).

use runar_compiler_rust::{compile_from_source_with_options, CompileOptions};
use std::path::PathBuf;

#[test]
fn loop_body_ops_map_to_the_body_line() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust/bounded-loop/BoundedLoop.runar.rs");
    let src = std::fs::read_to_string(&path).expect("read BoundedLoop.runar.rs");
    let opts = CompileOptions { disable_constant_folding: true, ..CompileOptions::default() };
    let art = compile_from_source_with_options(&path, &opts).expect("compile BoundedLoop.runar.rs");

    let find = |needle: &str, anchor: &str| -> (usize, usize) {
        for (i, l) in src.lines().enumerate() {
            if l.contains(needle) {
                return (i + 1, l.find(anchor).unwrap());
            }
        }
        panic!("needle {needle:?} not in source");
    };
    let (for_line, for_col) = find("for i in", "for");
    let (body_line, body_col) = find("sum = sum + start + i", "sum");

    let asm: Vec<&str> = art.asm.split_whitespace().collect();
    let iter_pushes = [(1usize, "OP_0"), (9, "OP_1"), (17, "OP_2"), (25, "OP_3"), (33, "OP_4")];
    for (idx, code) in iter_pushes {
        assert_eq!(asm.get(idx).copied(), Some(code), "asm = {}", art.asm);
    }

    let mappings = art.source_map.expect("source map").mappings;
    let loop_ops: Vec<_> = mappings
        .iter()
        .filter(|m| (1..=39).contains(&m.opcode_index))
        .collect();
    assert_eq!(loop_ops.len(), 39, "loop-op mappings");
    for m in loop_ops {
        let want = if iter_pushes.iter().any(|&(i, _)| i == m.opcode_index) {
            (for_line, for_col)
        } else {
            (body_line, body_col)
        };
        assert_eq!(
            (m.opcode_index, m.line, m.column),
            (m.opcode_index, want.0, want.1),
            "opcode {} ({})",
            m.opcode_index,
            asm[m.opcode_index]
        );
    }
}
