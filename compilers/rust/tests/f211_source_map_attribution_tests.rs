//! F-211 (CL-BUG-056) — the Rust tier's source map attributed compiler-injected
//! opcodes to user statements.
//!
//! Two leaks, both "sticky location" bugs:
//!
//! 1. ANF lowering set `current_source_loc` per statement and never cleared it,
//!    so every binding the stateful scaffold appends AFTER the developer's body
//!    (the whole state-continuation / hashOutputs check, ~125 opcodes per
//!    method) carried the LAST user statement's line. The TypeScript reference
//!    (`04-anf-lower.ts` `lowerStatement`) resets the location to `undefined`
//!    after each statement, so those bindings carry none.
//! 2. Emit set `pending_source_loc` per op and never cleared it after a method
//!    body, so the dispatch opcodes of the NEXT method (`OP_ELSE <i>
//!    OP_NUMEQUALVERIFY`, the closing `OP_ENDIF`) were attributed to the last
//!    statement of the PREVIOUS method. TS (`06-emit.ts` `emitStackOp`) clears
//!    the location after every op.
//!
//! The independent anchor oracle (conformance/source-map/independent-oracle.ts)
//! cannot see either: every leaked mapping points at a real token of a real
//! statement — just not the statement that produced the opcode.
//!
//! What this proves: for the conformance fixtures' own Rust sources, the
//! continuation bindings carry no source location; no dispatch opcode is
//! mapped; and stateful-counter's Rust mappings fall inside the TypeScript
//! reference golden's per-statement opcode spans and cover every opcode TS maps.
//! What it does NOT prove: anything about the other tiers, nor nested
//! control flow — a `StackOp::If`'s inner ops share the if-statement's
//! location in this tier (the parallel `source_locs` vector is top-level only),
//! which is coarser than TS's per-inner-statement mapping and is not
//! addressed here.

use runar_compiler_rust::ir::ANFValue;
use runar_compiler_rust::{
    compile_from_source_with_options, compile_source_to_ir_with_options, CompileOptions,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn repo(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
}

fn fold_off() -> CompileOptions {
    CompileOptions { disable_constant_folding: true, ..CompileOptions::default() }
}

/// ASM tokens with each `<raw N bytes>` span collapsed to one opcode slot,
/// so token index == source-map `opcodeIndex`.
fn opcode_tokens(asm: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = asm.split_whitespace().peekable();
    while let Some(t) = it.next() {
        if t == "<raw" {
            it.next();
            it.next();
            out.push("<raw>".to_string());
        } else {
            out.push(t.to_string());
        }
    }
    out
}

#[test]
fn stateful_continuation_bindings_carry_no_source_location() {
    let ir = compile_source_to_ir_with_options(
        &repo("examples/rust/stateful-counter/Counter.runar.rs"),
        &fold_off(),
    )
    .expect("compile Counter.runar.rs to IR");
    for m in ir.methods.iter().filter(|m| m.is_public) {
        let start = m
            .body
            .iter()
            .position(|b| matches!(b.value, ANFValue::GetStateScript {}))
            .unwrap_or_else(|| panic!("{}: no get_state_script in continuation", m.name));
        // Completeness: the user statements before it are still tracked.
        assert!(
            m.body[..start].iter().any(|b| b.source_loc.is_some()),
            "{}: user statements lost their source location",
            m.name
        );
        for b in &m.body[start..] {
            assert!(
                b.source_loc.is_none(),
                "{}: compiler-injected continuation binding {} is attributed to line {}",
                m.name,
                b.name,
                b.source_loc.as_ref().unwrap().line
            );
        }
    }
}

#[test]
fn dispatch_opcodes_are_not_attributed_to_the_previous_method() {
    // Escrow: two public methods, no user-level if/else, no raw spans — so
    // every OP_ELSE / OP_ENDIF and the selector after OP_ELSE is dispatch.
    let art = compile_from_source_with_options(&repo("examples/rust/escrow/Escrow.runar.rs"), &fold_off())
        .expect("compile Escrow.runar.rs");
    let ops = opcode_tokens(&art.asm);
    let mapped: BTreeMap<usize, usize> = art
        .source_map
        .expect("escrow has a source map")
        .mappings
        .iter()
        .map(|m| (m.opcode_index, m.line))
        .collect();
    let mut dispatch = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        if op == "OP_ELSE" {
            dispatch.extend([i, i + 1, i + 2]); // OP_ELSE <1> OP_NUMEQUALVERIFY
        } else if op == "OP_ENDIF" {
            dispatch.push(i);
        }
    }
    assert!(!dispatch.is_empty(), "expected a dispatch table in {}", art.asm);
    for i in dispatch {
        assert!(
            !mapped.contains_key(&i),
            "dispatch opcode #{} ({}) is attributed to source line {}",
            i,
            ops[i],
            mapped[&i]
        );
    }
}

/// Per-statement opcode spans from a golden: statement ordinal (rank of its
/// line among the mapped lines) -> (min opcodeIndex, max opcodeIndex).
fn spans(mappings: &[(usize, usize)]) -> (BTreeMap<usize, usize>, BTreeMap<usize, (usize, usize)>) {
    let mut lines: Vec<usize> = mappings.iter().map(|&(_, l)| l).collect();
    lines.sort();
    lines.dedup();
    let ord: BTreeMap<usize, usize> = lines.iter().enumerate().map(|(i, &l)| (l, i)).collect();
    let mut sp: BTreeMap<usize, (usize, usize)> = BTreeMap::new();
    let mut by_idx = BTreeMap::new();
    for &(i, l) in mappings {
        let k = ord[&l];
        by_idx.insert(i, k);
        let e = sp.entry(k).or_insert((i, i));
        e.0 = e.0.min(i);
        e.1 = e.1.max(i);
    }
    (by_idx, sp)
}

#[test]
fn stateful_counter_mappings_match_the_typescript_reference_spans() {
    let ts: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo("conformance/source-map/stateful-counter/ts/expected-source-map.json"))
            .expect("read TS golden"),
    )
    .unwrap();
    let ts_maps: Vec<(usize, usize)> = ts["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| (m["opcodeIndex"].as_u64().unwrap() as usize, m["line"].as_u64().unwrap() as usize))
        .collect();
    let (ts_idx, ts_spans) = spans(&ts_maps);

    let art = compile_from_source_with_options(
        &repo("examples/rust/stateful-counter/Counter.runar.rs"),
        &fold_off(),
    )
    .expect("compile Counter.runar.rs");
    let rs_maps: Vec<(usize, usize)> = art
        .source_map
        .expect("source map")
        .mappings
        .iter()
        .map(|m| (m.opcode_index, m.line))
        .collect();
    let (rs_idx, _) = spans(&rs_maps);

    // Correctness: each Rust mapping lies inside the TS span of the same statement.
    for (&i, &k) in &rs_idx {
        let (lo, hi) = ts_spans
            .get(&k)
            .copied()
            .unwrap_or_else(|| panic!("Rust maps opcode #{} to statement #{} that TS never maps", i, k));
        assert!(
            (lo..=hi).contains(&i),
            "Rust maps opcode #{} to statement #{}, outside the TS span {}..={} for it",
            i,
            k,
            lo,
            hi
        );
    }
    // Completeness: every opcode TS maps, Rust maps to the same statement.
    for (&i, &k) in &ts_idx {
        assert_eq!(rs_idx.get(&i), Some(&k), "TS maps opcode #{} to statement #{}; Rust does not", i, k);
    }
}
