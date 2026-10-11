//! Per-pass unit tests for the Rust analyzer port.
//!
//! Each test constructs a small synthetic hex script that exercises one
//! finding code (spec §5) and asserts the analyzer emits exactly that
//! finding (plus any unavoidable companion findings — e.g. an empty body
//! always triggers `UNCONDITIONALLY_SUCCEEDS`/`NO_SIG_CHECK`).

use runar_lang::analyzer::{
    analyze_script, analyze_script_with_options, opcode_concerns::format_kb, script_parser,
    serialize_report, AnalyzeOptions, RawScriptSpan,
};

/// Helper: filter findings by code.
fn codes(result: &runar_lang::analyzer::AnalysisResult) -> Vec<&str> {
    result.findings.iter().map(|f| f.code.as_str()).collect()
}

#[test]
fn empty_script_invalid_terminal_stack() {
    let r = analyze_script("").unwrap();
    assert_eq!(r.script_size, 0);
    assert!(codes(&r).contains(&"INVALID_TERMINAL_STACK"));
    assert!(r.paths.is_empty());
    assert_eq!(r.summary.script_size_bytes, 0);
}

#[test]
fn stack_underflow_only_when_initial_depth_positive() {
    // A bare OP_DROP at the top level pops 1 from an empty stack. Per spec
    // §8.2 step 4, this is NOT a STACK_UNDERFLOW because initialDepth = 0.
    let r = analyze_script("75").unwrap(); // OP_DROP
    assert!(!codes(&r).contains(&"STACK_UNDERFLOW"));
    // It should still have the path with stackDepthAtEnd = -1.
    assert_eq!(r.paths.len(), 1);
    assert_eq!(r.paths[0].stack_depth_at_end, -1);
}

#[test]
fn unbalanced_if_endif_stray_endif() {
    // Stray OP_ENDIF (no matching OP_IF).
    let r = analyze_script("68").unwrap();
    assert!(codes(&r).contains(&"UNBALANCED_IF_ENDIF"));
    // paths must be empty when structural error present.
    assert!(r.paths.is_empty());
}

#[test]
fn unbalanced_if_endif_unclosed_if() {
    let r = analyze_script("6300").unwrap(); // OP_IF OP_0
    let found: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.code == "UNBALANCED_IF_ENDIF")
        .collect();
    assert!(!found.is_empty());
    assert!(r.paths.is_empty());
}

#[test]
fn unconditionally_succeeds_on_no_op_path() {
    // Single OP_NOP — non-empty path with no verifier → UNCONDITIONALLY_SUCCEEDS.
    let r = analyze_script("61").unwrap();
    assert!(codes(&r).contains(&"UNCONDITIONALLY_SUCCEEDS"));
}

#[test]
fn no_sig_check_on_path_without_checksig() {
    // OP_VERIFY satisfies the "has verifier" check, so it doesn't trigger
    // UNCONDITIONALLY_SUCCEEDS, but it has no CHECKSIG either.
    let r = analyze_script("69").unwrap(); // OP_VERIFY
    assert!(codes(&r).contains(&"NO_SIG_CHECK"));
    assert!(!codes(&r).contains(&"UNCONDITIONALLY_SUCCEEDS"));
}

#[test]
fn checksig_result_dropped() {
    // OP_CHECKSIG immediately followed by OP_DROP.
    let r = analyze_script("ac75").unwrap();
    assert!(codes(&r).contains(&"CHECKSIG_RESULT_DROPPED"));
    // OP_CHECKSIG also satisfies hasCheckSig, so NO_SIG_CHECK should NOT fire.
    assert!(!codes(&r).contains(&"NO_SIG_CHECK"));
}

// F-234: OP_2DROP pops the CHECKSIG result as surely as OP_DROP does, so
// `OP_CHECKSIG OP_2DROP OP_1` used to verify clean. Proves the immediate
// OP_2DROP form is flagged with the spec §5.1 message and that OP_NIP (which
// removes the item BELOW the result) is not. Does not prove that longer
// discard sequences (OP_SWAP OP_NIP, OP_TOALTSTACK, ...) are caught: the rule
// only looks at the next opcode.
#[test]
fn checksig_result_dropped_by_2drop() {
    for (hex, want, offset) in [
        ("0000ac6d51", "OP_CHECKSIG result is dropped by OP_2DROP — signature check has no effect", 2),
        ("000000ae6d51", "OP_CHECKMULTISIG result is dropped by OP_2DROP — signature check has no effect", 3),
    ] {
        let r = analyze_script(hex).unwrap();
        let got: Vec<_> = r.findings.iter().filter(|f| f.code == "CHECKSIG_RESULT_DROPPED").collect();
        assert_eq!(got.len(), 1, "{hex}: {:?}", codes(&r));
        assert_eq!(got[0].message, want);
        assert_eq!(got[0].offset, Some(offset));
    }
    // OP_0 OP_0 OP_CHECKSIG OP_NIP — the result survives on top; not flagged.
    let r = analyze_script("0000ac77").unwrap();
    assert!(!codes(&r).contains(&"CHECKSIG_RESULT_DROPPED"));
}

#[test]
fn checksigverify_not_flagged_when_dropped() {
    // Spec §9 explicitly excludes OP_CHECKSIGVERIFY (0xad).
    let r = analyze_script("ad75").unwrap();
    assert!(!codes(&r).contains(&"CHECKSIG_RESULT_DROPPED"));
}

#[test]
fn codeseparator_present() {
    let r = analyze_script("ab").unwrap();
    assert!(codes(&r).contains(&"CODESEPARATOR_PRESENT"));
}

#[test]
fn inefficient_push_pushdata1_short() {
    // OP_PUSHDATA1 0x05 <5 bytes>
    let r = analyze_script("4c050102030405").unwrap();
    assert!(codes(&r).contains(&"INEFFICIENT_PUSH"));
    let msg = r
        .findings
        .iter()
        .find(|f| f.code == "INEFFICIENT_PUSH")
        .map(|f| f.message.clone())
        .unwrap();
    assert!(msg.contains("OP_PUSHDATA1"));
    assert!(msg.contains("opcode 0x05"));
}

#[test]
fn inefficient_push_pushdata2_short() {
    // OP_PUSHDATA2 0x0005 <5 bytes>
    let r = analyze_script("4d05000102030405").unwrap();
    let p = r
        .findings
        .iter()
        .find(|f| f.code == "INEFFICIENT_PUSH")
        .expect("INEFFICIENT_PUSH expected");
    assert!(p.message.contains("OP_PUSHDATA2"));
    assert!(p.message.contains("OP_PUSHDATA1"));
}

#[test]
fn inconsistent_branch_depth_with_else() {
    // OP_0 OP_IF OP_1 OP_ELSE OP_1 OP_2 OP_ENDIF — THEN delta = 1, ELSE = 2.
    let r = analyze_script("00635167515268").unwrap();
    assert!(codes(&r).contains(&"INCONSISTENT_BRANCH_DEPTH"));
}

#[test]
fn paths_truncated_emits_finding_at_nine_branches() {
    // 9 OP_IFs (each followed by OP_ENDIF) → 2^9 = 512 > 256 → PATHS_TRUNCATED.
    let mut script = String::new();
    for _ in 0..9 {
        script.push_str("00"); // OP_0 (push something so OP_IF has a stack item; analyzer doesn't care here)
        script.push_str("63"); // OP_IF
    }
    for _ in 0..9 {
        script.push_str("68"); // OP_ENDIF
    }
    let r = analyze_script(&script).unwrap();
    let pt = r
        .findings
        .iter()
        .find(|f| f.code == "PATHS_TRUNCATED")
        .expect("PATHS_TRUNCATED expected");
    assert!(pt.message.contains("2^9 = 512"));
    assert_eq!(r.paths.len(), 256);
}

#[test]
fn paths_truncated_emits_for_large_branches() {
    // Spec v1.2: numBranches=33 has 2^33 true paths, so PATHS_TRUNCATED
    // MUST fire with the exact-decimal message form (33 < 53).
    let mut script = String::new();
    for _ in 0..33 {
        script.push_str("63"); // OP_IF
    }
    for _ in 0..33 {
        script.push_str("68"); // OP_ENDIF
    }
    let r = analyze_script(&script).unwrap();
    let pt = r
        .findings
        .iter()
        .find(|f| f.code == "PATHS_TRUNCATED")
        .expect("PATHS_TRUNCATED expected");
    assert!(pt.message.contains("2^33 = 8589934592 paths"));
    assert_eq!(r.paths.len(), 256);
}

#[test]
fn paths_truncated_renders_symbolic_for_very_large_branches() {
    // Spec v1.2: numBranches >= 53 renders "more than 2^53 paths"
    // symbolically.
    let mut script = String::new();
    for _ in 0..53 {
        script.push_str("63");
    }
    for _ in 0..53 {
        script.push_str("68");
    }
    let r = analyze_script(&script).unwrap();
    let pt = r
        .findings
        .iter()
        .find(|f| f.code == "PATHS_TRUNCATED")
        .expect("PATHS_TRUNCATED expected");
    assert!(pt.message.contains("Script has 53 branch points (more than 2^53 paths)"));
    assert_eq!(r.paths.len(), 256);
}

#[test]
fn unreachable_after_return() {
    // OP_RETURN OP_0 — second opcode is on the only path and is post-RETURN.
    let r = analyze_script("6a00").unwrap();
    assert!(codes(&r).contains(&"UNREACHABLE_AFTER_RETURN"));
}

#[test]
fn large_script_threshold_500_001() {
    // Construct a 500_001-byte script of OP_NOPs (0x61).
    let n = 500_001usize;
    let mut hex = String::with_capacity(n * 2);
    for _ in 0..n {
        hex.push_str("61");
    }
    let r = analyze_script(&hex).unwrap();
    let ls = r
        .findings
        .iter()
        .find(|f| f.code == "LARGE_SCRIPT")
        .expect("LARGE_SCRIPT expected");
    assert!(ls.message.contains("500001 bytes"));
    // 500001 / 1024 = 488.282... → "488.3".
    assert!(ls.message.contains("488.3 KB"), "got: {}", ls.message);
}

#[test]
fn large_script_not_emitted_at_500_000() {
    let n = 500_000usize;
    let mut hex = String::with_capacity(n * 2);
    for _ in 0..n {
        hex.push_str("61");
    }
    let r = analyze_script(&hex).unwrap();
    assert!(!codes(&r).contains(&"LARGE_SCRIPT"));
}

#[test]
fn format_kb_non_tie_cases() {
    // None of these land on an exact tie at the tenths digit, so
    // round-half-up and round-half-to-even agree on all of them.
    // 1024 → "1.0"
    assert_eq!(format_kb(1024), "1.0");
    // 1536 (1024 + 512, exactly 1.5 KB) → "1.5" (no half).
    assert_eq!(format_kb(1536), "1.5");
    // 51 → 51/1024 = 0.04980... → "0.0"
    assert_eq!(format_kb(51), "0.0");
    // 52 → 52/1024 = 0.05078 → "0.1"
    assert_eq!(format_kb(52), "0.1");
}

#[test]
fn format_kb_breaks_ties_like_js_not_half_to_even() {
    // 500992/1024 = 489.25 exactly (1024 is a power of two, so the
    // division has no rounding error). Scaled by 10 that is 4892.5 — an
    // exact tie at the tenths digit. JS Number.prototype.toFixed(1) does
    // NOT use round-half-to-even: per spec it picks the integer n for
    // which n/10 - x is closest to zero, and on a tie picks the LARGER n.
    // Verified live: node -e "console.log((500992/1024).toFixed(1))" ->
    // "489.3". Round-half-to-even rounds 4892.5 down to 4892 (already
    // even), producing the wrong "489.2".
    assert_eq!(format_kb(500_992), "489.3");
}

#[test]
fn format_kb_does_not_move_existing_analyzer_goldens() {
    // Pins the two LARGE_SCRIPT conformance goldens
    // (conformance/analyzer/{ec-demo,schnorr-zkp}) so the tie-rounding fix
    // above is proven not to move them — neither size lands on an exact
    // .5 tie at the tenths digit.
    assert_eq!(format_kb(1_337_343), "1306.0");
    assert_eq!(format_kb(877_253), "856.7");
}

#[test]
fn analyze_script_normalize_strips_js_whitespace_set() {
    // The TS reference strips exactly what JS's /\s/g matches: a fixed
    // 25-codepoint set (ECMA-262 WhiteSpace + LineTerminator). NBSP
    // (U+00A0) and the BOM (U+FEFF) are both in that set. Verified
    // against the live TS analyzer: both inputs below normalize to
    // "76a988ac".
    let r = analyze_script("76\u{00a0}a9\u{00a0}88\u{00a0}ac").unwrap();
    assert_eq!(r.script, "76a988ac");
    assert_eq!(r.script_size, 4);

    let r = analyze_script("\u{feff}76a988ac").unwrap();
    assert_eq!(r.script, "76a988ac");
    assert_eq!(r.script_size, 4);
}

#[test]
fn raw_span_collapse_drops_inner_opcodes() {
    // 4 bytes that decode to OP_NOP × 4. Provide a single span covering
    // bytes [1, 3). Opcodes at offsets 1 and 2 should collapse to one
    // RAW_SPAN; opcodes at 0 and 3 stay.
    let opcodes = script_parser::parse_script("61616161");
    let spans = vec![RawScriptSpan {
        offset: 1,
        length: 2,
        in_arity: 0,
        out_arity: 1,
    }];
    let collapsed = script_parser::collapse_raw_script_spans(opcodes, &spans);
    assert_eq!(collapsed.len(), 3);
    assert_eq!(collapsed[0].name, "OP_NOP");
    assert_eq!(collapsed[1].name, "RAW_SPAN");
    assert_eq!(collapsed[1].offset, 1);
    assert_eq!(collapsed[1].size, 2);
    assert_eq!(collapsed[1].raw_span_arity, Some((0, 1)));
    assert_eq!(collapsed[2].name, "OP_NOP");
    assert_eq!(collapsed[2].offset, 3);
}

#[test]
fn raw_span_options_round_trip_through_analyze() {
    // Same script + span. Analyzer should treat RAW_SPAN as (in,out)=(0,1)
    // and produce a single linear path with stackDepthAtEnd = 1 (pure push).
    let opts = AnalyzeOptions {
        raw_script_spans: vec![RawScriptSpan {
            offset: 1,
            length: 2,
            in_arity: 0,
            out_arity: 1,
        }],
    };
    let r = analyze_script_with_options("61616161", &opts).unwrap();
    assert_eq!(r.paths.len(), 1);
    assert_eq!(r.paths[0].stack_depth_at_end, 1);
}

#[test]
fn serializer_omits_optional_fields() {
    // No finding has offset, opcode, or path on the empty-script result.
    let r = analyze_script("").unwrap();
    let s = serialize_report(&r);
    // Sanity: still byte-exact 2-space indent + trailing newline.
    assert!(s.ends_with("\n"));
    assert!(s.contains("\"code\": \"INVALID_TERMINAL_STACK\""));
    // The empty-script finding has no offset/opcode/path — they MUST be omitted.
    assert!(!s.contains("\"offset\""));
    assert!(!s.contains("\"opcode\""));
    assert!(!s.contains("\"path\""));
}

/// The seven Chronicle opcodes the compiler emits, with the (pops, pushes)
/// the @bsv/sdk interpreter (Spend.ts) gives them.
const CHRONICLE: [(&str, &str, i64, i64); 7] = [
    ("8d", "OP_2MUL", 1, 1),
    ("8e", "OP_2DIV", 1, 1),
    ("b3", "OP_SUBSTR", 3, 1),
    ("b4", "OP_LEFT", 2, 1),
    ("b5", "OP_RIGHT", 2, 1),
    ("b6", "OP_LSHIFTNUM", 2, 1),
    ("b7", "OP_RSHIFTNUM", 2, 1),
];

/// F-131. Proves: the Chronicle opcodes are named per spec §4.1 and modelled
/// with their real stack effect, in the lookup and in the observable report
/// (underflow message, stackDepthAtEnd, maxStackDepth). Does not prove runtime
/// semantics (the analyzer is static) and does not re-derive the arities from
/// the interpreter.
#[test]
fn chronicle_opcodes_names_and_effects() {
    use runar_lang::analyzer::stack_analyzer::{analyze_stack_linear, stack_effect};
    for (b, name, pops, pushes) in CHRONICLE {
        let ops = script_parser::parse_script(b);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].name, name, "0x{b} name");
        assert_eq!(stack_effect(&ops[0]), (pops, pushes), "{name} effect");

        // OP_DROP empties a stack of known depth 1, then the opcode needs `pops` items.
        let lin = analyze_stack_linear(&script_parser::parse_script(&format!("75{b}")), 1);
        let want = format!("{name} requires {pops} stack item(s) but only 0 available");
        assert!(
            lin.findings.iter().any(|f| f.code == "STACK_UNDERFLOW" && f.message == want),
            "{name}: missing underflow {want:?}"
        );

        // `pops` pushes of OP_1 then the opcode leave exactly `pushes` items.
        let r = analyze_script(&format!("{}{b}", "51".repeat(pops as usize))).unwrap();
        assert_eq!(r.paths[0].stack_depth_at_end, pushes, "{name} depth at end");
        assert_eq!(r.summary.max_stack_depth, pushes, "{name} maxStackDepth");
    }

    // A genuinely unknown byte keeps the OP_UNKNOWN name and (0, 0) effect.
    let ops = script_parser::parse_script("b8");
    assert_eq!(ops[0].name, "OP_UNKNOWN(0xb8)");
    assert_eq!(stack_effect(&ops[0]), (0, 0));
}
