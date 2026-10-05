//! BUG-008 follow-up: source-parser size-guard regression tests for the
//! Rust tier. Mirrors `compilers/go/frontend/parser_size_guard_test.go`.

use runar_compiler_rust::frontend::input_limits::{
    assert_source_bytes_under_limit, SourceSizeExceededError, MAX_SOURCE_BYTES,
};
use runar_compiler_rust::frontend::parser::{parse, parse_source};
use runar_compiler_rust::frontend::parser_gocontract::parse_go_contract;
use runar_compiler_rust::frontend::parser_java::parse_java;
use runar_compiler_rust::frontend::parser_move::parse_move;
use runar_compiler_rust::frontend::parser_python::parse_python;
use runar_compiler_rust::frontend::parser_ruby::parse_ruby;
use runar_compiler_rust::frontend::parser_rustmacro::parse_rust_dsl;
use runar_compiler_rust::frontend::parser_sol::parse_solidity;
use runar_compiler_rust::frontend::parser_zig::parse_zig;

#[test]
fn parse_source_rejects_oversized_input() {
    let oversized: String = " ".repeat(MAX_SOURCE_BYTES + 1);
    let res = parse_source(&oversized, Some("Counter.runar.ts"));
    let sse = res
        .source_size_err
        .expect("expected source_size_err to be set");
    assert_eq!(sse.limit, MAX_SOURCE_BYTES);
    assert_eq!(sse.actual, MAX_SOURCE_BYTES + 1);
    assert!(res.contract.is_none());
    assert!(!res.errors.is_empty());
}

#[test]
fn parse_source_rejects_oversized_input_regardless_of_extension() {
    let oversized: String = " ".repeat(MAX_SOURCE_BYTES + 1);
    for ext in [
        ".runar.ts",
        ".runar.sol",
        ".runar.move",
        ".runar.go",
        ".runar.py",
        ".runar.rs",
        ".runar.rb",
        ".runar.zig",
        ".runar.java",
    ] {
        let name = format!("Counter{}", ext);
        let res = parse_source(&oversized, Some(&name));
        assert!(
            res.source_size_err.is_some(),
            "ext {} did not trip source-size guard",
            ext
        );
    }
}

#[test]
fn parse_source_accepts_normal_sized_input() {
    let src = r#"
        class Counter extends SmartContract {
            public readonly x: bigint;
            constructor(x: bigint) { super(); this.x = x; }
            public unlock() {}
        }
    "#;
    let res = parse_source(src, Some("Counter.runar.ts"));
    assert!(
        res.source_size_err.is_none(),
        "size guard incorrectly tripped"
    );
}

#[test]
fn parse_rejects_oversized_input_directly() {
    let oversized: String = " ".repeat(MAX_SOURCE_BYTES + 1);
    let res = parse(&oversized, Some("Counter.runar.ts"));
    assert!(res.source_size_err.is_some());
}

// N-136: the per-format parsers are exported from the crate and callable
// directly (parse_source dispatches to them, but a caller can reach around
// the dispatcher exactly the way R-146 found in TS and F-177 found in Go).
// Each one hardcoded `source_size_err: None` and went straight to its own
// tokenizer, so a caller invoking e.g. `parse_solidity` directly got no
// DoS-bound rejection at all. This test proves each of the 8 exported
// per-format entries refuses a MAX_SOURCE_BYTES+1 input; it does not prove
// the guard runs before tokenization (that is a code-inspection fact, as in
// the Go test this mirrors).
#[test]
fn every_exported_per_format_parser_rejects_oversized_input() {
    let oversized: String = " ".repeat(MAX_SOURCE_BYTES + 1);

    let parsers: Vec<(&str, fn(&str, Option<&str>) -> runar_compiler_rust::frontend::parser::ParseResult)> = vec![
        ("parse_solidity", parse_solidity),
        ("parse_move", parse_move),
        ("parse_go_contract", parse_go_contract),
        ("parse_python", parse_python),
        ("parse_rust_dsl", parse_rust_dsl),
        ("parse_ruby", parse_ruby),
        ("parse_zig", parse_zig),
        ("parse_java", parse_java),
    ];

    for (name, f) in parsers {
        let res = f(&oversized, Some("Counter.runar.ts"));
        let sse = res
            .source_size_err
            .unwrap_or_else(|| panic!("{name}: expected source_size_err to be set"));
        assert_eq!(sse.limit, MAX_SOURCE_BYTES, "{name}: wrong limit");
        assert_eq!(sse.actual, MAX_SOURCE_BYTES + 1, "{name}: wrong actual");
        assert!(res.contract.is_none(), "{name}: expected no contract");
        assert!(!res.errors.is_empty(), "{name}: expected a diagnostic");
    }
}

// Control for the above: small input, well under the cap, must not trip the
// guard on any entry point. The parser is still free to fail afterwards for
// its own syntactic reasons (empty input is not valid source for most of
// these formats) — this test asserts only on source_size_err.
#[test]
fn every_exported_per_format_parser_accepts_small_input_at_the_guard() {
    let small = "";

    let parsers: Vec<(&str, fn(&str, Option<&str>) -> runar_compiler_rust::frontend::parser::ParseResult)> = vec![
        ("parse_solidity", parse_solidity),
        ("parse_move", parse_move),
        ("parse_go_contract", parse_go_contract),
        ("parse_python", parse_python),
        ("parse_rust_dsl", parse_rust_dsl),
        ("parse_ruby", parse_ruby),
        ("parse_zig", parse_zig),
        ("parse_java", parse_java),
    ];

    for (name, f) in parsers {
        let res = f(small, Some("Counter.runar.ts"));
        assert!(
            res.source_size_err.is_none(),
            "{name}: size guard incorrectly tripped on {}-byte input",
            small.len()
        );
    }
}

#[test]
fn assert_source_bytes_under_limit_typed_error() {
    let oversized: String = " ".repeat(MAX_SOURCE_BYTES + 1);
    let sse = assert_source_bytes_under_limit(&oversized).expect("expected error");
    let display = format!("{}", sse);
    assert!(display.contains("MAX_SOURCE_BYTES"));
    assert!(display.contains(&MAX_SOURCE_BYTES.to_string()));
    // Confirm Error trait
    let _: &dyn std::error::Error = &sse as &dyn std::error::Error;
    let _: SourceSizeExceededError = sse;
}
