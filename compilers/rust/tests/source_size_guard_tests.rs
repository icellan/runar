//! BUG-008 follow-up: source-parser size-guard regression tests for the
//! Rust tier. Mirrors `compilers/go/frontend/parser_size_guard_test.go`.

use runar_compiler_rust::frontend::input_limits::{
    assert_source_bytes_under_limit, SourceSizeExceededError, MAX_SOURCE_BYTES,
};
use runar_compiler_rust::frontend::parser::{parse, parse_source};

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
