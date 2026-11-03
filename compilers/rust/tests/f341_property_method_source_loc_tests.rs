//! F-341 remainder — the Rust `.runar.ts` (swc) parser locates each
//! property, method, and constructor at its real source position instead of
//! the parser-wide `default_loc` (1, 0).
//!
//! F-337 already fixed STATEMENT positions on the swc `.ts` surface (and
//! five other non-native surfaces). It left the property, constructor, and
//! method constructors in `compilers/rust/src/frontend/parser.rs` stamping
//! `default_loc(file)` — the only surface parser in the Rust tier that still
//! did, since the hand-written tokenizer parsers (sol/move/python/zig/ruby)
//! already stamp token-derived positions there rather than `default_loc`
//! (whether those are each node's exact *start* position is not checked by
//! this test — only the swc `.ts` surface is). `current_method_loc` in
//! `typecheck.rs` and the many `prop.source_location` / `method.source_location`
//! reads in `validator.rs` use these positions as the fallback location for
//! diagnostics about a property or method, and `parse_sighash_on_method`'s
//! three diagnostics used the same `default_loc`, so the collapse silently
//! mislocated all of those diagnostics to line 1 on the `.runar.ts` surface.
//!
//! What this proves: parsing a `.runar.ts` contract whose properties,
//! constructor, and methods sit on distinct, known source lines, each
//! node's `source_location` carries that node's own real (line, column) —
//! not (1, 0) — computed by scanning the source text directly, the same
//! convention F-337 established for statements (1-based line, 1-based
//! column in the parser's internal AST; `codegen/emit.rs` converts to
//! 0-based only when writing the final source map, and only for statements).
//! It also proves a `@sighash` directive error on a private method is
//! reported at that method's real line, not line 1.
//! What it does NOT prove: anything about the sol/move/python/zig/ruby
//! surfaces (untouched here), diagnostic text/wording, or per-opcode
//! attribution.

use runar_compiler_rust::frontend::parser::parse_source;

const SRC: &str = "import { StatefulSmartContract, assert } from 'runar-lang';

class PropMethodLoc extends StatefulSmartContract {
  readonly c: bigint;

  a: bigint;

  b: bigint;

  constructor(c: bigint, a: bigint, b: bigint) {
    super(c, a, b);
    this.a = a;
    this.b = b;
  }

  public bump(v: bigint) {
    this.a = this.a + v;
  }

  public check(v: bigint) {
    assert(this.b == v);
  }

  /** @sighash SINGLE|FORKID */
  private helper(): void {
    assert(true);
  }
}
";

/// 1-based (line, column) of the first non-whitespace character of the
/// first line containing `marker`.
fn line_col(src: &str, marker: &str) -> (usize, usize) {
    for (i, l) in src.lines().enumerate() {
        if l.contains(marker) {
            let indent = l.chars().take_while(|c| c.is_whitespace()).count();
            return (i + 1, indent + 1);
        }
    }
    panic!("{marker:?} not in source");
}

#[test]
fn properties_methods_and_constructor_get_real_positions() {
    let res = parse_source(SRC, Some("PropMethodLoc.runar.ts"));
    let errs = res.error_strings();
    let contract = res.contract.unwrap_or_else(|| panic!("parse failed: {errs:?}"));

    let want_c = line_col(SRC, "readonly c: bigint;");
    let want_a = line_col(SRC, "a: bigint;");
    let want_b = line_col(SRC, "b: bigint;");
    let want_ctor = line_col(SRC, "constructor(c: bigint, a: bigint, b: bigint)");
    let want_bump = line_col(SRC, "public bump(v: bigint)");
    let want_check = line_col(SRC, "public check(v: bigint)");
    let want_helper = line_col(SRC, "private helper(): void");

    let prop_c = contract.properties.iter().find(|p| p.name == "c").expect("prop c");
    let prop_a = contract.properties.iter().find(|p| p.name == "a").expect("prop a");
    let prop_b = contract.properties.iter().find(|p| p.name == "b").expect("prop b");
    let bump = contract.methods.iter().find(|m| m.name == "bump").expect("bump");
    let check = contract.methods.iter().find(|m| m.name == "check").expect("check");
    let helper = contract.methods.iter().find(|m| m.name == "helper").expect("helper");

    let got_c = (prop_c.source_location.line, prop_c.source_location.column);
    let got_a = (prop_a.source_location.line, prop_a.source_location.column);
    let got_b = (prop_b.source_location.line, prop_b.source_location.column);
    let got_ctor = (
        contract.constructor.source_location.line,
        contract.constructor.source_location.column,
    );
    let got_bump = (bump.source_location.line, bump.source_location.column);
    let got_check = (check.source_location.line, check.source_location.column);
    let got_helper = (helper.source_location.line, helper.source_location.column);

    assert_eq!(got_c, want_c, "readonly property 'c' location");
    assert_eq!(got_a, want_a, "property 'a' location");
    assert_eq!(got_b, want_b, "property 'b' location");
    assert_eq!(got_ctor, want_ctor, "constructor location");
    assert_eq!(got_bump, want_bump, "method 'bump' location");
    assert_eq!(got_check, want_check, "method 'check' location");
    assert_eq!(got_helper, want_helper, "method 'helper' location");

    // The core defect: `default_loc` collapses every one of these onto line
    // 1. Seven distinct declarations on seven distinct lines must stay
    // distinct.
    let lines: std::collections::BTreeSet<usize> = [
        prop_c.source_location.line,
        prop_a.source_location.line,
        prop_b.source_location.line,
        contract.constructor.source_location.line,
        bump.source_location.line,
        check.source_location.line,
        helper.source_location.line,
    ]
    .into_iter()
    .collect();
    assert_eq!(lines.len(), 7, "expected 7 distinct lines, got {lines:?}");

    // `private helper` has a `@sighash` directive, which only public methods
    // may carry (Issue #123) — the resulting diagnostic must point at
    // `helper`'s own line, not line 1.
    let sighash_err = errs
        .iter()
        .find(|e| e.contains("@sighash directive on non-public method 'helper'"))
        .unwrap_or_else(|| panic!("expected a @sighash diagnostic for 'helper', got {errs:?}"));
    assert!(
        sighash_err.contains(&format!(":{}:", want_helper.0)),
        "@sighash diagnostic should report helper's real line {}, got: {sighash_err}",
        want_helper.0
    );
}
