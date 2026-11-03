//! N-180: the shared call-depth limit, MAX_CALL_DEPTH = 128.
//!
//! A chain of private helpers `verify -> m0 -> m1 -> ... -> mN` is flat source
//! (MAX_SOURCE_NESTING never fires) but N+1 nested inlinings. Before N-180 this
//! tier aborted the process (`thread 'main' has overflowed its stack`) on an
//! 8000-link chain, and its recursion check restarted its DFS from every
//! method (quadratic).
//!
//! What these tests prove, on the .ts, .sol (bare `m(x)` calls) and .rs
//! surfaces: the chain at the limit (N=127, verify at depth 128) passes
//! validation; one past (N=128) is refused with the shared diagnostic naming
//! `verify`; N=20000 is refused naming `m0`, promptly and without a stack
//! overflow (which would abort this test binary, not fail one test); and a
//! cycle is still the recursion diagnostic, once per method that reaches it.
//!
//! What they do NOT prove: that the other surfaces agree, or that the accepted
//! chain compiles to the TS bytes (conformance/negatives/
//! n180-call-depth-parity.test.ts drives every CLI on all nine surfaces), nor
//! anything about the --ir JSON path.

use std::time::{Duration, Instant};

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::frontend::input_limits::MAX_CALL_DEPTH;
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::validator::validate;

fn diag(m: &str) -> String {
    format!("call depth of method '{}' exceeds MAX_CALL_DEPTH (limit=128)", m)
}

fn chain(ext: &str, n: usize) -> String {
    let mut s = String::new();
    match ext {
        "ts" => {
            s.push_str("import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n");
            for i in 0..n {
                s.push_str(&format!(" private m{}(x: bigint): bigint {{ return this.m{}(x); }}\n", i, i + 1));
            }
            s.push_str(&format!(" private m{}(x: bigint): bigint {{ return x; }}\n public verify(a: bigint) {{ assert(this.m0(a) == this.t); }}\n}}\n", n));
        }
        "sol" => {
            s.push_str("pragma runar ^0.1.0;\ncontract P is SmartContract {\n int immutable t;\n constructor(int _t) { t = _t; }\n");
            for i in 0..n {
                s.push_str(&format!(" function m{}(int x) private returns (int) {{ return m{}(x); }}\n", i, i + 1));
            }
            s.push_str(&format!(" function m{}(int x) private returns (int) {{ return x; }}\n function verify(int a) public {{ require(m0(a) == t); }}\n}}\n", n));
        }
        "rs" => {
            s.push_str("use runar::prelude::*;\n\n#[runar::contract]\nstruct P {\n #[readonly]\n t: Int,\n}\n\nimpl P {\n");
            for i in 0..n {
                s.push_str(&format!(" fn m{}(&self, x: Int) -> Int {{ self.m{}(x) }}\n", i, i + 1));
            }
            s.push_str(&format!(" fn m{}(&self, x: Int) -> Int {{ x }}\n pub fn verify(&self, a: Int) {{ assert!(self.m0(a) == self.t); }}\n}}\n", n));
        }
        _ => unreachable!("surface {}", ext),
    }
    s
}

fn errors_of(src: &str, file: &str) -> Vec<String> {
    let parsed = parse_source(src, Some(file));
    let parse_errors: Vec<_> = parsed.errors.iter().filter(|d| d.severity == Severity::Error).collect();
    assert!(parse_errors.is_empty(), "parse: {:?}", parse_errors);
    let contract = parsed.contract.expect("contract");
    validate(&contract).errors.into_iter().map(|d| d.message).collect()
}

#[test]
fn max_call_depth_is_128() {
    assert_eq!(MAX_CALL_DEPTH, 128);
}

#[test]
fn chain_boundary_on_ts_sol_rs() {
    for ext in ["ts", "sol", "rs"] {
        let file = format!("P.runar.{}", ext);
        let at = errors_of(&chain(ext, 127), &file);
        assert!(at.is_empty(), "{}: N=127 must be accepted, got {:?}", ext, at);
        let past = errors_of(&chain(ext, 128), &file);
        assert_eq!(past, vec![diag("verify")], "{}: N=128", ext);
    }
}

#[test]
fn chain_of_20000_is_refused_promptly() {
    for ext in ["ts", "sol", "rs"] {
        let file = format!("P.runar.{}", ext);
        let src = chain(ext, 20000);
        let start = Instant::now();
        let errs = errors_of(&src, &file);
        let elapsed = start.elapsed();
        assert_eq!(errs, vec![diag("m0")], "{}: N=20000", ext);
        assert!(elapsed < Duration::from_secs(20), "{}: took {:?} (quadratic call-graph walk?)", ext, elapsed);
    }
}

#[test]
fn cycle_is_still_reported_as_recursion() {
    let src = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n private a(x: bigint): bigint { return this.b(x); }\n private b(x: bigint): bigint { return this.c(x); }\n private c(x: bigint): bigint { return this.b(x); }\n private d(x: bigint): bigint { return x; }\n public verify(v: bigint) { assert(this.a(v) + this.d(v) == this.t); }\n}\n";
    let want: Vec<String> = ["a", "b", "c", "verify"]
        .iter()
        .map(|m| format!("Recursion detected: method '{}' calls itself directly or indirectly. Recursion is not allowed in Rúnar contracts.", m))
        .collect();
    assert_eq!(errors_of(src, "P.runar.ts"), want);
}
