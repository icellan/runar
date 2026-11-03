//! N-265 — the `--ir` path bypasses N-180's `MAX_CALL_DEPTH` bound, and
//! (outside Go's F-071, which was cycle-only) the recursion check entirely.
//!
//! `compile_from_program_with_options` skips `frontend::validator`'s
//! `check_no_recursion`, which enforces both the call-graph cycle rule and
//! N-180's `MAX_CALL_DEPTH` (128) bound. Stack lowering (`codegen/stack.rs`'s
//! `inline_method_call`) inlines every `method_call` to a private method by
//! lowering its body in place, with no cycle or depth guard, so a
//! self/mutually-recursive method recurses the host call stack until it
//! aborts, and an acyclic chain past the bound recurses it just as deep.
//!
//! Proves: `compile_from_ir_str` now refuses a chain one past
//! `MAX_CALL_DEPTH`, naming the first offending method in declaration order
//! with the shared diagnostic, accepts a chain right at the bound, refuses a
//! 20000-link chain promptly (no SIGABRT, no multi-second hang), and refuses
//! a direct/mutual cycle with the shared recursion wording.
//!
//! Does not prove: that the other six tiers' `--ir` loaders agree
//! (`conformance/negatives/n265-ir-call-depth-parity.test.ts` does); call
//! graphs other than a chain or a 2/3-node cycle; or that 128 is the right
//! number (N-180 already measured that).

use runar_compiler_rust::compile_from_ir_str;
use runar_compiler_rust::frontend::input_limits::MAX_CALL_DEPTH;

/// `verify(a)` calls `m0(a)`; m_i calls m_{i+1} for i < n; m_{n-1} returns its
/// argument unchanged. Declaration order is m0..m(n-1) THEN verify, matching
/// N-180's own chain fixture: at n=MAX_CALL_DEPTH only `verify` exceeds the
/// bound, but at n=20000 `m0` is declared first and already exceeds it.
fn chain_ir(n: usize) -> String {
    let mut methods = String::new();
    for i in 0..n {
        if i > 0 {
            methods.push(',');
        }
        if i == n - 1 {
            methods.push_str(&format!(
                r#"{{"name": "m{i}", "isPublic": false, "params": [{{"name": "x", "type": "bigint"}}], "body": [
                    {{"name": "t0", "value": {{"kind": "load_param", "name": "x"}}}}
                ]}}"#,
                i = i
            ));
        } else {
            methods.push_str(&format!(
                r#"{{"name": "m{i}", "isPublic": false, "params": [{{"name": "x", "type": "bigint"}}], "body": [
                    {{"name": "t0", "value": {{"kind": "load_const", "value": "@this"}}}},
                    {{"name": "t1", "value": {{"kind": "load_param", "name": "x"}}}},
                    {{"name": "t2", "value": {{"kind": "method_call", "object": "t0", "method": "m{next}", "args": ["t1"]}}}}
                ]}}"#,
                i = i,
                next = i + 1
            ));
        }
    }
    if n > 0 {
        methods.push(',');
    }
    methods.push_str(
        r#"{"name": "verify", "isPublic": true, "params": [{"name": "a", "type": "bigint"}], "body": [
            {"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
            {"name": "t1", "value": {"kind": "load_param", "name": "a"}},
            {"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": "m0", "args": ["t1"]}},
            {"name": "t3", "value": {"kind": "load_const", "value": 0}},
            {"name": "t4", "value": {"kind": "bin_op", "op": ">=", "left": "t2", "right": "t3"}},
            {"name": "t5", "value": {"kind": "assert", "value": "t4"}}
        ]}"#,
    );
    format!(r#"{{"contractName": "Chain", "properties": [], "methods": [{methods}]}}"#, methods = methods)
}

/// `unlock(x)` calls private `p(x)`, whose body is given explicitly (either a
/// `method_call` to `callee`, or a terminal `x + 1`).
fn cycle_ir(private_methods: &[(&str, Option<&str>)]) -> String {
    let mut methods = format!(
        r#"{{"name": "unlock", "isPublic": true, "params": [{{"name": "x", "type": "bigint"}}], "body": [
            {{"name": "t0", "value": {{"kind": "load_const", "value": "@this"}}}},
            {{"name": "t1", "value": {{"kind": "load_param", "name": "x"}}}},
            {{"name": "t2", "value": {{"kind": "method_call", "object": "t0", "method": "p", "args": ["t1"]}}}},
            {{"name": "t3", "value": {{"kind": "load_const", "value": 0}}}},
            {{"name": "t4", "value": {{"kind": "bin_op", "op": ">=", "left": "t2", "right": "t3"}}}},
            {{"name": "t5", "value": {{"kind": "assert", "value": "t4"}}}}
        ]}}"#
    );
    for (name, callee) in private_methods {
        methods.push(',');
        match callee {
            None => methods.push_str(&format!(
                r#"{{"name": "{name}", "isPublic": false, "params": [{{"name": "x", "type": "bigint"}}], "body": [
                    {{"name": "t0", "value": {{"kind": "load_param", "name": "x"}}}}
                ]}}"#,
                name = name
            )),
            Some(callee) => methods.push_str(&format!(
                r#"{{"name": "{name}", "isPublic": false, "params": [{{"name": "x", "type": "bigint"}}], "body": [
                    {{"name": "t0", "value": {{"kind": "load_const", "value": "@this"}}}},
                    {{"name": "t1", "value": {{"kind": "load_param", "name": "x"}}}},
                    {{"name": "t2", "value": {{"kind": "method_call", "object": "t0", "method": "{callee}", "args": ["t1"]}}}}
                ]}}"#,
                name = name,
                callee = callee
            )),
        }
    }
    format!(r#"{{"contractName": "Rec", "properties": [], "methods": [{methods}]}}"#, methods = methods)
}

#[test]
fn n265_chain_at_max_call_depth_compiles() {
    compile_from_ir_str(&chain_ir(MAX_CALL_DEPTH))
        .unwrap_or_else(|e| panic!("chain at MAX_CALL_DEPTH must compile: {}", e));
}

#[test]
fn n265_chain_one_past_max_call_depth_refused() {
    let err = compile_from_ir_str(&chain_ir(MAX_CALL_DEPTH + 1))
        .expect_err("expected a call-depth refusal, got a compiled artifact");
    let want = format!("call depth of method 'verify' exceeds MAX_CALL_DEPTH (limit={})", MAX_CALL_DEPTH);
    assert!(err.contains(&want), "expected {:?}, got: {}", want, err);
}

#[test]
fn n265_20000_link_chain_refused_promptly() {
    let start = std::time::Instant::now();
    let err = compile_from_ir_str(&chain_ir(20000))
        .expect_err("expected a call-depth refusal, got a compiled artifact");
    let want = format!("call depth of method 'm0' exceeds MAX_CALL_DEPTH (limit={})", MAX_CALL_DEPTH);
    assert!(err.contains(&want), "expected {:?}, got: {}", want, err);
    assert!(start.elapsed().as_secs() < 10, "refusal took too long: {:?}", start.elapsed());
}

#[test]
fn n265_direct_self_recursion_refused() {
    let err = compile_from_ir_str(&cycle_ir(&[("p", Some("p"))]))
        .expect_err("expected a recursion refusal, got a compiled artifact");
    assert!(err.contains("recursion detected"), "{}", err);
    assert!(err.contains("calls itself directly or indirectly"), "{}", err);
    assert!(err.contains("method 'p'"), "{}", err);
}

#[test]
fn n265_mutual_recursion_refused() {
    let err = compile_from_ir_str(&cycle_ir(&[("p", Some("q")), ("q", Some("p"))]))
        .expect_err("expected a recursion refusal, got a compiled artifact");
    assert!(err.contains("recursion detected"), "{}", err);
    assert!(err.contains("method 'p'") || err.contains("method 'q'"), "{}", err);
}

#[test]
fn n265_non_recursive_chain_still_compiles() {
    compile_from_ir_str(&cycle_ir(&[("p", Some("q")), ("q", Some("r")), ("r", None)]))
        .unwrap_or_else(|e| panic!("non-recursive helper chain must compile: {}", e));
}
