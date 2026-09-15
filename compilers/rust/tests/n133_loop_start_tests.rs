//! N-133 — `loop.start` on the `--ir` trust boundary.
//!
//! `Loop.start` is `integer | string`, and the string arm is the sanctioned
//! `"<decimal>n"` form — the suffix is REQUIRED, which is what Java's loader
//! implements and what the schema's other two string-carrying integer fields
//! (`load_const.value`, `ANFProperty.initialValue`) mean by a string.
//!
//! Rust kept `start` as a raw `serde_json::Value` all the way into
//! `lower_loop`, where it read it with
//!
//!     match parse_const_value(start) {
//!         Some(ConstValue::Int(n)) => n,
//!         _ => BigInt::from(0),          // <- everything else
//!     }
//!
//! `parse_const_value` returns `ConstValue::Str` for any string without the
//! `n` suffix, so that arm swallowed `"5"`, `"abc"`, `""`, `"5nn"` and a
//! boolean alike — all of them becoming a zero-start loop that compiles and
//! exits 0. `"5"` is the one that shows how bad that is: go, python, zig and
//! ruby all read it as 5 while this tier read it as 0, and both sides exited
//! 0 with a well-formed script.
//!
//! 0 is what makes this invisible: a perfectly plausible loop start, and the
//! commonest one.
//!
//! The probe is a two-iteration loop summing its iterator, so the start lands
//! in the emitted bytes and nothing else does.

use runar_compiler_rust::compile_from_ir_str;

fn ir(start_json: &str) -> String {
    format!(
        r#"{{
      "contractName": "LoopProbe",
      "properties": [{{"name": "target", "type": "bigint", "readonly": true}}],
      "methods": [
        {{"name": "constructor", "params": [], "isPublic": false,
         "body": [{{"name": "t0", "value": {{"kind": "call", "func": "super", "args": []}}}}]}},
        {{"name": "run", "params": [], "isPublic": true,
         "body": [
           {{"name": "acc", "value": {{"kind": "load_const", "value": 0}}}},
           {{"name": "t1", "value": {{"kind": "loop", "count": 2, "iterVar": "i",
             "start": {start_json}, "step": 1,
             "body": [{{"name": "acc", "value": {{"kind": "bin_op", "left": "acc", "op": "+", "right": "i"}}}}]}}}},
           {{"name": "t2", "value": {{"kind": "load_prop", "name": "target"}}}},
           {{"name": "t3", "value": {{"kind": "bin_op", "left": "acc", "op": "===", "right": "t2"}}}},
           {{"name": "t4", "value": {{"kind": "assert", "value": "t3"}}}}
         ]}}
      ]
    }}"#
    )
}

fn script_hex(start_json: &str) -> String {
    compile_from_ir_str(&ir(start_json))
        .unwrap_or_else(|e| panic!("loop.start {start_json}: {e}"))
        .script
}

/// Both cases non-zero: 0 is what the `_ =>` arm also produced.
#[test]
fn n133_decimal_bigint_string_start_means_the_integer() {
    for (as_string, as_integer, want) in [("\"5n\"", "5", "5b009c"), ("\"-3n\"", "-3", "0185009c")] {
        assert_eq!(script_hex(as_string), script_hex(as_integer));
        assert_eq!(script_hex(as_string), want);
    }
}

/// `start` is a `BigInt` through lowering, so this tier carries the value.
#[test]
fn n133_over_int64_start_is_not_truncated() {
    assert_eq!(
        script_hex("\"999999999999999999999999999999n\""),
        "0dffffff7fd4dbe98ca039593e19009c"
    );
}

/// The rows the `_ =>` arm silently zeroed.
#[test]
fn n133_unreadable_start_is_refused() {
    for bad in [
        "\"5\"", "\"abc\"", "\"\"", "\"5nn\"", "\"n\"", "\"-n\"", "\"1.5n\"", "true", "null",
    ] {
        assert!(
            compile_from_ir_str(&ir(bad)).is_err(),
            "loop.start {bad} was accepted; a start the loader could not read \
             became 0, which is a plausible loop start and so compiles silently"
        );
    }
}

/// The bytes every fallback-to-zero lands on. Without this the rows above
/// could all be satisfied by a probe that cannot tell two starts apart.
#[test]
fn n133_zero_start_is_its_own_script() {
    assert_eq!(script_hex("0"), "008b009c");
    assert_ne!(script_hex("0"), script_hex("5"));
}
