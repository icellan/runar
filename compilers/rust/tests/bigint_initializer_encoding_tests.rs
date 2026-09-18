//! R-017 / CL-BUG-140 — `push_json_value` must decode the cross-tier BigInt
//! wire encoding, not read it as hex.
//!
//! `bigint_to_json` (`frontend/anf_lower.rs`) emits a **decimal** string with a
//! trailing `n` for any value above `Number.MAX_SAFE_INTEGER`; the Go tier emits
//! the same value as an arbitrary-precision JSON **number**. `push_json_value`
//! (`codegen/stack.rs`) used to feed the string straight into `hex_to_bytes`
//! (decimal digits reinterpreted as hex, `…n` collapsing to `0x00`) and to read
//! the number through `as_i64().unwrap_or(0)` (anything beyond `i64` silently
//! became zero).
//!
//! The correct reader is `ir::parse_const_value`.
//!
//! Expected bytes below are the minimally-encoded little-endian Script numbers
//! and were cross-checked against the Go tier (`compilers/go/runar-go --asm`).

use runar_compiler_rust::{compile_from_ir_str, compile_from_source_str};

fn asm_of(source: &str, file: &str) -> String {
    compile_from_source_str(source, Some(file)).expect("compile should succeed").asm
}

fn contract(name: &str, literal: &str) -> String {
    format!(
        r#"
import {{ SmartContract, assert }} from 'runar-lang';

class {name} extends SmartContract {{
    readonly n: bigint = {literal};

    constructor() {{
        super();
    }}

    public unlock(x: bigint) {{
        assert(x == this.n);
    }}
}}
"#
    )
}

/// Control: a value below 2^53 rides the JSON-number arm and always worked.
/// 1152921504606846 -> LE minimal 7e 6a bc 74 93 18 04.
#[test]
fn sub_max_safe_integer_initializer_is_unchanged() {
    let asm = asm_of(&contract("Small", "1152921504606846n"), "Small.runar.ts");
    assert!(
        asm.contains("<7e6abc74931804>"),
        "sub-2^53 control regressed; asm = {asm}"
    );
}

/// 2^60 = 1152921504606846976 -> LE minimal 00 00 00 00 00 00 00 10.
/// Before the fix this emitted `<11529215046068469700>` — the decimal digits
/// read as hex with the trailing `6n` collapsed to `00`.
#[test]
fn two_pow_60_initializer_emits_the_actual_value() {
    let asm = asm_of(&contract("Big", "1152921504606846976n"), "Big.runar.ts");
    assert!(
        asm.contains("<0000000000000010>"),
        "2^60 initializer must emit its own value, not its decimal digits as hex; asm = {asm}"
    );
    assert!(
        !asm.contains("<11529215046068469700>"),
        "decimal string was still read as hex; asm = {asm}"
    );
}

/// The secp256k1 group order N. 78 decimal digits — before the fix this did not
/// even compile: `invalid hex string length: 79`.
#[test]
fn secp256k1_order_initializer_emits_the_actual_value() {
    let asm = asm_of(
        &contract(
            "Order",
            "115792089237316195423570985008687907852837564279074904382605163141518161494337n",
        ),
        "Order.runar.ts",
    );
    assert!(
        asm.contains("<414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00>"),
        "secp256k1 order initializer emitted the wrong bytes; asm = {asm}"
    );
}

/// Negative oversize values use the same `"-…n"` encoding.
/// -(2^60) -> LE minimal 00 00 00 00 00 00 00 90 (sign bit on the top byte).
#[test]
fn negative_oversize_initializer_emits_the_actual_value() {
    let asm = asm_of(&contract("Neg", "-1152921504606846976n"), "Neg.runar.ts");
    assert!(
        asm.contains("<0000000000000090>"),
        "negative oversize initializer emitted the wrong bytes; asm = {asm}"
    );
}

/// A genuine ByteString initializer is still hex and must stay hex — the
/// bigint decode must not swallow it.
#[test]
fn bytestring_initializer_is_still_hex() {
    let source = r#"
import { SmartContract, ByteString, assert } from 'runar-lang';

class Bs extends SmartContract {
    readonly b: ByteString = "deadbeef" as ByteString;
    readonly digits: ByteString = "12345678" as ByteString;

    constructor() {
        super();
    }

    public unlock(x: ByteString, y: ByteString) {
        assert(x == this.b);
        assert(y == this.digits);
    }
}
"#;
    let asm = asm_of(source, "Bs.runar.ts");
    assert!(
        asm.contains("<deadbeef>"),
        "ByteString initializer must still be decoded as hex; asm = {asm}"
    );
    // An all-decimal-digit hex ByteString has no trailing `n`, so the bigint
    // decode must not claim it.
    assert!(
        asm.contains("<12345678>"),
        "all-digit ByteString initializer must still be decoded as hex; asm = {asm}"
    );
}

// ---------------------------------------------------------------------------
// The JSON-number arm: the Go tier serialises an oversize `initialValue` as an
// arbitrary-precision JSON number, so `--ir` cross-tier codegen hits a
// different arm of `push_json_value` than the Rust frontend does.
// ---------------------------------------------------------------------------

/// Minimal hand-built ANF IR carrying `initialValue` as a raw JSON number,
/// exactly as `compilers/go/runar-go --source X --emit-ir` writes it.
fn ir_with_numeric_initial_value(literal: &str) -> String {
    format!(
        r#"{{
  "contractName": "NumArm",
  "parentClass": "SmartContract",
  "properties": [
    {{ "name": "n", "type": "bigint", "readonly": true, "initialValue": {literal} }}
  ],
  "methods": [
    {{
      "name": "constructor",
      "isPublic": false,
      "params": [],
      "body": [
        {{ "name": "t0", "value": {{ "kind": "call", "func": "super", "args": [] }} }}
      ]
    }},
    {{
      "name": "unlock",
      "isPublic": true,
      "params": [{{ "name": "x", "type": "bigint" }}],
      "body": [
        {{ "name": "t0", "value": {{ "kind": "load_param", "name": "x" }} }},
        {{ "name": "t1", "value": {{ "kind": "load_prop", "name": "n" }} }},
        {{ "name": "t2", "value": {{ "kind": "bin_op", "op": "===", "left": "t0", "right": "t1" }} }},
        {{ "name": "t3", "value": {{ "kind": "assert", "value": "t2" }} }}
      ]
    }}
  ]
}}"#
    )
}

#[test]
fn ir_numeric_initial_value_within_i64_is_unchanged() {
    let asm = compile_from_ir_str(&ir_with_numeric_initial_value("1152921504606846976"))
        .expect("compile should succeed")
        .asm;
    assert!(
        asm.contains("<0000000000000010>"),
        "in-range JSON-number control regressed; asm = {asm}"
    );
}

/// Minimal hand-built ANF IR putting the same oversize literal through
/// `load_const`, the OTHER consumer of the same JSON encoding.
fn ir_with_numeric_load_const(literal: &str) -> String {
    format!(
        r#"{{
  "contractName": "NumArm",
  "parentClass": "SmartContract",
  "properties": [],
  "methods": [
    {{
      "name": "constructor",
      "isPublic": false,
      "params": [],
      "body": [
        {{ "name": "t0", "value": {{ "kind": "call", "func": "super", "args": [] }} }}
      ]
    }},
    {{
      "name": "unlock",
      "isPublic": true,
      "params": [{{ "name": "x", "type": "bigint" }}],
      "body": [
        {{ "name": "t0", "value": {{ "kind": "load_param", "name": "x" }} }},
        {{ "name": "t1", "value": {{ "kind": "load_const", "value": {literal} }} }},
        {{ "name": "t2", "value": {{ "kind": "bin_op", "op": "===", "left": "t0", "right": "t1" }} }},
        {{ "name": "t3", "value": {{ "kind": "assert", "value": "t2" }} }}
      ]
    }}
  ]
}}"#
    )
}

/// Beyond `i64`, `as_i64().unwrap_or(0)` silently produced **zero** — the
/// comparison collapsed to `x == 0`, which the peephole folded to `OP_NOT`.
///
/// What this test pins is that `push_json_value` and `load_const` are now the
/// SAME reader (`ir::parse_const_value`) for the same JSON token, and that the
/// silent-zero is gone. It deliberately does NOT assert the exact secp256k1
/// bytes for this input: the crate builds `serde_json` without
/// `arbitrary_precision`, so an integer literal too large for `u64` is already
/// an `f64` by the time `serde_json::from_str::<ANFProgram>` returns — the
/// digits are lost at parse time, upstream of every reader. That precision
/// limit hits `load_const` identically and is a separate defect; this
/// assertion stays green when it is fixed.
#[test]
fn ir_numeric_initial_value_matches_load_const_and_is_not_zero() {
    const HUGE: &str =
        "115792089237316195423570985008687907852837564279074904382605163141518161494337";

    let via_initial_value = compile_from_ir_str(&ir_with_numeric_initial_value(HUGE))
        .expect("compile should succeed")
        .asm;
    let via_load_const = compile_from_ir_str(&ir_with_numeric_load_const(HUGE))
        .expect("compile should succeed")
        .asm;

    assert_eq!(
        via_initial_value, via_load_const,
        "an oversize JSON number must decode the same through an initializer as \
         through load_const"
    );
    assert!(
        !via_initial_value.contains("OP_NOT"),
        "oversize JSON number was still truncated to zero; asm = {via_initial_value}"
    );
}
