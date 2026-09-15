//! N-132 — a string `ANFProperty.initialValue` on the `--ir` trust boundary.
//!
//! The string arm of `initialValue` carries two different things, and the
//! discriminator is the trailing `n` — exactly as it is for `load_const.value`:
//!
//!   `"42n"`       a decimal bigint -> the number 42
//!   `"deadbeef"`  a hex ByteString -> the bytes `de ad be ef`
//!
//! Rust reads the first arm correctly (R-017 pinned that). What it did not do
//! was FAIL on a string that is neither. `hex_to_bytes` asserts on odd length
//! but then decodes each pair with `u8::from_str_radix(..).unwrap_or(0)`, so a
//! non-hex digit pair became `0x00` rather than an error:
//!
//!   `"zz"`    -> pushes `0x00`     while go/python/zig/java refuse
//!   `"1.5n"`  -> pushes `0x0000`   while go/python/zig/java refuse
//!
//! Both are bytes in a locking script that the IR did not contain, arrived at
//! by a decoder that could not fail. That is the same fail-open shape N-131
//! was about, in the one decoder nobody looked at because a bad hex string
//! looks obviously bad — so nobody checked that the tiers agreed it was.
//!
//! The probe is a four-byte script — push the property, OP_EQUALVERIFY against
//! the parameter — so each assertion is about the property's bytes and nothing
//! else.

use runar_compiler_rust::compile_from_ir_str;

/// secp256k1's group order, minimally encoded as script push data: PUSH33 then
/// the 33-byte little-endian sign-magnitude body.
const EC_N: &str =
    "115792089237316195423570985008687907852837564279074904382605163141518161494337";
const EC_N_PUSH: &str =
    "21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00";

/// Smallest IR that pushes one property's `initialValue`. The value is spliced
/// in as raw JSON text so a test can write a string, a number, or a literal of
/// any width without a Rust type getting an opinion about it first.
fn ir(initial_value_json: &str) -> String {
    format!(
        r#"{{
      "contractName": "InitProbe",
      "properties": [
        {{"name": "v", "type": "bigint", "readonly": true, "initialValue": {initial_value_json}}}
      ],
      "methods": [
        {{"name": "constructor", "params": [], "isPublic": false,
         "body": [{{"name": "t0", "value": {{"kind": "call", "func": "super", "args": []}}}}]}},
        {{"name": "check", "params": [{{"name": "expected", "type": "bigint"}}], "isPublic": true,
         "body": [
           {{"name": "t0", "value": {{"kind": "load_prop", "name": "v"}}}},
           {{"name": "t1", "value": {{"kind": "load_param", "name": "expected"}}}},
           {{"name": "t2", "value": {{"kind": "bin_op", "left": "t0", "op": "===", "right": "t1"}}}},
           {{"name": "t3", "value": {{"kind": "assert", "value": "t2"}}}}
         ]}}
      ]
    }}"#
    )
}

fn script_hex(initial_value_json: &str) -> String {
    compile_from_ir_str(&ir(initial_value_json))
        .unwrap_or_else(|e| panic!("initialValue {initial_value_json}: {e}"))
        .script
}

/// A string that is neither the `"<decimal>n"` bigint form nor valid hex must
/// be REFUSED, not decoded into whatever bytes `unwrap_or(0)` produces.
///
/// `compile_from_ir_str` catches the stack-lowering panic and returns it as
/// `Err`, which is how the odd-length case already surfaces — so an `Err` here
/// is the same class of refusal the CLI reports as exit 1.
#[test]
fn n132_unreadable_string_is_refused() {
    for bad in ["\"zz\"", "\"5\"", "\"5nn\"", "\"1.5n\"", "\"n\"", "\"-n\""] {
        assert!(
            compile_from_ir_str(&ir(bad)).is_err(),
            "initialValue {bad} was accepted; a decoder that cannot fail puts \
             bytes into a locking script that the IR does not contain"
        );
    }
}

/// Not "it loads" — "it loads AS the number it spells".
#[test]
fn n132_decimal_bigint_string_means_the_integer() {
    for (as_string, as_integer) in [("\"42n\"", "42"), ("\"-3n\"", "-3"), ("\"0n\"", "0")] {
        assert_eq!(
            script_hex(as_string),
            script_hex(as_integer),
            "initialValue {as_string} must lower to the same bytes as {as_integer}"
        );
    }
}

/// 0 is what every fallback path also produces, so a non-zero case is what
/// makes the equality above mean something.
#[test]
fn n132_decimal_bigint_string_exact_bytes() {
    assert_eq!(script_hex("\"42n\""), "012a7c9c");
}

/// The reason the string form exists (issue #121): a value this wide cannot
/// survive a JSON number in a double-backed reader.
#[test]
fn n132_oversize_bigint_string_is_not_truncated() {
    assert!(script_hex(&format!("\"{EC_N}n\"")).contains(EC_N_PUSH));
}

/// The control an over-broad fix fails: `"1000"` is the two bytes 0x10 0x00,
/// not one thousand. A tier that reads any all-digit string as decimal passes
/// every other test in this file.
#[test]
fn n132_bare_digit_string_is_hex_not_decimal() {
    let as_hex = script_hex("\"1000\"");
    let as_decimal = script_hex("1000");
    assert_eq!(as_hex, "0210007c9c");
    assert_eq!(as_decimal, "02e8037c9c");
    assert_ne!(as_hex, as_decimal);
}

/// The hex arm still works. A guard that refuses bad hex by refusing hex
/// reddens here.
#[test]
fn n132_hex_bytestring_still_decodes() {
    assert_eq!(script_hex("\"deadbeef\""), "04deadbeef7c9c");
    assert_eq!(script_hex("\"\""), "007c9c");
    // Upper case is hex too, and the strict decoder must keep accepting it.
    assert_eq!(script_hex("\"DEADBEEF\""), "04deadbeef7c9c");
}
