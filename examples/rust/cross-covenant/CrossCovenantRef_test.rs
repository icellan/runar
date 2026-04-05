#[path = "CrossCovenantRef.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

// ---------------------------------------------------------------------------
// Test fixtures -- simulated referenced output
// ---------------------------------------------------------------------------

// Layout: 16 bytes prefix + 32 bytes state root + 8 bytes suffix
fn test_prefix() -> Vec<u8> {
    vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
    ]
}

fn test_state_root() -> Vec<u8> {
    vec![
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    ]
}

fn test_suffix() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

fn test_referenced_output() -> Vec<u8> {
    let mut out = test_prefix();
    out.extend_from_slice(&test_state_root());
    out.extend_from_slice(&test_suffix());
    out
}

// ---------------------------------------------------------------------------
// verify_and_extract
// ---------------------------------------------------------------------------

#[test]
fn test_verify_and_extract() {
    let output = test_referenced_output();
    let output_hash = hash256(&output);
    let c = CrossCovenantRef { source_script_hash: output_hash };
    c.verify_and_extract(output.clone(), test_state_root(), 16);
}

#[test]
#[should_panic]
fn test_verify_and_extract_tampered() {
    let mut output = test_referenced_output();
    let output_hash = hash256(&output);
    output[0] = 0xff; // tamper
    let c = CrossCovenantRef { source_script_hash: output_hash };
    c.verify_and_extract(output, test_state_root(), 16);
}

#[test]
#[should_panic]
fn test_verify_and_extract_wrong_root() {
    let output = test_referenced_output();
    let output_hash = hash256(&output);
    let wrong_root = vec![0u8; 32];
    let c = CrossCovenantRef { source_script_hash: output_hash };
    c.verify_and_extract(output, wrong_root, 16);
}

// ---------------------------------------------------------------------------
// verify_and_extract_numeric
// ---------------------------------------------------------------------------

#[test]
fn test_verify_and_extract_numeric() {
    // Build an output with a numeric value embedded at offset 16
    let mut num_output = vec![0u8; 16];
    // Embed the value 42 as a 4-byte LE signed-magnitude value
    let num_value = num2bin(&42, 4);
    num_output.extend_from_slice(&num_value);
    num_output.extend_from_slice(&[0u8; 8]);
    let num_hash = hash256(&num_output);

    let c = CrossCovenantRef { source_script_hash: num_hash };
    c.verify_and_extract_numeric(num_output, 42, 16, 4);
}

// ---------------------------------------------------------------------------
// Compile check
// ---------------------------------------------------------------------------

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("CrossCovenantRef.runar.rs"),
        "CrossCovenantRef.runar.rs",
    )
    .unwrap();
}
