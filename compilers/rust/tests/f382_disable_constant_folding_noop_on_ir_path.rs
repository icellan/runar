//! F-382: --disable-constant-folding is a silent no-op on the --ir path
//!
//! This test verifies that:
//! 1. The CLI help text documents that the flag is a no-op when using --ir
//! 2. Compiling from IR with and without the flag produces byte-identical output
//!    (proving the documentation is truthful and the behavior is correct)

use std::path::PathBuf;
use std::process::Command;

/// Test 1: Help text documents the no-op behavior
#[test]
fn help_text_documents_disable_constant_folding_noop_on_ir_path() {
    let cargo_bin = env!("CARGO_BIN_EXE_runar-compiler-rust");
    let output = Command::new(cargo_bin)
        .arg("--help")
        .output()
        .expect("Failed to run CLI with --help");

    let help_text = String::from_utf8_lossy(&output.stdout);

    // Assert that the help text mentions the flag
    assert!(
        help_text.contains("--disable-constant-folding"),
        "Help text should mention --disable-constant-folding flag"
    );

    // Assert that it documents the no-op behavior on --ir path
    assert!(
        help_text.contains("no-op when using --ir")
            || help_text.contains("no-op") && help_text.contains("--ir"),
        "Help text should document that --disable-constant-folding is a no-op on the --ir path.\nActual help text:\n{}",
        help_text
    );
}

/// Test 2: IR compilation is byte-identical with and without the flag
#[test]
fn ir_compilation_is_identical_with_and_without_disable_constant_folding() {
    let cargo_bin = env!("CARGO_BIN_EXE_runar-compiler-rust");

    // Use a conformance fixture IR file (arithmetic is a simple, stable fixture)
    let ir_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get parent directory")
        .parent()
        .expect("Failed to get parent directory")
        .join("conformance/tests/arithmetic/expected-ir.json");

    if !ir_path.exists() {
        // Skip if the fixture doesn't exist (e.g., in certain build environments)
        eprintln!("Skipping: IR fixture not found at {:?}", ir_path);
        return;
    }

    // Compile with --disable-constant-folding
    let output_with_flag = Command::new(cargo_bin)
        .arg("--ir")
        .arg(&ir_path)
        .arg("--hex")
        .arg("--disable-constant-folding")
        .output()
        .expect("Failed to run compiler with --disable-constant-folding");

    let hex_with_flag = String::from_utf8_lossy(&output_with_flag.stdout).trim().to_string();

    // Compile without --disable-constant-folding
    let output_without_flag = Command::new(cargo_bin)
        .arg("--ir")
        .arg(&ir_path)
        .arg("--hex")
        .output()
        .expect("Failed to run compiler without --disable-constant-folding");

    let hex_without_flag = String::from_utf8_lossy(&output_without_flag.stdout).trim().to_string();

    // Both should succeed
    assert!(
        output_with_flag.status.success(),
        "Compiler with --disable-constant-folding should succeed. stderr: {}",
        String::from_utf8_lossy(&output_with_flag.stderr)
    );

    assert!(
        output_without_flag.status.success(),
        "Compiler without --disable-constant-folding should succeed. stderr: {}",
        String::from_utf8_lossy(&output_without_flag.stderr)
    );

    // The outputs must be identical (proving the flag is a no-op)
    assert_eq!(
        hex_with_flag, hex_without_flag,
        "IR compilation output should be identical with and without --disable-constant-folding\n\
         This proves the flag is a no-op on the --ir path.\n\
         With flag:    {}\n\
         Without flag: {}",
        hex_with_flag, hex_without_flag
    );
}
