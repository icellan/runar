//! `RabinSig` / `RabinPubKey` are `bigint` ALIASES. A mutable one is stored in
//! the state section as a bare 8-byte OP_NUM2BIN word, on BOTH sides.
//!
//! This tier's READER already says so in three places — `is_numeric_state_type`
//! (`codegen/stack.rs`), the `lower_deserialize_state` size table (8), and
//! `fixed_state_section_length` (8). Its two state SERIALIZERS did not: they
//! tested `prop.prop_type == "bigint"` literally, so a mutable Rabin field went
//! into the accumulator in its MINIMAL script-number encoding with no NUM2BIN.
//!
//! Same class of writer/reader split as R-015 (`Sig`), and the same fund loss:
//! for any value whose minimal encoding is not exactly 8 bytes the continuation
//! this contract builds cannot be re-read by its own script. Deploy succeeds,
//! the first spend succeeds, and the UTXO it creates is dead.
//!
//! Cause: `31276a06` widened writer AND reader in the TypeScript reference;
//! `e06f8c2c` widened only Go's reader, and this tier followed Go.
//!
//! The lock: a mutable Rabin field must compile BYTE-IDENTICALLY to the same
//! contract with a `bigint` field — the path whose writer and reader are known
//! to agree. `ByteString` / `Sig` (framed) and `PubKey` (33 raw) stay the
//! negative controls, so the equality cannot be satisfied by collapsing every
//! state type onto one shape.

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

const WRITE_FILE: &str = "RabinStateWrite.runar.ts";
const ADD_OUTPUT_FILE: &str = "RabinStateAddOutput.runar.ts";

/// Mutating method, implicit continuation — drives the compute-state-bytes
/// serializer.
fn write_src(prop_type: &str) -> String {
    format!(
        "import {{ StatefulSmartContract }} from 'runar-lang';\n\
         class RabinStateWrite extends StatefulSmartContract {{\n\
         \x20 tag: {t};\n\
         \x20 constructor(tag: {t}) {{ super(tag); this.tag = tag; }}\n\
         \x20 public update(next: {t}): void {{ this.tag = next; }}\n\
         }}",
        t = prop_type
    )
}

/// Mutating method with an EXPLICIT addOutput — drives `lower_add_output`, the
/// second serializer.
fn add_output_src(prop_type: &str) -> String {
    format!(
        "import {{ StatefulSmartContract }} from 'runar-lang';\n\
         class RabinStateAddOutput extends StatefulSmartContract {{\n\
         \x20 tag: {t};\n\
         \x20 constructor(tag: {t}) {{ super(tag); this.tag = tag; }}\n\
         \x20 public update(next: {t}): void {{ this.tag = next; this.addOutput(1000n, next); }}\n\
         }}",
        t = prop_type
    )
}

fn script_hex(src: &str, file: &str) -> String {
    let opts = CompileOptions {
        disable_constant_folding: true,
        ..CompileOptions::default()
    };
    let result = compile_from_source_str_with_result(src, Some(file), &opts);
    assert!(
        !result
            .diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error),
        "compile errors for {}: {:?}",
        file,
        result.diagnostics
    );
    result.script_hex.expect("no script hex")
}

fn shapes() -> Vec<(&'static str, fn(&str) -> String, &'static str)> {
    vec![
        ("implicit continuation", write_src as fn(&str) -> String, WRITE_FILE),
        ("explicit addOutput", add_output_src as fn(&str) -> String, ADD_OUTPUT_FILE),
    ]
}

/// The decisive equality: the writer must emit the reader's fixed 8-byte word.
#[test]
fn rabin_state_writes_the_same_fixed_word_as_bigint() {
    for (label, build, file) in shapes() {
        let control = script_hex(&build("bigint"), file);
        for prop_type in ["RabinSig", "RabinPubKey"] {
            let got = script_hex(&build(prop_type), file);
            assert_eq!(
                got, control,
                "{label}: a mutable {prop_type} field does not serialize like bigint — \
                 the writer disagrees with its own 8-byte reader \
                 (got {} hex chars, want {})",
                got.len(),
                control.len()
            );
        }
    }
}

/// Controls: the equality above must not be reachable by collapsing the framed
/// or other-width state types onto the same shape.
#[test]
fn rabin_state_controls_stay_distinct() {
    for (label, build, file) in shapes() {
        let control = script_hex(&build("bigint"), file);
        for prop_type in ["ByteString", "Sig", "PubKey"] {
            let got = script_hex(&build(prop_type), file);
            assert_ne!(
                got, control,
                "{label}: a mutable {prop_type} field compiled identically to bigint — \
                 the Rabin equality no longer discriminates"
            );
        }
    }
}
