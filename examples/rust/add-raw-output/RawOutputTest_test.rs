// RawOutputTest.runar.rs uses `self.add_raw_output` and `self.add_output` —
// Rúnar intrinsics that the compiler materialises into the emitted Bitcoin
// Script. `#[runar::contract]` generates both as real methods on the Rust
// struct (F-057 for `add_output`; N-122 for `add_raw_output`), each recording
// what it was given on its own thread-local log, so `#[path] mod contract;`
// below compiles and runs the real contract rather than only the Rúnar
// frontend.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("RawOutputTest.runar.rs"),
        "RawOutputTest.runar.rs",
    )
    .unwrap();
}

#[path = "RawOutputTest.runar.rs"]
mod contract;

#[test]
fn native_add_output_methods_compile_and_run() {
    let mut c = contract::RawOutputTest { count: 0 };
    c.send_to_script(vec![0x51]);
    assert_eq!(c.count, 1);
}

// N-122: `add_raw_output` used to discard its arguments — the method existed
// (so the test above already compiled) but nothing could be asserted about
// what `send_to_script` actually emitted. Proves the recorded satoshis and
// script bytes round-trip, and that `take_raw_outputs` drains; does not prove
// anything about emitted Bitcoin Script.
#[test]
fn add_raw_output_records_satoshis_and_script() {
    let mut c = contract::RawOutputTest { count: 0 };
    c.send_to_script(vec![0x51]);
    c.send_to_script(vec![0x52, 0x53]);

    let raw = contract::RawOutputTest::take_raw_outputs();
    assert_eq!(
        raw,
        vec![
            contract::RawOutputTestRawOutput { satoshis: 1000, script: vec![0x51] },
            contract::RawOutputTestRawOutput { satoshis: 1000, script: vec![0x52, 0x53] },
        ]
    );
    assert!(
        contract::RawOutputTest::take_raw_outputs().is_empty(),
        "take_raw_outputs drains the log"
    );

    // send_to_script also emits one add_output per call, which is a
    // different log entirely — recording add_raw_output must not feed it.
    let outputs = contract::RawOutputTest::take_outputs();
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].count, 1);
    assert_eq!(outputs[1].count, 2);
}
