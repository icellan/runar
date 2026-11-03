// DataOutputTest.runar.rs uses `self.add_data_output` — a Rúnar intrinsic the
// compiler materialises into emitted Bitcoin Script. `#[runar::contract]`
// generates it as a real method on the Rust struct that records what it was
// given on a thread-local log (N-122; the peer add-raw-output test follows
// the same pattern), so `#[path] mod contract;` below compiles and runs the
// real contract rather than only the Rúnar frontend.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("DataOutputTest.runar.rs"),
        "DataOutputTest.runar.rs",
    )
    .unwrap();
}

#[path = "DataOutputTest.runar.rs"]
mod contract;

#[test]
fn native_publish_compiles_and_runs() {
    let mut c = contract::DataOutputTest { count: 0 };
    c.publish(vec![0xaa]);
    assert_eq!(c.count, 1);
}

// N-122: `add_data_output` used to discard its arguments — the method
// existed (so the test above already compiled) but nothing could be asserted
// about what `publish` actually emitted. Proves the recorded satoshis and
// payload bytes round-trip, and that `take_data_outputs` drains. `publish`
// only ever calls `add_data_output`, never `add_output` (the state
// continuation is an auto-injected compiler intrinsic, not a native call this
// mock sees) — does not prove anything about emitted Bitcoin Script.
#[test]
fn add_data_output_records_satoshis_and_payload() {
    let mut c = contract::DataOutputTest { count: 0 };
    c.publish(vec![0xaa]);
    c.publish(vec![0xbb, 0xcc]);
    assert_eq!(c.count, 2);

    let data = contract::DataOutputTest::take_data_outputs();
    assert_eq!(
        data,
        vec![
            contract::DataOutputTestDataOutput { satoshis: 0, data: vec![0xaa] },
            contract::DataOutputTestDataOutput { satoshis: 0, data: vec![0xbb, 0xcc] },
        ]
    );
    assert!(
        contract::DataOutputTest::take_data_outputs().is_empty(),
        "take_data_outputs drains the log"
    );
}
