// N-122: BranchedReadonlyLen sat in `examples/rust/native-exclusions/exclusions_test.rs`'s
// EXCLUDED set with a stale reason — the macro-generated struct had no
// `add_output` method at all. F-057 gave `#[runar::contract]` a real,
// recording `add_output`, which is the only thing this contract calls besides
// the `len` builtin (already mocked). Wiring it up here is what lets
// `exclusions_test.rs` drop the entry.
//
// Business-logic reference: `conformance/witnesses/real-crypto/branched-readonly-len.json`
// pins the same two branches against @bsv/sdk Spend (constructor count=5,
// tag=0x3030): spend(0x4142) takes the len>0 arm (count 5->6, tag->0x4142);
// spend(0x) takes the len==0 arm (count 5->4, tag->0x3030).

#[path = "BranchedReadonlyLen.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("BranchedReadonlyLen.runar.rs"),
        "BranchedReadonlyLen.runar.rs",
    )
    .unwrap();
}

#[test]
fn spend_with_nonempty_scratch_takes_the_then_arm() {
    let mut c = BranchedReadonlyLen { count: 5, tag: to_byte_string("3030") };
    c.spend(vec![0x41, 0x42]);
    assert_eq!(c.count, 6);
    assert_eq!(c.tag, vec![0x41, 0x42]);

    let outputs = BranchedReadonlyLen::take_outputs();
    assert_eq!(
        outputs,
        vec![BranchedReadonlyLenOutput { satoshis: 1000, count: 6, tag: vec![0x41, 0x42] }]
    );
}

#[test]
fn spend_with_empty_scratch_takes_the_else_arm() {
    let mut c = BranchedReadonlyLen { count: 5, tag: to_byte_string("3030") };
    c.spend(vec![]);
    assert_eq!(c.count, 4);
    assert_eq!(c.tag, to_byte_string("3030"));

    let outputs = BranchedReadonlyLen::take_outputs();
    assert_eq!(
        outputs,
        vec![BranchedReadonlyLenOutput { satoshis: 1000, count: 4, tag: to_byte_string("3030") }]
    );
}
