// N-122: PrivateHelperOutputs.runar.rs calls `self.add_output` /
// `self.add_data_output` from PRIVATE helpers (`bump`, `record`,
// `fork_output`), which are internal to this module and need nothing special
// to be visible from the public methods that call them. The struct and its
// `counter` field are already `pub`, so the only reason this suite was
// compile-check-only was that `add_output` / `add_data_output` discarded
// their arguments (fixed by F-057 and N-122 respectively), leaving nothing
// to assert against a native call. See the sibling TS suite
// `examples/ts/private-helper-outputs/PrivateHelperOutputs.test.ts` for the
// same three behaviours exercised through the interpreter instead.

#[path = "PrivateHelperOutputs.runar.rs"]
mod contract;

use contract::*;

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("PrivateHelperOutputs.runar.rs"),
        "PrivateHelperOutputs.runar.rs",
    )
    .unwrap();
}

// `commit()` delegates to the private `bump()`, which mutates `counter`. The
// private helper is not reachable directly from this test file (private to
// the `contract` module), so it is pinned only through the public entry
// point — which is exactly what the audit regression (see the contract's
// header) is about: the SIDE EFFECT of a private helper must be visible to
// the caller.
#[test]
fn commit_mutates_counter_via_the_private_helper() {
    let mut c = PrivateHelperOutputs { counter: 5 };
    c.commit();
    assert_eq!(c.counter, 6);
}

#[test]
fn repeated_commit_calls_accumulate() {
    let mut c = PrivateHelperOutputs { counter: 0 };
    c.commit();
    c.commit();
    c.commit();
    assert_eq!(c.counter, 3);
}

// `log(payload)` delegates to the private `record(payload)`, which calls
// `add_data_output`. The private helper's output must register as if the
// public method had called it directly.
#[test]
fn log_emits_a_data_output_via_the_private_helper() {
    let mut c = PrivateHelperOutputs { counter: 0 };
    c.log(vec![0x68, 0x69]);

    let data = PrivateHelperOutputs::take_data_outputs();
    assert_eq!(data, vec![PrivateHelperOutputsDataOutput { satoshis: 0, data: vec![0x68, 0x69] }]);
    // `log` never calls `add_output` itself -- the private helper's
    // add_data_output must not leak into the other log.
    assert!(PrivateHelperOutputs::take_outputs().is_empty());
}

// `partition(amount, leftover)` delegates to the private
// `fork_output(amount, leftover)`, which calls `add_output`. The private
// helper's output must register as if the public method had called it
// directly, carrying `counter` positionally as `leftover` (the sole mutable
// field, per the contract's declaration order).
#[test]
fn partition_emits_a_state_output_via_the_private_helper() {
    let mut c = PrivateHelperOutputs { counter: 100 };
    c.partition(30, 70);

    let outputs = PrivateHelperOutputs::take_outputs();
    assert_eq!(outputs, vec![PrivateHelperOutputsOutput { satoshis: 30, counter: 70 }]);
}
