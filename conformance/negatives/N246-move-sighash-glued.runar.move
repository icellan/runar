// N-244: the sighash marker glued to its flag list on the Move surface.
// Only .runar.ts honours the directive; every other surface must refuse ANY
// occurrence of the marker (N-039's rule), not just a word-bounded one, with
// the one shared "not supported by the Move surface parser" message.
// Before N-244 every tier read the glued form as prose and compiled ALL|FORKID.
module Counter {
    resource struct Counter {
        count: &mut bigint,
    }

    // @sighashSINGLE|FORKID
    public fun increment(contract: &mut Counter) {
        contract.count = contract.count + 1;
    }
}
