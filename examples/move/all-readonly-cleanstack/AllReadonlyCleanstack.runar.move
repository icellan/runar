// AllReadonlyCleanstack — regression fixture for issue #44.
//
// A StatefulSmartContract with ZERO mutable fields (only a readonly `owner`)
// plus a readonly-field-binding in a terminal method. The `owner_copy = owner`
// binding force-embeds the readonly field onto the stack; it is not consumed by
// the terminal check_sig assertion, leaving an excess stack item below the
// top-of-stack boolean. Before the fix, the leftover survived and the spend was
// rejected on mainnet with "Script did not clean its stack". The fix runs
// cleanupExcessStack() for every public method, emitting the trailing OP_NIP.
module AllReadonlyCleanstack {
    use runar::StatefulSmartContract;
    use runar::types::{PubKey, Sig};
    use runar::crypto::check_sig;

    resource struct AllReadonlyCleanstack {
        owner: PubKey,
    }

    public fun claim(contract: &AllReadonlyCleanstack, sig: Sig) {
        let owner_copy = contract.owner;
        assert!(check_sig(sig, contract.owner), 0);
    }
}
