use runar::prelude::*;

/// AllReadonlyCleanstack — regression fixture for issue #44.
///
/// A `StatefulSmartContract` with ZERO mutable fields (only a readonly `owner`)
/// plus a readonly-field-binding in a terminal method. The `owner_copy = owner`
/// binding force-embeds the readonly field onto the stack; it is not consumed by
/// the terminal `check_sig` assertion, leaving an excess stack item below the
/// top-of-stack boolean. Before the fix, the leftover survived and the spend was
/// rejected on mainnet with "Script did not clean its stack". The fix runs the
/// stack cleanup for every public method, emitting the trailing `OP_NIP`.
#[runar::stateful_contract]
struct AllReadonlyCleanstack {
    #[readonly]
    owner: PubKey,
}

impl AllReadonlyCleanstack {
    pub fn claim(&self, sig: &Sig) {
        let owner_copy = self.owner;
        assert!(check_sig(sig, self.owner));
    }
}
