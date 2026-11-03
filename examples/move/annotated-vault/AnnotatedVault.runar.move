// AnnotatedVault -- N-044 conformance fixture: a mutable variable-length
// ByteString state field (memo) BEFORE a mutable PubKey (owner). Anyone may
// replace the memo; only the owner may withdraw.
module AnnotatedVault {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig};

    resource struct AnnotatedVault {
        memo: &mut ByteString,
        owner: &mut PubKey,
        balance: &mut bigint,
    }

    // Replace the memo. Anyone can call.
    public fun annotate(contract: &mut AnnotatedVault, next_memo: ByteString) {
        contract.memo = next_memo;
    }

    // Only the owner may spend.
    public fun withdraw(contract: &AnnotatedVault, sig: Sig) {
        assert!(check_sig(sig, contract.owner), 0);
    }
}
