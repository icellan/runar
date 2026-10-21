// Notary -- F-352 second witness for the mutable-state shape
// {ByteString, PubKey, bigint}, with the PubKey declared first.
module Notary {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig};

    resource struct Notary {
        signer: &mut PubKey,
        note: &mut ByteString,
        seq: &mut bigint,
    }

    public fun notarize(contract: &mut Notary, sig: Sig, next_note: ByteString) {
        assert!(check_sig(sig, contract.signer), 0);
        contract.note = next_note;
        contract.seq = contract.seq + 1;
    }
}
