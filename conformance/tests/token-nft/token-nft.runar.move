module SimpleNFT {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig};

    resource struct SimpleNFT {
        owner: &mut PubKey,
        token_id: ByteString,
        metadata: ByteString,
    }

    public fun transfer(contract: &mut SimpleNFT, sig: Sig, new_owner: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        contract.add_output(output_satoshis, new_owner);
    }

    public fun burn(contract: &mut SimpleNFT, sig: Sig) {
        assert!(check_sig(sig, contract.owner), 0);
    }
}
