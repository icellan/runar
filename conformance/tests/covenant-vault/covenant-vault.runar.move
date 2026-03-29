module CovenantVault {
    use runar::types::{PubKey, Sig, Addr, ByteString, SigHashPreimage};
    use runar::crypto::{check_sig, check_preimage, extract_output_hash, hash256, num2bin, cat};

    struct CovenantVault {
        owner: PubKey,
        recipient: Addr,
        min_amount: bigint,
    }

    public fun spend(contract: &CovenantVault, sig: Sig, tx_preimage: SigHashPreimage) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(check_preimage(tx_preimage), 0);
        let p2pkh_script: ByteString = cat(cat(0x1976a914, contract.recipient), 0x88ac);
        let expected_output: ByteString = cat(num2bin(contract.min_amount, 8), p2pkh_script);
        assert!(hash256(expected_output) == extract_output_hash(tx_preimage), 0);
    }
}
