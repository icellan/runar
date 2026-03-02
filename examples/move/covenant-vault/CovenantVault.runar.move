module CovenantVault {
    use runar::types::{PubKey, Sig, Addr, SigHashPreimage};
    use runar::crypto::{check_sig, check_preimage};

    struct CovenantVault {
        owner: PubKey,
        recipient: Addr,
        min_amount: bigint,
    }

    public fun spend(contract: &CovenantVault, sig: Sig, amount: bigint, tx_preimage: SigHashPreimage) {
        // Owner must authorize
        assert!(check_sig(sig, contract.owner), 0);
        assert!(check_preimage(tx_preimage), 0);

        // Enforce minimum output amount (covenant rule)
        assert!(amount >= contract.min_amount, 0);
    }
}
