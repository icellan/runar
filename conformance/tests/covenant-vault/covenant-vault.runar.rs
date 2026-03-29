use runar::prelude::*;

#[runar::contract]
struct CovenantVault {
    #[readonly]
    owner: PubKey,
    #[readonly]
    recipient: Addr,
    #[readonly]
    min_amount: Bigint,
}

#[runar::methods(CovenantVault)]
impl CovenantVault {
    #[public]
    fn spend(&self, sig: Sig, tx_preimage: SigHashPreimage) {
        assert!(check_sig(sig, self.owner));
        assert!(check_preimage(tx_preimage));
        let p2pkh_script = cat(cat("1976a914", self.recipient), "88ac");
        let expected_output = cat(num2bin(self.min_amount, 8), p2pkh_script);
        assert!(hash256(expected_output) == extract_output_hash(tx_preimage));
    }
}
