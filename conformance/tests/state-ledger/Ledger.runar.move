// Ledger -- F-352 second witness for the mutable-state shape
// {PubKey, bigint, bigint}.
module Ledger {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig};

    resource struct Ledger {
        holder: &mut PubKey,
        balance: &mut bigint,
        nonce: &mut bigint,
    }

    public fun spend(contract: &mut Ledger, sig: Sig, amount: bigint) {
        assert!(check_sig(sig, contract.holder), 0);
        assert!(amount > 0, 0);
        assert!(amount <= contract.balance, 0);
        contract.balance = contract.balance - amount;
        contract.nonce = contract.nonce + 1;
    }
}
