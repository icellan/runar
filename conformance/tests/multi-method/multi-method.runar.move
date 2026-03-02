module MultiMethod {
    use runar::types::{PubKey, Sig, Int};
    use runar::crypto::{check_sig};

    resource struct MultiMethod {
        owner: PubKey,
        backup: PubKey,
    }

    fun compute_threshold(a: Int, b: Int): Int {
        a * b + 1
    }

    public fun spend_with_owner(contract: &MultiMethod, sig: Sig, amount: Int) {
        let threshold = compute_threshold(amount, 2);
        assert!(threshold > 10, 0);
        assert!(check_sig(sig, contract.owner), 0);
    }

    public fun spend_with_backup(contract: &MultiMethod, sig: Sig) {
        assert!(check_sig(sig, contract.backup), 0);
    }
}
