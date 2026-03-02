use runar::prelude::*;

#[runar::contract]
struct MultiMethod {
    #[readonly]
    owner: PubKey,
    #[readonly]
    backup: PubKey,
}

#[runar::methods(MultiMethod)]
impl MultiMethod {
    fn compute_threshold(&self, a: Int, b: Int) -> Int {
        a * b + 1
    }

    #[public]
    fn spend_with_owner(&self, sig: Sig, amount: Int) {
        let threshold = self.compute_threshold(amount, 2);
        assert!(threshold > 10);
        assert!(check_sig(sig, self.owner));
    }

    #[public]
    fn spend_with_backup(&self, sig: Sig) {
        assert!(check_sig(sig, self.backup));
    }
}
