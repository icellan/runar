use runar::prelude::*;

#[runar::contract]
struct FunctionPatterns {
    #[readonly]
    owner: PubKey,
    balance: Bigint,
}

#[runar::methods(FunctionPatterns)]
impl FunctionPatterns {
    #[public]
    fn deposit(&mut self, sig: &Sig, amount: Bigint) {
        self.require_owner(sig);
        assert!(amount > 0);
        self.balance = self.balance + amount;
    }

    #[public]
    fn withdraw(&mut self, sig: &Sig, amount: Bigint, fee_bps: Bigint) {
        self.require_owner(sig);
        assert!(amount > 0);
        let fee = self.compute_fee(amount, fee_bps);
        let total = amount + fee;
        assert!(total <= self.balance);
        self.balance = self.balance - total;
    }

    #[public]
    fn scale(&mut self, sig: &Sig, numerator: Bigint, denominator: Bigint) {
        self.require_owner(sig);
        self.balance = self.scale_value(self.balance, numerator, denominator);
    }

    #[public]
    fn normalize(&mut self, sig: &Sig, lo: Bigint, hi: Bigint, step: Bigint) {
        self.require_owner(sig);
        let clamped = self.clamp_value(self.balance, lo, hi);
        self.balance = self.round_down(clamped, step);
    }

    fn require_owner(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.owner));
    }

    fn compute_fee(&self, amount: Bigint, fee_bps: Bigint) -> Bigint {
        percent_of(amount, fee_bps)
    }

    fn scale_value(&self, value: Bigint, numerator: Bigint, denominator: Bigint) -> Bigint {
        mul_div(value, numerator, denominator)
    }

    fn clamp_value(&self, value: Bigint, lo: Bigint, hi: Bigint) -> Bigint {
        clamp(value, lo, hi)
    }

    fn round_down(&self, value: Bigint, step: Bigint) -> Bigint {
        let remainder = safemod(value, step);
        value - remainder
    }
}
