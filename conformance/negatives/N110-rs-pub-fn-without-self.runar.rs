// N-050 (StaticSiphon): a static / class-level method is not a contract method.
// Pre-fix, `requirePositive` became a PUBLIC spending entry point in several
// tiers — a path anyone satisfies with `<1>` and no signature (@bsv/sdk
// Spend.validate accepted it against the TS artifact). Every tier must refuse:
//   static methods are not allowed in Rúnar contracts; method 'require_positive' is declared static
// Shape: a `pub fn` without a self receiver (an associated function) on the Rust surface.
use runar::prelude::*;

#[runar::contract]
struct Vault {
    #[readonly]
    owner: PubKey,
}

impl Vault {
    pub fn require_positive(amount: Int) {
        assert!(amount > 0);
    }

    pub fn withdraw(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.owner));
    }
}
