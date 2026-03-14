use runar::prelude::*;

#[runar::contract]
struct InductiveToken {
    owner: PubKey,
    balance: Int,
    #[readonly]
    token_id: ByteString,
}

#[runar::methods(InductiveToken)]
impl InductiveToken {
    #[public]
    fn transfer(&mut self, sig: &Sig, to: &PubKey, amount: Int, output_satoshis: Int) {
        assert!(check_sig(sig, &self.owner));
        assert!(amount > 0);
        assert!(amount <= self.balance);

        self.add_output(output_satoshis, to.clone(), amount);
        self.add_output(output_satoshis, self.owner.clone(), self.balance - amount);
    }

    #[public]
    fn send(&mut self, sig: &Sig, to: &PubKey, output_satoshis: Int) {
        assert!(check_sig(sig, &self.owner));

        self.add_output(output_satoshis, to.clone(), self.balance);
    }
}
