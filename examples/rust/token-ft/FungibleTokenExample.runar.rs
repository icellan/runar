use runar::prelude::*;

#[runar::contract]
pub struct FungibleToken {
    pub owner: PubKey,       // stateful: current token owner
    pub balance: Bigint,     // stateful: token balance in this UTXO
    #[readonly]
    pub token_id: ByteString, // immutable: token identifier
}

#[runar::methods(FungibleToken)]
impl FungibleToken {
    /// Split: 1 input -> 2 outputs (recipient + change)
    #[public]
    pub fn transfer(&mut self, sig: &Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(amount > 0);
        assert!(amount <= self.balance);

        let change_owner = self.owner.clone();
        let change_balance = self.balance - amount;
        self.add_output(output_satoshis, to, amount);
        self.add_output(output_satoshis, change_owner, change_balance);
    }

    /// Simple send: 1 input -> 1 output, full balance
    #[public]
    pub fn send(&mut self, sig: &Sig, to: PubKey, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        self.add_output(output_satoshis, to, self.balance);
    }

    /// Merge: N inputs -> 1 output (each input calls this independently)
    #[public]
    pub fn merge(&mut self, sig: &Sig, total_balance: Bigint, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(total_balance >= self.balance);
        let owner = self.owner.clone();
        self.add_output(output_satoshis, owner, total_balance);
    }
}
