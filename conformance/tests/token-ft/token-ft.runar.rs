use runar::prelude::*;

#[runar::contract]
struct FungibleToken {
    owner: PubKey,
    balance: Bigint,
    merge_balance: Bigint,
    #[readonly]
    token_id: ByteString,
}

#[runar::methods(FungibleToken)]
impl FungibleToken {
    #[public]
    fn transfer(&mut self, sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint) {
        assert!(check_sig(sig, self.owner));
        assert!(output_satoshis >= 1);
        let total_balance = self.balance + self.merge_balance;
        assert!(amount > 0);
        assert!(amount <= total_balance);
        self.add_output(output_satoshis, to, amount, 0);
        if amount < total_balance {
            self.add_output(output_satoshis, self.owner, total_balance - amount, 0);
        }
    }

    #[public]
    fn send(&mut self, sig: Sig, to: PubKey, output_satoshis: Bigint) {
        assert!(check_sig(sig, self.owner));
        assert!(output_satoshis >= 1);
        self.add_output(output_satoshis, to, self.balance + self.merge_balance, 0);
    }

    #[public]
    fn merge(&mut self, sig: Sig, other_balance: Bigint, all_prevouts: ByteString, output_satoshis: Bigint) {
        assert!(check_sig(sig, self.owner));
        assert!(output_satoshis >= 1);
        assert!(other_balance >= 0);
        assert!(hash256(all_prevouts) == extract_hash_prevouts(self.tx_preimage));
        let my_outpoint = extract_outpoint(self.tx_preimage);
        let first_outpoint = substr(all_prevouts, 0, 36);
        let my_balance = self.balance + self.merge_balance;
        if my_outpoint == first_outpoint {
            self.add_output(output_satoshis, self.owner, my_balance, other_balance);
        } else {
            self.add_output(output_satoshis, self.owner, other_balance, my_balance);
        }
    }
}
