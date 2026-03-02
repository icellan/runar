module FungibleToken {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig};

    resource struct FungibleToken {
        owner: &mut PubKey,
        balance: &mut bigint,
        token_id: ByteString,
    }

    // Split: 1 input -> 2 outputs (recipient + change)
    public fun transfer(contract: &mut FungibleToken, sig: Sig, to: PubKey, amount: bigint, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(amount > 0, 0);
        assert!(amount <= contract.balance, 0);

        // add_output(satoshis, owner, balance) -- args match mutable props in order
        contract.add_output(output_satoshis, to, amount);
        contract.add_output(output_satoshis, contract.owner, contract.balance - amount);
    }

    // Simple send: 1 input -> 1 output, full balance
    public fun send(contract: &mut FungibleToken, sig: Sig, to: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);

        contract.add_output(output_satoshis, to, contract.balance);
    }

    // Merge: N inputs -> 1 output (each input calls this independently)
    public fun merge(contract: &mut FungibleToken, sig: Sig, total_balance: bigint, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(total_balance >= contract.balance, 0);

        contract.add_output(output_satoshis, contract.owner, total_balance);
    }
}
