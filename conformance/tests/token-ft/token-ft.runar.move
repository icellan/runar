module FungibleToken {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig, hash256, extract_hash_prevouts, extract_outpoint, substr};

    resource struct FungibleToken {
        owner: &mut PubKey,
        balance: &mut bigint,
        merge_balance: &mut bigint,
        token_id: ByteString,
    }

    public fun transfer(contract: &mut FungibleToken, sig: Sig, to: PubKey, amount: bigint, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        let total_balance: bigint = contract.balance + contract.merge_balance;
        assert!(amount > 0, 0);
        assert!(amount <= total_balance, 0);
        contract.add_output(output_satoshis, to, amount, 0);
        if (amount < total_balance) {
            contract.add_output(output_satoshis, contract.owner, total_balance - amount, 0);
        }
    }

    public fun send(contract: &mut FungibleToken, sig: Sig, to: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        contract.add_output(output_satoshis, to, contract.balance + contract.merge_balance, 0);
    }

    public fun merge(contract: &mut FungibleToken, sig: Sig, other_balance: bigint, all_prevouts: ByteString, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        assert!(other_balance >= 0, 0);
        assert!(hash256(all_prevouts) == extract_hash_prevouts(contract.tx_preimage), 0);
        let my_outpoint: ByteString = extract_outpoint(contract.tx_preimage);
        let first_outpoint: ByteString = substr(all_prevouts, 0, 36);
        let my_balance: bigint = contract.balance + contract.merge_balance;
        if (my_outpoint == first_outpoint) {
            contract.add_output(output_satoshis, contract.owner, my_balance, other_balance);
        } else {
            contract.add_output(output_satoshis, contract.owner, other_balance, my_balance);
        }
    }
}
