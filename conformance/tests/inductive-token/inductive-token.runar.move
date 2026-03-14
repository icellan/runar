module InductiveToken {
    use runar::InductiveSmartContract;

    resource struct InductiveToken has inductive {
        owner: &mut PubKey,
        balance: &mut Int,
        token_id: ByteString,
    }

    public fun transfer(contract: &mut InductiveToken, sig: Sig, to: PubKey, amount: Int, output_satoshis: Int) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(amount > 0, 0);
        assert!(amount <= contract.balance, 0);

        add_output(contract, output_satoshis, to, amount);
        add_output(contract, output_satoshis, contract.owner, contract.balance - amount);
    }

    public fun send(contract: &mut InductiveToken, sig: Sig, to: PubKey, output_satoshis: Int) {
        assert!(check_sig(sig, contract.owner), 0);

        add_output(contract, output_satoshis, to, contract.balance);
    }
}
