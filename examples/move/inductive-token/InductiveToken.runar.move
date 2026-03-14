module InductiveToken {
    use runar::InductiveSmartContract;

    resource struct InductiveToken has inductive {
        owner: &mut PubKey,
        balance: &mut bigint,
        token_id: ByteString,
    }

    public fun transfer(contract: &mut InductiveToken, sig: Sig, to: PubKey, amount: bigint, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(amount > 0, 0);
        assert!(amount <= contract.balance, 0);

        contract.add_output(output_satoshis, to, amount);
        contract.add_output(output_satoshis, contract.owner, contract.balance - amount);
    }

    public fun send(contract: &mut InductiveToken, sig: Sig, to: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);

        contract.add_output(output_satoshis, to, contract.balance);
    }
}
