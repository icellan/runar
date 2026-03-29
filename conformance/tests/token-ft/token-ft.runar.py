from runar import (
    StatefulSmartContract, PubKey, Sig, ByteString, Bigint, Readonly,
    public, assert_, check_sig, hash256, substr, extract_hash_prevouts, extract_outpoint,
)

class FungibleToken(StatefulSmartContract):
    owner: PubKey
    balance: Bigint
    merge_balance: Bigint
    token_id: Readonly[ByteString]

    def __init__(self, owner: PubKey, balance: Bigint, merge_balance: Bigint, token_id: ByteString):
        super().__init__(owner, balance, merge_balance, token_id)
        self.owner = owner
        self.balance = balance
        self.merge_balance = merge_balance
        self.token_id = token_id

    @public
    def transfer(self, sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint):
        assert_(check_sig(sig, self.owner))
        assert_(output_satoshis >= 1)
        total_balance = self.balance + self.merge_balance
        assert_(amount > 0)
        assert_(amount <= total_balance)
        self.add_output(output_satoshis, to, amount, 0)
        if amount < total_balance:
            self.add_output(output_satoshis, self.owner, total_balance - amount, 0)

    @public
    def send(self, sig: Sig, to: PubKey, output_satoshis: Bigint):
        assert_(check_sig(sig, self.owner))
        assert_(output_satoshis >= 1)
        self.add_output(output_satoshis, to, self.balance + self.merge_balance, 0)

    @public
    def merge(self, sig: Sig, other_balance: Bigint, all_prevouts: ByteString, output_satoshis: Bigint):
        assert_(check_sig(sig, self.owner))
        assert_(output_satoshis >= 1)
        assert_(other_balance >= 0)
        assert_(hash256(all_prevouts) == extract_hash_prevouts(self.tx_preimage))
        my_outpoint = extract_outpoint(self.tx_preimage)
        first_outpoint = substr(all_prevouts, 0, 36)
        my_balance = self.balance + self.merge_balance
        if my_outpoint == first_outpoint:
            self.add_output(output_satoshis, self.owner, my_balance, other_balance)
        else:
            self.add_output(output_satoshis, self.owner, other_balance, my_balance)
