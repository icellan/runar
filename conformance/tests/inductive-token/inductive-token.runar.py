from runar import InductiveSmartContract, PubKey, Sig, Bigint, ByteString, public, assert_, check_sig

class InductiveToken(InductiveSmartContract):
    owner: PubKey
    balance: Bigint
    token_id: ByteString

    def __init__(self, owner: PubKey, balance: Bigint, token_id: ByteString):
        super().__init__(owner, balance, token_id)
        self.owner = owner
        self.balance = balance
        self.token_id = token_id

    @public
    def transfer(self, sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint):
        assert_(check_sig(sig, self.owner))
        assert_(amount > 0)
        assert_(amount <= self.balance)

        self.add_output(output_satoshis, to, amount)
        self.add_output(output_satoshis, self.owner, self.balance - amount)

    @public
    def send(self, sig: Sig, to: PubKey, output_satoshis: Bigint):
        assert_(check_sig(sig, self.owner))

        self.add_output(output_satoshis, to, self.balance)
