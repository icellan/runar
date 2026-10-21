from runar import (
    StatefulSmartContract, PubKey, Sig, Bigint,
    public, assert_, check_sig,
)


class Ledger(StatefulSmartContract):
    """Ledger -- F-352 second witness for the mutable-state shape
    {PubKey, bigint, bigint}."""

    holder: PubKey
    balance: Bigint
    nonce: Bigint

    def __init__(self, holder: PubKey, balance: Bigint, nonce: Bigint):
        super().__init__(holder, balance, nonce)
        self.holder = holder
        self.balance = balance
        self.nonce = nonce

    @public
    def spend(self, sig: Sig, amount: Bigint):
        assert_(check_sig(sig, self.holder))
        assert_(amount > 0)
        assert_(amount <= self.balance)
        self.balance = self.balance - amount
        self.nonce = self.nonce + 1
