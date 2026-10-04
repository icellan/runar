from runar import (
    StatefulSmartContract, PubKey, Sig, ByteString, Bigint,
    public, assert_, check_sig,
)


class AnnotatedVault(StatefulSmartContract):
    """AnnotatedVault -- N-044 conformance fixture.

    A mutable variable-length ByteString state field (memo) BEFORE a mutable
    PubKey (owner). Anyone may replace the memo; only the owner may withdraw.
    """

    memo: ByteString
    owner: PubKey
    balance: Bigint

    def __init__(self, memo: ByteString, owner: PubKey, balance: Bigint):
        super().__init__(memo, owner, balance)
        self.memo = memo
        self.owner = owner
        self.balance = balance

    @public
    def annotate(self, next_memo: ByteString):
        """Replace the memo. Anyone can call."""
        self.memo = next_memo

    @public
    def withdraw(self, sig: Sig):
        """Only the owner may spend."""
        assert_(check_sig(sig, self.owner))
