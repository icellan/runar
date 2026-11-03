"""MultiSigVerifyFused -- see MultiSigVerifyFused.runar.ts."""

from runar import SmartContract, PubKey, Sig, Bigint, public, assert_, check_multi_sig


class MultiSigVerifyFused(SmartContract):
    pk1: PubKey
    pk2: PubKey
    pk3: PubKey

    def __init__(self, pk1: PubKey, pk2: PubKey, pk3: PubKey):
        super().__init__(pk1, pk2, pk3)
        self.pk1 = pk1
        self.pk2 = pk2
        self.pk3 = pk3

    @public
    def unlock(self, sig1: Sig, sig2: Sig, amount: Bigint):
        assert_(check_multi_sig([sig1, sig2], [self.pk1, self.pk2, self.pk3]))
        assert_(amount > 0)
