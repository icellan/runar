"""MultiSig2of3 -- a 2-of-3 multi-signature contract.

Funds are locked to three public keys. To spend, the unlocker must supply
two valid ECDSA signatures from any two of the committed keys. The signing
pair can be (pk1,pk2), (pk1,pk3), or (pk2,pk3); the order of the supplied
signatures must match the order of the corresponding pubkeys in the
committed array.

``check_multi_sig([sig1, sig2], [self.pk1, self.pk2, self.pk3])`` lowers to
two ``array_literal`` ANF nodes -- one for the signature array, one for the
pubkey array. This is the canonical site where ``array_literal`` is emitted
and is useful as a cross-compiler conformance fixture.

Script layout:
    Unlocking: <sig1> <sig2>
    Locking:   OP_0 <sig1> <sig2> 2 <pk1> <pk2> <pk3> 3 OP_CHECKMULTISIG
               OP_VERIFY
"""

from runar import SmartContract, PubKey, Sig, public, assert_, check_multi_sig


class MultiSig2of3(SmartContract):
    pk1: PubKey
    pk2: PubKey
    pk3: PubKey

    def __init__(self, pk1: PubKey, pk2: PubKey, pk3: PubKey):
        super().__init__(pk1, pk2, pk3)
        self.pk1 = pk1
        self.pk2 = pk2
        self.pk3 = pk3

    @public
    def unlock(self, sig1: Sig, sig2: Sig):
        assert_(check_multi_sig([sig1, sig2], [self.pk1, self.pk2, self.pk3]))
