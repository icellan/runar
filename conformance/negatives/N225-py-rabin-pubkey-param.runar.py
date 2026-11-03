# F-286: verifyRabinSig's modulus (4th argument) is a spending-method parameter,
# so the spender picks n and forges any message (n = 1, sig = 0 passes real
# Spend). Every tier must refuse:
#   verifyRabinSig public key (4th argument) must be a contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature
# Shape: Python surface, @public method parameter.
from runar import SmartContract, ByteString, RabinSig, RabinPubKey, public, assert_, verify_rabin_sig


class RabinParam(SmartContract):
    pk: RabinPubKey

    def __init__(self, pk: RabinPubKey):
        super().__init__(pk)
        self.pk = pk

    @public
    def settle(self, msg: ByteString, sig: RabinSig, padding: ByteString, n: RabinPubKey):
        assert_(verify_rabin_sig(msg, sig, padding, n))
