from runar import SmartContract, PubKey, Sig, public, assert_, check_sig

class Escrow(SmartContract):
    buyer: PubKey
    seller: PubKey
    arbiter: PubKey

    def __init__(self, buyer: PubKey, seller: PubKey, arbiter: PubKey):
        super().__init__(buyer, seller, arbiter)
        self.buyer = buyer
        self.seller = seller
        self.arbiter = arbiter

    @public
    def release(self, seller_sig: Sig, arbiter_sig: Sig):
        assert_(check_sig(seller_sig, self.seller))
        assert_(check_sig(arbiter_sig, self.arbiter))

    @public
    def refund(self, buyer_sig: Sig, arbiter_sig: Sig):
        assert_(check_sig(buyer_sig, self.buyer))
        assert_(check_sig(arbiter_sig, self.arbiter))
