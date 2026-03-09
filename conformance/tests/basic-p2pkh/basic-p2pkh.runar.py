from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig

class P2PKH(SmartContract):
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
