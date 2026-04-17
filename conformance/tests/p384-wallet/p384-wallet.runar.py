from runar import SmartContract, ByteString, Addr, Sig, PubKey, public, assert_, hash160, check_sig, verify_ecdsa_p384

class P384Wallet(SmartContract):
    ecdsa_pub_key_hash: Addr
    p384_pub_key_hash: ByteString

    def __init__(self, ecdsa_pub_key_hash: Addr, p384_pub_key_hash: ByteString):
        super().__init__(ecdsa_pub_key_hash, p384_pub_key_hash)
        self.ecdsa_pub_key_hash = ecdsa_pub_key_hash
        self.p384_pub_key_hash = p384_pub_key_hash

    @public
    def spend(self, p384_sig: ByteString, p384_pub_key: ByteString, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.ecdsa_pub_key_hash)
        assert_(check_sig(sig, pub_key))
        assert_(hash160(p384_pub_key) == self.p384_pub_key_hash)
        assert_(verify_ecdsa_p384(sig, p384_sig, p384_pub_key))
