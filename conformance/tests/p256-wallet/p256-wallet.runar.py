from runar import SmartContract, ByteString, Addr, Sig, PubKey, public, assert_, hash160, check_sig, verify_ecdsa_p256

class P256Wallet(SmartContract):
    ecdsa_pub_key_hash: Addr
    p256_pub_key_hash: ByteString

    def __init__(self, ecdsa_pub_key_hash: Addr, p256_pub_key_hash: ByteString):
        super().__init__(ecdsa_pub_key_hash, p256_pub_key_hash)
        self.ecdsa_pub_key_hash = ecdsa_pub_key_hash
        self.p256_pub_key_hash = p256_pub_key_hash

    @public
    def spend(self, p256_sig: ByteString, p256_pub_key: ByteString, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.ecdsa_pub_key_hash)
        assert_(check_sig(sig, pub_key))
        assert_(hash160(p256_pub_key) == self.p256_pub_key_hash)
        assert_(verify_ecdsa_p256(sig, p256_sig, p256_pub_key))
