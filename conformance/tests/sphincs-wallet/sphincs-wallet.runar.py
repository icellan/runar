from runar import SmartContract, ByteString, Addr, Sig, PubKey, public, assert_, hash160, check_sig, verify_slh_dsa_sha2_128s

class SPHINCSWallet(SmartContract):
    ecdsa_pub_key_hash: Addr
    slhdsa_pub_key_hash: ByteString

    def __init__(self, ecdsa_pub_key_hash: Addr, slhdsa_pub_key_hash: ByteString):
        super().__init__(ecdsa_pub_key_hash, slhdsa_pub_key_hash)
        self.ecdsa_pub_key_hash = ecdsa_pub_key_hash
        self.slhdsa_pub_key_hash = slhdsa_pub_key_hash

    @public
    def spend(self, slhdsa_sig: ByteString, slhdsa_pub_key: ByteString, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.ecdsa_pub_key_hash)
        assert_(check_sig(sig, pub_key))

        assert_(hash160(slhdsa_pub_key) == self.slhdsa_pub_key_hash)
        assert_(verify_slh_dsa_sha2_128s(sig, slhdsa_sig, slhdsa_pub_key))
