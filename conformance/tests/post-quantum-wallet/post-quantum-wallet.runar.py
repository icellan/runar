from runar import SmartContract, ByteString, Addr, Sig, PubKey, public, assert_, hash160, check_sig, verify_wots

class PostQuantumWallet(SmartContract):
    ecdsa_pub_key_hash: Addr
    wots_pub_key_hash: ByteString

    def __init__(self, ecdsa_pub_key_hash: Addr, wots_pub_key_hash: ByteString):
        super().__init__(ecdsa_pub_key_hash, wots_pub_key_hash)
        self.ecdsa_pub_key_hash = ecdsa_pub_key_hash
        self.wots_pub_key_hash = wots_pub_key_hash

    @public
    def spend(self, wots_sig: ByteString, wots_pub_key: ByteString, sig: Sig, pub_key: PubKey):
        # Step 1: Verify ECDSA
        assert_(hash160(pub_key) == self.ecdsa_pub_key_hash)
        assert_(check_sig(sig, pub_key))

        # Step 2: Verify WOTS+
        assert_(hash160(wots_pub_key) == self.wots_pub_key_hash)
        assert_(verify_wots(sig, wots_sig, wots_pub_key))
