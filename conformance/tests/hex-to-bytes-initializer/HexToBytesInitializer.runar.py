from runar import SmartContract, Addr, ByteString, Sig, PubKey, public, assert_, hash160, check_sig, cat


class HexToBytesInitializer(SmartContract):
    p2pkh_prefix: ByteString = bytes.fromhex("1976a914")
    p2pkh_suffix: ByteString = bytes.fromhex("88ac")
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey, script: ByteString):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(cat(cat(self.p2pkh_prefix, self.pub_key_hash), self.p2pkh_suffix) == script)
        assert_(check_sig(sig, pub_key))
