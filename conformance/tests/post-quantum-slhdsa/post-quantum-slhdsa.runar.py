from runar import SmartContract, ByteString, public, assert_, verify_slh_dsa_sha2_128s

class PostQuantumSLHDSA(SmartContract):
    pubkey: ByteString

    def __init__(self, pubkey: ByteString):
        super().__init__(pubkey)
        self.pubkey = pubkey

    @public
    def spend(self, msg: ByteString, sig: ByteString):
        assert_(verify_slh_dsa_sha2_128s(msg, sig, self.pubkey))
