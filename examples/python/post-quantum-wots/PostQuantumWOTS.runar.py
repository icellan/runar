from runar import SmartContract, ByteString, public, assert_, verify_wots

class PostQuantumWOTS(SmartContract):
    pubkey: ByteString

    def __init__(self, pubkey: ByteString):
        super().__init__(pubkey)
        self.pubkey = pubkey

    @public
    def spend(self, msg: ByteString, sig: ByteString):
        assert_(verify_wots(msg, sig, self.pubkey))
