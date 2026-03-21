from runar import StatefulSmartContract, ByteString, PubKey, Sig, Readonly, public, assert_, check_sig

class MessageBoard(StatefulSmartContract):
    message: ByteString
    owner: Readonly[PubKey]

    def __init__(self, message: ByteString, owner: PubKey):
        super().__init__(message, owner)
        self.message = message
        self.owner = owner

    @public
    def post(self, new_message: ByteString):
        self.message = new_message
        assert_(True)

    @public
    def burn(self, sig: Sig):
        assert_(check_sig(sig, self.owner))
