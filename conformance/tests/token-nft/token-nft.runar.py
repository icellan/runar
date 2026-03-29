from runar import StatefulSmartContract, PubKey, Sig, ByteString, Bigint, Readonly, public, assert_, check_sig

class SimpleNFT(StatefulSmartContract):
    owner: PubKey
    token_id: Readonly[ByteString]
    metadata: Readonly[ByteString]

    def __init__(self, owner: PubKey, token_id: ByteString, metadata: ByteString):
        super().__init__(owner, token_id, metadata)
        self.owner = owner
        self.token_id = token_id
        self.metadata = metadata

    @public
    def transfer(self, sig: Sig, new_owner: PubKey, output_satoshis: Bigint):
        assert_(check_sig(sig, self.owner))
        assert_(output_satoshis >= 1)
        self.add_output(output_satoshis, new_owner)

    @public
    def burn(self, sig: Sig):
        assert_(check_sig(sig, self.owner))
