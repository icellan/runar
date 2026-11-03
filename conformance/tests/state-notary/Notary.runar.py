from runar import (
    StatefulSmartContract, PubKey, Sig, ByteString, Bigint,
    public, assert_, check_sig,
)


class Notary(StatefulSmartContract):
    """Notary -- F-352 second witness for the mutable-state shape
    {ByteString, PubKey, bigint}, with the PubKey declared first."""

    signer: PubKey
    note: ByteString
    seq: Bigint

    def __init__(self, signer: PubKey, note: ByteString, seq: Bigint):
        super().__init__(signer, note, seq)
        self.signer = signer
        self.note = note
        self.seq = seq

    @public
    def notarize(self, sig: Sig, next_note: ByteString):
        assert_(check_sig(sig, self.signer))
        self.note = next_note
        self.seq = self.seq + 1
