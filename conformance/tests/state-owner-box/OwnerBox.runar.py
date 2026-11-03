from runar import (
    StatefulSmartContract, PubKey, Sig,
    public, assert_, check_sig,
)


class OwnerBox(StatefulSmartContract):
    """OwnerBox -- F-352 second witness for the mutable-state shape
    {PubKey}."""

    owner: PubKey

    def __init__(self, owner: PubKey):
        super().__init__(owner)
        self.owner = owner

    @public
    def rotate(self, sig: Sig, new_owner: PubKey):
        assert_(check_sig(sig, self.owner))
        self.owner = new_owner
