from runar import StatefulSmartContract, PubKey, Sig, Readonly, public, assert_, check_sig

class AllReadonlyCleanstack(StatefulSmartContract):
    """AllReadonlyCleanstack — regression fixture for issue #44.

    A StatefulSmartContract with ZERO mutable fields (only a readonly `owner`)
    plus a readonly-field-binding in a terminal method. The `owner_copy = owner`
    binding force-embeds the readonly field onto the stack; it is not consumed by
    the terminal check_sig assertion, leaving an excess stack item below the
    top-of-stack boolean. Before the fix, the leftover survived and the spend was
    rejected on mainnet with "Script did not clean its stack". The fix runs the
    stack cleanup for every public method, emitting the trailing OP_NIP.
    """
    owner: Readonly[PubKey]

    def __init__(self, owner: PubKey):
        super().__init__(owner)
        self.owner = owner

    @public
    def claim(self, sig: Sig):
        owner_copy = self.owner
        assert_(check_sig(sig, self.owner))
