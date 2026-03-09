from runar import SmartContract, PubKey, Sig, Bigint, public, assert_, check_sig

class MultiMethod(SmartContract):
    owner: PubKey
    backup: PubKey

    def __init__(self, owner: PubKey, backup: PubKey):
        super().__init__(owner, backup)
        self.owner = owner
        self.backup = backup

    def _compute_threshold(self, a: Bigint, b: Bigint) -> Bigint:
        return a * b + 1

    @public
    def spend_with_owner(self, sig: Sig, amount: Bigint):
        threshold: Bigint = self._compute_threshold(amount, 2)
        assert_(threshold > 10)
        assert_(check_sig(sig, self.owner))

    @public
    def spend_with_backup(self, sig: Sig):
        assert_(check_sig(sig, self.backup))
