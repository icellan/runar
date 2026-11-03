# N-050 (StaticSiphon): a static / class-level method is not a contract method.
# Pre-fix, `requirePositive` became a PUBLIC spending entry point in several
# tiers — a path anyone satisfies with `<1>` and no signature (@bsv/sdk
# Spend.validate accepted it against the TS artifact). Every tier must refuse:
#   static methods are not allowed in Rúnar contracts; method 'require_positive' is declared static
# Shape: `@public @classmethod` on the Python surface.
from runar import SmartContract, Sig, PubKey, public, assert_, check_sig


class Vault(SmartContract):
    owner: PubKey

    def __init__(self, owner: PubKey):
        super().__init__(owner)
        self.owner = owner

    @public
    @classmethod
    def require_positive(cls, amount: int):
        assert_(amount > 0)

    @public
    def withdraw(self, sig: Sig):
        assert_(check_sig(sig, self.owner))
