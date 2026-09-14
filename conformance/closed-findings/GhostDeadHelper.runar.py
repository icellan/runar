# GK-BUG-009 — the uncalled-helper shape on the Python surface. Stack lowering
# never walks `never_called`, so the only pass that can catch the unresolvable
# name is the typechecker. MUST NOT COMPILE.
from runar import SmartContract, Bigint, public, assert_


class GhostDeadHelper(SmartContract):
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    def never_called(self) -> Bigint:
        assert_(not_declared_anywhere == 1)
        return 1

    @public
    def verify(self, seed: Bigint):
        assert_(seed == self.target)
