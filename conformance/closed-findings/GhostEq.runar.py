# GK-BUG-009 — the same probe on the Python surface. The Python parser
# camelCases identifiers, so `not_declared_anywhere` reaches the typechecker
# as `notDeclaredAnywhere` and the diagnostic must name it in that spelling.
# MUST NOT COMPILE.
from runar import SmartContract, Bigint, public, assert_


class GhostEq(SmartContract):
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, seed: Bigint):
        assert_(not_declared_anywhere == 1)
