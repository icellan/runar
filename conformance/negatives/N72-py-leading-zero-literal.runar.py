# F-026: `012` is not a Python 3 integer literal ("leading zeros in decimal
# integer literals are not permitted"). Pre-fix the seven tiers read it three
# ways: 12 (ts, rust, zig, java), 10 (go, ruby) and 0 (python). Every tier
# must refuse with:
#   invalid Python integer literal '012'
from runar import SmartContract, Bigint, public, assert_


class T(SmartContract):
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, amount: Bigint):
        assert_(amount > 012)
