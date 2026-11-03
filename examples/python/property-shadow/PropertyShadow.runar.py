# PropertyShadow — N-016 conformance fixture. A local that shares a
# property's name never captures ``self.<property>``.
from runar import StatefulSmartContract, Bigint, Readonly, public, assert_

class PropertyShadow(StatefulSmartContract):
    target: Readonly[Bigint]
    count: Bigint

    def __init__(self, target: Bigint, count: Bigint):
        super().__init__(target, count)
        self.target = target
        self.count = count

    @public
    def bump(self, n: Bigint):
        target = n + 1
        assert_(target == self.target)
        count = n
        self.count = self.count + count
        assert_(self.count > count)
