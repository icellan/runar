from runar import StatefulSmartContract, Bigint, Bool, Readonly, public, assert_

class PropertyInitializers(StatefulSmartContract):
    count: Bigint = 0
    max_count: Readonly[Bigint]
    active: Readonly[Bool] = True

    def __init__(self, max_count: Bigint):
        super().__init__(max_count)
        self.max_count = max_count

    @public
    def increment(self, amount: Bigint):
        assert_(self.active)
        self.count = self.count + amount
        assert_(self.count <= self.max_count)

    @public
    def reset(self):
        self.count = 0
