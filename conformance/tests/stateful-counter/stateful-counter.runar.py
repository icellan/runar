from runar import StatefulSmartContract, Bigint, public, assert_

class Counter(StatefulSmartContract):
    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def increment(self):
        self.count += 1

    @public
    def decrement(self):
        assert_(self.count > 0)
        self.count -= 1
