from runar import InductiveSmartContract, Bigint, public, assert_

class Inductive(InductiveSmartContract):
    count: Bigint
    max_count: Bigint

    def __init__(self, count: Bigint, max_count: Bigint):
        super().__init__(count, max_count)
        self.count = count
        self.max_count = max_count

    @public
    def increment(self, amount: Bigint):
        self.count = self.count + amount
        assert_(self.count <= self.max_count)

    @public
    def reset(self):
        self.count = 0
