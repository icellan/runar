from runar import StatefulSmartContract, Bigint, Readonly, public, assert_


class BoundedCounter(StatefulSmartContract):
    """BoundedCounter -- demonstrates property initializers in Python format.

    Properties with `= value` defaults are excluded from the auto-generated
    constructor. Only `max_count` needs to be provided at deploy time.
    """

    count: Bigint = 0
    max_count: Readonly[Bigint]
    active: Readonly[bool] = True

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
