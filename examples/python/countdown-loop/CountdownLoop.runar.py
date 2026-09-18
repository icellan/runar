from runar import SmartContract, Bigint, public, assert_


class CountdownLoop(SmartContract):
    # CountdownLoop — Python port. `step = -1` (R-102).
    #
    # `range`'s third argument is the step, and `range(5, 1, -1)` yields
    # 5, 4, 3, 2 — half-open at both ends, exactly as `range(3, 7)` is. Before
    # this fixture the surface accepted two arguments only, so it had no
    # descending spelling at all (N-130). See CountdownLoop.runar.ts.
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, seed: Bigint):
        acc: Bigint = seed
        for i in range(5, 1, -1):
            acc = acc + i
        assert_(acc == self.target)
