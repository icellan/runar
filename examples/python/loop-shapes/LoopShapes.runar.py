from runar import SmartContract, Bigint, public, assert_


class LoopShapes(SmartContract):
    # LoopShapes — Python port. A NON-ZERO loop start (R-102).
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, seed: Bigint):
        acc: Bigint = seed
        for i in range(3, 7):
            acc = acc + i
        assert_(acc == self.target)
