from runar import (
    StatefulSmartContract, Bigint, FixedArray,
    public, assert_,
)


class ArraySet(StatefulSmartContract):
    # Python port of ArraySet.runar.ts.

    slots: FixedArray[Bigint, 4] = [0, 0, 0, 0]

    def __init__(self):
        super().__init__()

    @public
    def put(self, i: Bigint, v: Bigint):
        self.slots[i] = v
        assert_(True)
