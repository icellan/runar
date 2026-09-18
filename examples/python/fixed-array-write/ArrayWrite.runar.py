from runar import (
    StatefulSmartContract, Bigint, FixedArray,
    public, assert_,
)


class ArrayWrite(StatefulSmartContract):
    # Python port of examples/ts/fixed-array-write/ArrayWrite.runar.ts.

    table: FixedArray[Bigint, 4] = [0, 0, 0, 0]

    def __init__(self):
        super().__init__()

    @public
    def bump(self, i: Bigint):
        self.table[i] = self.table[i] + 1
        assert_(True)
