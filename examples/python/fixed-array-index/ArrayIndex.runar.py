from runar import (
    SmartContract, Bigint, FixedArray, Readonly,
    public, assert_,
)


class ArrayIndex(SmartContract):
    # Python port of examples/ts/fixed-array-index/ArrayIndex.runar.ts.
    #
    # Exercises FixedArray[Bigint, 4] together with a RUNTIME index read
    # self.table[i].

    table: Readonly[FixedArray[Bigint, 4]] = [10, 20, 30, 40]

    def __init__(self):
        super().__init__()

    @public
    def lookup(self, i: Bigint, expected: Bigint):
        assert_(self.table[i] == expected)
