from runar import (
    StatefulSmartContract, Bigint, FixedArray,
    public, assert_,
)


class Grid2x2(StatefulSmartContract):
    # Minimal nested FixedArray[FixedArray[Bigint, 2], 2] acceptance contract.
    #
    # The expand-fixed-arrays pass desugars ``grid`` into four scalar
    # siblings ``grid__0__0, grid__0__1, grid__1__0, grid__1__1``. Pass 3b
    # attaches a two-element ``synthetic_array_chain`` to each leaf and the
    # iterative regrouper in the artifact assembler rebuilds a single
    # nested FixedArray state field.
    #
    # Runtime indexing into a nested FixedArray is still a compile error,
    # so each write is split into its own literal-index method.

    grid: FixedArray[FixedArray[Bigint, 2], 2] = [[0, 0], [0, 0]]

    def __init__(self):
        super().__init__()

    @public
    def set00(self, v: Bigint):
        self.grid[0][0] = v
        assert_(True)

    @public
    def set01(self, v: Bigint):
        self.grid[0][1] = v
        assert_(True)

    @public
    def set10(self, v: Bigint):
        self.grid[1][0] = v
        assert_(True)

    @public
    def set11(self, v: Bigint):
        self.grid[1][1] = v
        assert_(True)

    @public
    def read00(self):
        assert_(self.grid[0][0] == self.grid[0][0])
