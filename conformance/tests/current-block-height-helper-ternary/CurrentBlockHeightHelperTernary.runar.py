"""CurrentBlockHeightHelperTernary -- see CurrentBlockHeightHelperTernary.runar.ts."""

from runar import (
    StatefulSmartContract, Bigint, Readonly,
    public, assert_, current_block_height,
)


class CurrentBlockHeightHelperTernary(StatefulSmartContract):
    start: Readonly[Bigint]
    count: Bigint

    def __init__(self, start: Bigint, count: Bigint):
        super().__init__(start, count)
        self.start = start
        self.count = count

    def _height(self) -> Bigint:
        return current_block_height()

    @public
    def spend(self):
        assert_(self._height() >= self.start)
        h = current_block_height() if self.count > 5 else self.start
        assert_(h >= self.start)
        self.count = self.count + 1
