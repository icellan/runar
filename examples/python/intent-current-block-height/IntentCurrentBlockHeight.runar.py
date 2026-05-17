from runar import (
    StatefulSmartContract, Bigint, Readonly,
    public, assert_, current_block_height,
)


class IntentCurrentBlockHeight(StatefulSmartContract):
    """Exercises the current_block_height shorthand, which is pure
    source-level sugar for extract_locktime(self.tx_preimage)."""

    deadline: Readonly[Bigint]
    count: Bigint

    def __init__(self, deadline: Bigint, count: Bigint):
        super().__init__(deadline, count)
        self.deadline = deadline
        self.count = count

    @public
    def spend(self):
        h = current_block_height()
        assert_(h <= self.deadline)
        self.count = self.count + 1
