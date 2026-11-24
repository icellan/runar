from runar import (
    StatefulSmartContract, Bigint, public, assert_,
)


class StatefulTerminalLoop(StatefulSmartContract):
    """A TERMINAL stateful method (no state write, so no injected continuation
    assert) whose bounded loop of asserts is followed by a final assert, which
    is the script result. Without it the method is refused in every tier
    (conformance/negatives N547)."""

    floor: Bigint
    count: Bigint

    def __init__(self, floor: Bigint, count: Bigint):
        super().__init__(floor, count)
        self.floor = floor
        self.count = count

    @public
    def close(self, x: Bigint):
        for i in range(2):
            assert_(x >= self.floor + i)
        assert_(x > self.count)
