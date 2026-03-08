from runar import StatefulSmartContract, Bigint, public, assert_


class Counter(StatefulSmartContract):
    """Counter -- the simplest possible stateful smart contract.

    Demonstrates Runar's state management: a counter that persists its value
    across spending transactions on the Bitcoin SV blockchain.

    Because this class extends StatefulSmartContract, the compiler automatically
    injects:
      - checkPreimage at each public method entry -- verifies the spending
        transaction matches the sighash preimage.
      - State continuation at each public method exit -- serializes updated
        state into the new output script.

    Script layout (on-chain)::

        Locking: <contract logic> OP_RETURN <count>

    The state (count) is serialized as push data after OP_RETURN. When spent,
    the compiler-injected preimage check ensures the new output carries the
    correct updated state.

    No authorization checks. This contract is intentionally minimal for
    educational purposes -- anyone can call increment or decrement. A real
    stateful contract would include signature verification or other access
    control.
    """

    count: Bigint  # mutable (stateful, persists across transactions)

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def increment(self):
        """Increments count by 1. Anyone can call this method."""
        self.count += 1

    @public
    def decrement(self):
        """Decrements count by 1.

        Asserts count > 0 to prevent underflow. Anyone can call this method.
        """
        assert_(self.count > 0)
        self.count -= 1
