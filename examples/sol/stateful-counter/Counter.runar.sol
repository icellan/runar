pragma runar ^0.1.0;

/// @title Counter
/// @notice The simplest possible stateful smart contract.
/// @dev Demonstrates Rúnar's state management: a counter that persists its
/// value across spending transactions on the Bitcoin SV blockchain.
///
/// Because this contract inherits StatefulSmartContract, the compiler
/// automatically injects:
///   - `checkPreimage` at each public function entry — verifies the spending
///     transaction matches the sighash preimage.
///   - State continuation at each public function exit — serializes updated
///     state into the new output script.
///
/// Script layout (on-chain):
///   Locking: <contract logic> OP_RETURN <count>
///
/// The state (`count`) is serialized as push data after OP_RETURN. When spent,
/// the compiler-injected preimage check ensures the new output carries the
/// correct updated state.
///
/// No authorization checks. This contract is intentionally minimal for
/// educational purposes — anyone can call increment or decrement. A real
/// stateful contract would include signature verification or other access
/// control.
contract Counter is StatefulSmartContract {
    bigint count; // mutable (stateful, persists across transactions)

    constructor(bigint _count) {
        count = _count;
    }

    /// @notice Increments count by 1. Anyone can call this function.
    function increment() public {
        this.count++;
    }

    /// @notice Decrements count by 1.
    /// @dev Asserts count > 0 to prevent underflow. Anyone can call this function.
    function decrement() public {
        require(this.count > 0);
        this.count--;
    }
}
