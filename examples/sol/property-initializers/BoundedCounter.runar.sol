pragma runar ^0.1.0;

/// @title BoundedCounter
/// @notice Demonstrates property initializers in Solidity-like format.
///
/// Properties with `= value` defaults are excluded from the auto-generated
/// constructor. Only `maxCount` needs to be provided at deploy time.
contract BoundedCounter is StatefulSmartContract {
    int256 count = 0;
    int256 immutable maxCount;
    bool immutable active = true;

    function increment(int256 amount) public {
        require(this.active);
        this.count = this.count + amount;
        require(this.count <= this.maxCount);
    }

    function reset() public {
        this.count = 0;
    }
}
