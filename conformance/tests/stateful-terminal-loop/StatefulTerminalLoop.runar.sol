pragma runar ^0.1.0;

/// @title StatefulTerminalLoop
/// @notice A TERMINAL stateful method (no state write, so no injected
/// continuation assert) whose bounded loop of requires is followed by a final
/// require, which is the script result. Without it the method is refused in
/// every tier (conformance/negatives N547).
contract StatefulTerminalLoop is StatefulSmartContract {
    bigint floor;
    bigint count;

    constructor(bigint _floor, bigint _count) {
        floor = _floor;
        count = _count;
    }

    function close(bigint x) public {
        for (bigint i = 0; i < 2; i++) {
            require(x >= this.floor + i);
        }
        require(x > this.count);
    }
}
