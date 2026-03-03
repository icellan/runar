pragma runar ^0.1.0;

contract Inductive is InductiveSmartContract {
    int count;
    int immutable maxCount;

    constructor(int _count, int _maxCount) {
        count = _count;
        maxCount = _maxCount;
    }

    function increment(int amount) public {
        count = count + amount;
        require(count <= maxCount);
    }

    function reset() public {
        count = 0;
    }
}
