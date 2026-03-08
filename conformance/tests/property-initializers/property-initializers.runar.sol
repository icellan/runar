pragma runar ^0.1.0;

contract PropertyInitializers is StatefulSmartContract {
    int count = 0;
    int immutable maxCount;
    bool immutable active = true;

    constructor(int _maxCount) {
        maxCount = _maxCount;
    }

    function increment(int amount) public {
        require(active);
        count = count + amount;
        require(count <= maxCount);
    }

    function reset() public {
        count = 0;
    }
}
