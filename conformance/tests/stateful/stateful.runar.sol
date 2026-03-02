pragma runar ^0.1.0;

contract Stateful is SmartContract {
    int count;
    int immutable maxCount;

    constructor(int _count, int _maxCount) {
        count = _count;
        maxCount = _maxCount;
    }

    function increment(int amount, SigHashPreimage txPreimage) public {
        require(checkPreimage(txPreimage));
        count = count + amount;
        require(count <= maxCount);
        require(hash256(getStateScript()) == extractOutputHash(txPreimage));
    }

    function reset(SigHashPreimage txPreimage) public {
        require(checkPreimage(txPreimage));
        count = 0;
        require(hash256(getStateScript()) == extractOutputHash(txPreimage));
    }
}
