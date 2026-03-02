pragma runar ^0.1.0;

contract BooleanLogic is SmartContract {
    int immutable threshold;

    constructor(int _threshold) {
        threshold = _threshold;
    }

    function verify(int a, int b, bool flag) public {
        bool aAboveThreshold = a > threshold;
        bool bAboveThreshold = b > threshold;
        bool bothAbove = aAboveThreshold && bAboveThreshold;
        bool eitherAbove = aAboveThreshold || bAboveThreshold;
        bool notFlag = !flag;
        require(bothAbove || (eitherAbove && notFlag));
    }
}
