pragma runar ^0.1.0;

contract IfWithoutElse is SmartContract {
    int immutable threshold;

    constructor(int _threshold) {
        threshold = _threshold;
    }

    function check(int a, int b) public {
        int count = 0;
        if (a > threshold) {
            count = count + 1;
        }
        if (b > threshold) {
            count = count + 1;
        }
        require(count > 0);
    }
}
