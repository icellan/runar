pragma runar ^0.1.0;

contract BoundedLoop is SmartContract {
    int immutable expectedSum;

    constructor(int _expectedSum) {
        expectedSum = _expectedSum;
    }

    function verify(int start) public {
        int sum = 0;
        for (int i = 0; i < 5; i++) {
            sum = sum + start + i;
        }
        require(sum == expectedSum);
    }
}
