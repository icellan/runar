pragma runar ^0.1.0;

contract Arithmetic is SmartContract {
    int immutable target;

    constructor(int _target) {
        target = _target;
    }

    function verify(int a, int b) public {
        int sum = a + b;
        int diff = a - b;
        int prod = a * b;
        int quot = a / b;
        int result = sum + diff + prod + quot;
        require(result == target);
    }
}
