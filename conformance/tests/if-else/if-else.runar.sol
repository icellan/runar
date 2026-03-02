pragma runar ^0.1.0;

contract IfElse is SmartContract {
    int immutable limit;

    constructor(int _limit) {
        limit = _limit;
    }

    function check(int value, bool mode) public {
        int result = 0;
        if (mode) {
            result = value + limit;
        } else {
            result = value - limit;
        }
        require(result > 0);
    }
}
