pragma runar ^0.1.0;

// ParamShadowBranchArm — N-007 conformance fixture. The parameter `count`
// shares the state variable's name; inside the `if` arm it is still the
// parameter, and `this.count` is the state variable.
contract ParamShadowBranchArm is StatefulSmartContract {
    int count;

    constructor(int _count) {
        count = _count;
    }

    function set(int count, bool flag) public {
        if (flag) {
            require(count == 5);
        }
        this.count = count;
    }
}
