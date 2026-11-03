pragma runar ^0.1.0;

// PropertyShadow — N-016 conformance fixture. A local that shares a state
// variable's name shadows it; `this.x` still reads the state variable.
contract PropertyShadow is StatefulSmartContract {
    int immutable target;
    int count;

    constructor(int _target, int _count) {
        target = _target;
        count = _count;
    }

    function bump(int n) public {
        int target = n + 1;
        require(target == this.target);
        int count = n;
        this.count = this.count + count;
        require(this.count > count);
    }
}
