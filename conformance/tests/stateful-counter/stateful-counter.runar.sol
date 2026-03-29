pragma runar ^0.1.0;

contract Counter is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function increment() public {
        this.count++;
    }

    function decrement() public {
        require(this.count > 0);
        this.count--;
    }
}
