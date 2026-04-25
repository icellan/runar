pragma runar ^0.1.0;

contract HashRegistry is StatefulSmartContract {
    Ripemd160 currentHash;

    constructor(Ripemd160 _currentHash) {
        currentHash = _currentHash;
    }

    function update(Ripemd160 newHash) public {
        currentHash = newHash;
        require(true);
    }
}
