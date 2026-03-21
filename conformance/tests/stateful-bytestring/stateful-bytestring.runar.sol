pragma runar ^0.1.0;

contract MessageBoard is StatefulSmartContract {
    bytes message;
    address immutable owner;

    constructor(bytes _message, address _owner) {
        message = _message;
        owner = _owner;
    }

    function post(bytes newMessage) public {
        message = newMessage;
        require(true);
    }

    function burn(bytes sig) public {
        require(checkSig(sig, owner));
    }
}
