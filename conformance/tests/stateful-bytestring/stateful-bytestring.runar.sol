pragma runar ^0.1.0;

contract MessageBoard is StatefulSmartContract {
    bytes message;
    PubKey immutable owner;

    constructor(bytes _message, PubKey _owner) {
        message = _message;
        owner = _owner;
    }

    function post(bytes newMessage) public {
        message = newMessage;
        require(true);
    }

    function burn(Sig sig) public {
        require(checkSig(sig, owner));
    }
}
