pragma runar ^0.1.0;

contract PostQuantumWOTS is SmartContract {
    ByteString immutable pubkey;

    constructor(ByteString _pubkey) {
        pubkey = _pubkey;
    }

    function spend(ByteString msg, ByteString sig) public {
        require(verifyWOTS(msg, sig, this.pubkey));
    }
}
