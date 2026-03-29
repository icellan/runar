pragma runar ^0.1.0;

contract PostQuantumSLHDSA is SmartContract {
    ByteString immutable pubkey;

    constructor(ByteString _pubkey) {
        pubkey = _pubkey;
    }

    function spend(ByteString msg, ByteString sig) public {
        require(verifySLHDSA_SHA2_128s(msg, sig, this.pubkey));
    }
}
