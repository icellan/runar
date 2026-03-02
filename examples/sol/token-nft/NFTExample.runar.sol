pragma runar ^0.1.0;

contract SimpleNFT is StatefulSmartContract {
    PubKey owner;
    ByteString immutable tokenId;
    ByteString immutable metadata;

    constructor(PubKey _owner, ByteString _tokenId, ByteString _metadata) {
        owner = _owner;
        tokenId = _tokenId;
        metadata = _metadata;
    }

    function transfer(Sig sig, PubKey newOwner, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        // addOutput(satoshis, owner) -- single mutable prop
        this.addOutput(outputSatoshis, newOwner);
    }

    function burn(Sig sig) public {
        // Only owner can burn
        require(checkSig(sig, this.owner));
        // No addOutput and no state mutation = token destroyed
    }
}
