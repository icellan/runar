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
        require(outputSatoshis >= 1);
        this.addOutput(outputSatoshis, newOwner);
    }

    function burn(Sig sig) public {
        require(checkSig(sig, this.owner));
    }
}
