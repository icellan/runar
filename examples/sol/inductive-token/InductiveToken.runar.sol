pragma runar ^0.1.0;

contract InductiveToken is InductiveSmartContract {
    PubKey owner;
    bigint balance;
    ByteString immutable tokenId;

    constructor(PubKey _owner, bigint _balance, ByteString _tokenId) {
        owner = _owner;
        balance = _balance;
        tokenId = _tokenId;
    }

    function transfer(Sig sig, PubKey to, bigint amount, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(amount > 0);
        require(amount <= this.balance);

        this.addOutput(outputSatoshis, to, amount);
        this.addOutput(outputSatoshis, this.owner, this.balance - amount);
    }

    function send(Sig sig, PubKey to, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));

        this.addOutput(outputSatoshis, to, this.balance);
    }
}
