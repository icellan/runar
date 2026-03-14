pragma runar ^0.1.0;

contract InductiveToken is InductiveSmartContract {
    PubKey owner;
    int balance;
    bytes immutable tokenId;

    constructor(PubKey _owner, int _balance, bytes _tokenId) {
        owner = _owner;
        balance = _balance;
        tokenId = _tokenId;
    }

    function transfer(Sig sig, PubKey to, int amount, int outputSatoshis) public {
        require(checkSig(sig, owner));
        require(amount > 0);
        require(amount <= balance);

        addOutput(outputSatoshis, to, amount);
        addOutput(outputSatoshis, owner, balance - amount);
    }

    function send(Sig sig, PubKey to, int outputSatoshis) public {
        require(checkSig(sig, owner));

        addOutput(outputSatoshis, to, balance);
    }
}
