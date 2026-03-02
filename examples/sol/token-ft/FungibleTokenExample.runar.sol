 pragma runar ^0.1.0;

contract FungibleToken is StatefulSmartContract {
    PubKey owner;
    bigint balance;
    ByteString immutable tokenId;

    constructor(PubKey _owner, bigint _balance, ByteString _tokenId) {
        owner = _owner;
        balance = _balance;
        tokenId = _tokenId;
    }

    // Split: 1 input -> 2 outputs (recipient + change)
    function transfer(Sig sig, PubKey to, bigint amount, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(amount > 0);
        require(amount <= this.balance);

        // addOutput(satoshis, owner, balance) -- args match mutable props in order
        this.addOutput(outputSatoshis, to, amount);
        this.addOutput(outputSatoshis, this.owner, this.balance - amount);
    }

    // Simple send: 1 input -> 1 output, full balance
    function send(Sig sig, PubKey to, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));

        this.addOutput(outputSatoshis, to, this.balance);
    }

    // Merge: N inputs -> 1 output (each input calls this independently)
    function merge(Sig sig, bigint totalBalance, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(totalBalance >= this.balance);

        this.addOutput(outputSatoshis, this.owner, totalBalance);
    }
}
