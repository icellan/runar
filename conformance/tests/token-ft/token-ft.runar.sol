pragma runar ^0.1.0;

contract FungibleToken is StatefulSmartContract {
    PubKey owner;
    bigint balance;
    bigint mergeBalance;
    ByteString immutable tokenId;

    constructor(PubKey _owner, bigint _balance, bigint _mergeBalance, ByteString _tokenId) {
        owner = _owner;
        balance = _balance;
        mergeBalance = _mergeBalance;
        tokenId = _tokenId;
    }

    function transfer(Sig sig, PubKey to, bigint amount, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);
        bigint totalBalance = this.balance + this.mergeBalance;
        require(amount > 0);
        require(amount <= totalBalance);
        this.addOutput(outputSatoshis, to, amount, 0);
        if (amount < totalBalance) {
            this.addOutput(outputSatoshis, this.owner, totalBalance - amount, 0);
        }
    }

    function send(Sig sig, PubKey to, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);
        this.addOutput(outputSatoshis, to, this.balance + this.mergeBalance, 0);
    }

    function merge(Sig sig, bigint otherBalance, ByteString allPrevouts, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);
        require(otherBalance >= 0);
        require(hash256(allPrevouts) == extractHashPrevouts(this.txPreimage));
        ByteString myOutpoint = extractOutpoint(this.txPreimage);
        ByteString firstOutpoint = substr(allPrevouts, 0, 36);
        bigint myBalance = this.balance + this.mergeBalance;
        if (myOutpoint == firstOutpoint) {
            this.addOutput(outputSatoshis, this.owner, myBalance, otherBalance);
        } else {
            this.addOutput(outputSatoshis, this.owner, otherBalance, myBalance);
        }
    }
}
