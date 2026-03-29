pragma runar ^0.1.0;

contract CovenantVault is SmartContract {
    PubKey immutable owner;
    Addr immutable recipient;
    bigint immutable minAmount;

    constructor(PubKey _owner, Addr _recipient, bigint _minAmount) {
        owner = _owner;
        recipient = _recipient;
        minAmount = _minAmount;
    }

    function spend(Sig sig, SigHashPreimage txPreimage) public {
        require(checkSig(sig, this.owner));
        require(checkPreimage(txPreimage));
        ByteString p2pkhScript = cat(cat(0x1976a914, this.recipient), 0x88ac);
        ByteString expectedOutput = cat(num2bin(this.minAmount, 8), p2pkhScript);
        require(hash256(expectedOutput) == extractOutputHash(txPreimage));
    }
}
