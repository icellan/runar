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

    function spend(Sig sig, bigint amount, SigHashPreimage txPreimage) public {
        // Owner must authorize
        require(checkSig(sig, this.owner));
        require(checkPreimage(txPreimage));

        // Enforce minimum output amount (covenant rule)
        require(amount >= this.minAmount);
    }
}
